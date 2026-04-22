package binutils

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	yparser "github.com/sansecio/yargo/parser"
	yscanner "github.com/sansecio/yargo/scanner"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
)

// yaraScanTimeout bounds a single yargo ScanMem call. The rules used by the
// binary classifier are short and complete in well under a second on typical
// binaries; a generous timeout is just belt-and-suspenders.
const yaraScanTimeout = 5 * time.Second

// YaraVersionMatcher returns an EvidenceMatcher that scans a file with the
// given yargo YARA rule source and, on a match, extracts the version by
// applying versionPattern (a Go regex with a named "version" capture) to:
//
//   - the bytes matched by the rule's "$version" string, if the rule defines
//     one and it participated in the match; or
//   - the full file buffer, otherwise — allowing the rule to act purely as
//     an AC-accelerated prefilter.
//
// The YARA source and the Go version regex are parsed/compiled lazily on
// first use (under a sync.Once), and any invalid input panics at match time.
// Prefer compile-time-constant rule sources so mistakes surface in tests.
func YaraVersionMatcher(catalogerName, yaraRule, versionPattern string) EvidenceMatcher {
	compiled := &lazyYara{source: yaraRule}
	versionRe := regexp.MustCompile(versionPattern)

	return func(classifier Classifier, context MatcherContext) ([]pkg.Package, error) {
		rules, err := compiled.load()
		if err != nil {
			return nil, err
		}

		contents, err := getReader(context)
		if err != nil {
			return nil, fmt.Errorf("unable to get reader for file: %w", err)
		}
		defer internal.CloseAndLogError(contents, context.Location.RealPath)

		buf, err := io.ReadAll(contents)
		if err != nil {
			return nil, fmt.Errorf("unable to read file contents: %w", err)
		}

		var matches yscanner.MatchRules
		if err := rules.ScanMem(buf, 0, yaraScanTimeout, &matches); err != nil {
			return nil, fmt.Errorf("yara scan failed: %w", err)
		}
		if len(matches) == 0 {
			return nil, nil
		}

		for _, m := range matches {
			meta := extractVersionFromMatch(versionRe, m, buf)
			if meta == nil {
				continue
			}
			p := NewClassifierPackage(classifier, context.Location, meta, catalogerName)
			if p != nil {
				return []pkg.Package{*p}, nil
			}
		}
		return nil, nil
	}
}

// YaraVersionMatcher is a convenience wrapper for callers that already have a
// ContextualEvidenceMatchers bound to a cataloger name.
func (c ContextualEvidenceMatchers) YaraVersionMatcher(yaraRule, versionPattern string) EvidenceMatcher {
	return YaraVersionMatcher(c.CatalogerName, yaraRule, versionPattern)
}

// extractVersionFromMatch tries to extract a named-capture map from a YARA
// match by applying versionRe first to the bytes captured by the rule's
// "$version" string (if any), and falling back to the full buffer.
func extractVersionFromMatch(versionRe *regexp.Regexp, match yscanner.MatchRule, buf []byte) map[string]string {
	for _, s := range match.Strings {
		if s.Name != "$version" {
			continue
		}
		if meta := namedCaptureGroups(versionRe, s.Data); meta != nil {
			return meta
		}
	}
	return namedCaptureGroups(versionRe, buf)
}

func namedCaptureGroups(re *regexp.Regexp, data []byte) map[string]string {
	sub := re.FindSubmatch(data)
	if sub == nil {
		return nil
	}
	out := make(map[string]string, len(sub))
	for i, name := range re.SubexpNames() {
		if name == "" || i >= len(sub) {
			continue
		}
		out[name] = string(sub[i])
	}
	if _, ok := out["version"]; !ok {
		return nil
	}
	return out
}

type lazyYara struct {
	once   sync.Once
	source string
	rules  *yscanner.Rules
	err    error
}

func (l *lazyYara) load() (*yscanner.Rules, error) {
	l.once.Do(func() {
		rs, err := yparser.New().Parse(l.source)
		if err != nil {
			l.err = fmt.Errorf("parsing yara rule: %w", err)
			return
		}
		compiled, err := yscanner.Compile(rs)
		if err != nil {
			l.err = fmt.Errorf("compiling yara rule: %w", err)
			return
		}
		if compiled == nil {
			l.err = errors.New("yara rule set compiled to nil")
			return
		}
		l.rules = compiled
	})
	return l.rules, l.err
}
