package binutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func Test_YaraVersionMatcher_ExtractsFromVersionString(t *testing.T) {
	const rule = `
rule test_version {
    strings:
        $version = /envoy-v[0-9]+\.[0-9]+\.[0-9]+/
        $anchor = "testbinary"
    condition:
        $version and $anchor
}
`

	classifier := Classifier{
		Class:           "test-binary",
		Package:         "testbinary",
		EvidenceMatcher: YaraVersionMatcher("cataloger-name", rule, `envoy-v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
	}

	resolver := file.NewMockResolverForPaths("testdata/yara_match.bin")
	ls, err := resolver.FilesByPath("testdata/yara_match.bin")
	require.NoError(t, err)
	require.Len(t, ls, 1)

	pkgs, err := classifier.EvidenceMatcher(classifier, MatcherContext{Resolver: resolver, Location: ls[0]})
	require.NoError(t, err)

	require.Len(t, pkgs, 1)
	assert.Equal(t, "testbinary", pkgs[0].Name)
	assert.Equal(t, "1.2.3", pkgs[0].Version)
}

func Test_YaraVersionMatcher_NoMatchWhenAnchorAbsent(t *testing.T) {
	const rule = `
rule test_version {
    strings:
        $version = /envoy-v[0-9]+\.[0-9]+\.[0-9]+/
        $anchor = "non-existent-anchor-xyzzy"
    condition:
        $version and $anchor
}
`

	classifier := Classifier{
		Class:           "test-binary",
		Package:         "testbinary",
		EvidenceMatcher: YaraVersionMatcher("cataloger-name", rule, `envoy-v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
	}

	resolver := file.NewMockResolverForPaths("testdata/yara_match.bin")
	ls, err := resolver.FilesByPath("testdata/yara_match.bin")
	require.NoError(t, err)
	require.Len(t, ls, 1)

	pkgs, err := classifier.EvidenceMatcher(classifier, MatcherContext{Resolver: resolver, Location: ls[0]})
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func Test_YaraVersionMatcher_PrefilterFallsBackToFullBuffer(t *testing.T) {
	const rule = `
rule test_anchor_only {
    strings:
        $anchor = "testbinary"
    condition:
        $anchor
}
`

	classifier := Classifier{
		Class:           "test-binary",
		Package:         "testbinary",
		EvidenceMatcher: YaraVersionMatcher("cataloger-name", rule, `envoy-v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
	}

	resolver := file.NewMockResolverForPaths("testdata/yara_match.bin")
	ls, err := resolver.FilesByPath("testdata/yara_match.bin")
	require.NoError(t, err)
	require.Len(t, ls, 1)

	pkgs, err := classifier.EvidenceMatcher(classifier, MatcherContext{Resolver: resolver, Location: ls[0]})
	require.NoError(t, err)

	require.Len(t, pkgs, 1)
	assert.Equal(t, "testbinary", pkgs[0].Name)
	assert.Equal(t, "1.2.3", pkgs[0].Version)
}
