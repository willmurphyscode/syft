package cyclonedxjson

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
)

// The component from https://github.com/anchore/syft/issues/3880, as the reporter posted it: a third-party
// CycloneDX 1.6 document whose only location is a (Windows, relative) evidence occurrence.
func TestReview_issue3880ThirdPartyOccurrenceIsDecoded(t *testing.T) {
	f, err := os.Open("testdata/review-syft-3880-third-party-deb.json")
	require.NoError(t, err)
	defer f.Close()

	s, _, _, err := NewFormatDecoder().Decode(f)
	require.NoError(t, err)

	var got *pkg.Package
	for p := range s.Artifacts.Packages.Enumerate() {
		if p.Name == "zeromq3" {
			got = &p
		}
	}
	require.NotNil(t, got)
	locations := got.Locations.ToSlice()
	require.Len(t, locations, 1)
	assert.Equal(t, "/packages\\libzmq5_4.3.2-2ubuntu1.20.04.1~esm2_amd64.deb", locations[0].RealPath)
}

// The PR changes the derived package ID of a component that has occurrences and no bom-ref. A real cdxgen 12.8.4
// document (the PR's own fixture) gives every component a bom-ref, so its packages keep the bom-ref as their ID while
// gaining the location.
func TestReview_cdxgenDocumentKeepsBomRefAsID(t *testing.T) {
	f, err := os.Open("testdata/cdxgen-evidence-occurrences.json")
	require.NoError(t, err)
	defer f.Close()

	s, _, _, err := NewFormatDecoder().Decode(f)
	require.NoError(t, err)

	pkgs := s.Artifacts.Packages.PackagesByName("lodash")
	require.Len(t, pkgs, 1)
	assert.Equal(t, "pkg:npm/lodash@4.17.21", string(pkgs[0].ID()))
	assert.Equal(t, []string{"/src/index.js"}, realPaths(pkgs[0]))
}

func realPaths(p pkg.Package) []string {
	var out []string
	for _, l := range p.Locations.ToSlice() {
		out = append(out, l.RealPath)
	}
	return out
}
