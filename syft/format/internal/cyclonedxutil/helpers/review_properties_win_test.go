package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
)

// When a document states a path in syft:location properties, an evidence occurrence for the same path is not decoded
// as a second location, even if its additional context names another layer: the properties win. Hand-built input.
func TestReview_propertiesWinOverOccurrenceForSamePath(t *testing.T) {
	properties := map[string]string{
		"syft:location:0:path":    "/usr/bin/example",
		"syft:location:0:layerID": "sha256:layer-1",
	}
	evidence := &cyclonedx.Evidence{Occurrences: &[]cyclonedx.EvidenceOccurrence{
		{Location: "/usr/bin/example", AdditionalContext: "layerID: sha256:layer-2"},
	}}

	locations := decodeLocations(properties, evidence)
	got := locations.CoordinateSet().ToSlice()
	assert.Equal(t, []file.Coordinates{file.NewCoordinates("/usr/bin/example", "sha256:layer-1")}, got)
}
