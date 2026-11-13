package cyclonedxjson

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/internal/testutil"
)

// cyclonedxhelpers.ToFormatModel is public: library callers (grype's CycloneDX presenter is one) encode its model with
// cyclonedx.BOMEncoder.EncodeVersion at the BOM's own spec version. The locations of a component should come out the
// same as from syft's own encoder at that version.
func TestReview_toFormatModelWritesLocationsLikeTheEncoder(t *testing.T) {
	s, _ := testutil.LocationsInput(t)

	enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: cyclonedx.SpecVersion1_7.String()})
	require.NoError(t, err)
	var syftOut bytes.Buffer
	require.NoError(t, enc.Encode(&syftOut, s))

	bom := cyclonedxhelpers.ToFormatModel(s)
	require.Equal(t, cyclonedx.SpecVersion1_7, bom.SpecVersion)
	var grypeOut bytes.Buffer
	require.NoError(t, cyclonedx.NewBOMEncoder(&grypeOut, cyclonedx.BOMFileFormatJSON).EncodeVersion(bom, bom.SpecVersion))

	assert.Equal(t, locationsOf(t, syftOut.Bytes()), locationsOf(t, grypeOut.Bytes()))
}

type componentLocations struct {
	Properties  []string
	Occurrences []cyclonedx.EvidenceOccurrence
}

func locationsOf(t *testing.T, doc []byte) componentLocations {
	t.Helper()
	var bom cyclonedx.BOM
	require.NoError(t, json.Unmarshal(doc, &bom))
	var out componentLocations
	for _, c := range *bom.Components {
		if c.Name != testutil.LocationsInputPackageName {
			continue
		}
		if c.Properties != nil {
			for _, p := range *c.Properties {
				if strings.HasPrefix(p.Name, "syft:location:") {
					out.Properties = append(out.Properties, p.Name+"="+p.Value)
				}
			}
		}
		if c.Evidence != nil && c.Evidence.Occurrences != nil {
			out.Occurrences = *c.Evidence.Occurrences
		}
	}
	return out
}

// cyclonedx-go writes an occurrence's additionalContext as an XML attribute, which the 1.7 schema does not allow: it
// declares additionalContext as a child element of occurrence (bom-1.7.xsd in cyclonedx-go v0.12.0). syft's own
// encoder leaves it out of XML for that reason, but a library caller that writes XML from the public ToFormatModel
// gets it, and the document fails schema validation.
func TestReview_toFormatModelXMLHasNoOccurrenceContextAttribute(t *testing.T) {
	s, _ := testutil.LocationsInput(t)
	bom := cyclonedxhelpers.ToFormatModel(s)
	var out bytes.Buffer
	require.NoError(t, cyclonedx.NewBOMEncoder(&out, cyclonedx.BOMFileFormatXML).EncodeVersion(bom, bom.SpecVersion))
	assert.False(t, strings.Contains(out.String(), "additionalContext="),
		"ToFormatModel XML at %s writes additionalContext as an occurrence attribute, which the schema rejects", bom.SpecVersion)
}

// Every syft and grype released before this change reads package locations only from the syft:location properties, so
// a default (JSON, 1.7) document without them decodes with no locations in those readers.
func TestReview_defaultJSONKeepsLocationProperties(t *testing.T) {
	s, _ := testutil.LocationsInput(t)
	enc, err := NewFormatEncoderWithConfig(DefaultEncoderConfig())
	require.NoError(t, err)
	var out bytes.Buffer
	require.NoError(t, enc.Encode(&out, s))

	got := locationsOf(t, out.Bytes())
	assert.Contains(t, got.Properties, "syft:location:0:path=/opt/example")
	assert.NotEmpty(t, got.Occurrences)
}
