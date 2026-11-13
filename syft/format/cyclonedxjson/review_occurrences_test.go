package cyclonedxjson

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/internal/testutil"
)

// Every 1.5+ XML document syft writes gains evidence occurrences, one per distinct path: /usr/bin/example is found in
// two layers but is one occurrence, since XML leaves the layer to the syft:location properties.
func TestReview_xmlWritesOneOccurrencePerPath(t *testing.T) {
	s, _ := testutil.LocationsInput(t)
	for _, version := range []string{"1.5", "1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			enc, err := cyclonedxxml.NewFormatEncoderWithConfig(cyclonedxxml.EncoderConfig{Version: version})
			require.NoError(t, err)
			var out bytes.Buffer
			require.NoError(t, enc.Encode(&out, s))
			assert.Equal(t, 1, strings.Count(out.String(), "<location>/usr/bin/example</location>"))
		})
	}
}
