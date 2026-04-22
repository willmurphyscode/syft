package binary

// envoyYaraRules mirrors the null-delimited version + context-anchor matchers
// that the envoy classifier used to express as large "(?s)...\.{0,1000}..."
// Go regexes. Each rule pins a version prefix (e.g. 1.3x, 1.2x, 1.1x) and
// pairs it with the literal anchor string that, historically, has indicated
// the version-bearing section of an envoy binary. The Go regex passed
// alongside this rule set extracts the actual version from the bytes
// captured by the "$version" string.
//
// Rules are ordered by specificity — the rules whose version regex has a
// longer literal prefix come first so yargo's deterministic rule-index
// iteration gives us predictable first-match-wins semantics.
const envoyYaraRules = `
rule envoy_1_34_5_reloadable_features {
    strings:
        $version = /\x001\.34\.5\x00/
        $anchor = "envoy.reloadable_features"
    condition:
        $version and $anchor
}

rule envoy_1_3x_reloadable_features {
    strings:
        $version = /\x001\.3[0-9]\.[0-9]+(-dev)?\x00/
        $anchor = "envoy_reloadable_features"
    condition:
        $version and $anchor
}

rule envoy_1_2x_quic {
    strings:
        $version = /\x001\.2[0-9]\.[0-9]+(-dev)?\x00/
        $anchor = "envoy_quic_"
    condition:
        $version and $anchor
}

rule envoy_1_2x_validation_error {
    strings:
        $version = /\x001\.2[0-9]\.[0-9]+(-dev)?\x00/
        $anchor = "ValidationError"
    condition:
        $version and $anchor
}

rule envoy_1_1x_validation_error {
    strings:
        $version = /\x001\.1[0-9]\.[0-9]+(-dev)?\x00/
        $anchor = "ValidationError"
    condition:
        $version and $anchor
}

rule envoy_1_1x_source {
    strings:
        $version = /\x001\.1[0-9]\.[0-9]+(-dev)?\x00/
        $anchor = "[source/"
    condition:
        $version and $anchor
}
`
