package virustotal

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
	"encoding/json"
	"strings"
	"testing"
)

func TestFormatVTInt(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
		ok       bool
	}{
		{
			name:     "float64 input",
			input:    float64(4242),
			expected: "4242",
			ok:       true,
		},
		{
			name:     "int input",
			input:    int(98765),
			expected: "98765",
			ok:       true,
		},
		{
			name:     "int64 input",
			input:    int64(1234567890123),
			expected: "1234567890123",
			ok:       true,
		},
		{
			name:     "json.Number input",
			input:    json.Number("8888"),
			expected: "8888",
			ok:       true,
		},
		{
			name:     "unsupported string",
			input:    "not a number",
			expected: "",
			ok:       false,
		},
		{
			name:     "unsupported nil",
			input:    nil,
			expected: "",
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := formatVTInt(tt.input)
			if ok != tt.ok {
				t.Errorf("formatVTInt() ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.expected {
				t.Errorf("formatVTInt() got = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHelpers_EdgeCases(t *testing.T) {
	tags := extractVTTags(map[string]any{
		"tags": []any{
			444,
			"    ",
			"dup_tag_555",
			"dup_tag_555",
			"valid_tag_666",
		},
	})
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}

	m := &module{}
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	m.extractThreatScore(map[string]any{
		vtKeyAnalysisStats: map[string]any{
			constants.TagMalicious:  float64(0),
			constants.TagSuspicious: float64(5),
		},
	}, constants.TypeDomain, "test777.example.net", nil, exec, gen)
	if len(exec.Results) == 0 {
		t.Error("expected threat score result for suspicious")
	}

	eng1 := extractEngines(map[string]any{})
	if eng1 != "" {
		t.Errorf("expected empty engines string, got %q", eng1)
	}

	eng2 := extractEngines(map[string]any{
		"last_analysis_results": map[string]any{
			"engine_alpha": 888,
			"engine_beta":  map[string]any{},
			"engine_gamma": map[string]any{
				constants.KeyCategory: constants.TagMalicious,
				"engine_name":         "test_engine_999",
			},
		},
	})
	if !strings.Contains(eng2, "test_engine_999") {
		t.Errorf("expected test_engine_999 in output, got %q", eng2)
	}
}
