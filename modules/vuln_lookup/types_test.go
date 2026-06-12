package vuln_lookup

import (
	"testing"
)

func TestMetric_UnmarshalJSON_Error(t *testing.T) {
	var m Metric
	err := m.UnmarshalJSON([]byte(`["invalid"]`))
	if err == nil {
		t.Error("expected error unmarshaling Metric from array, got nil")
	}
}

func TestNVDMetrics_UnmarshalJSON_Error(t *testing.T) {
	var m NVDMetrics
	err := m.UnmarshalJSON([]byte(`["invalid"]`))
	if err == nil {
		t.Error("expected error unmarshaling NVDMetrics from array, got nil")
	}
}

func TestProcessRawKey_Invalid(t *testing.T) {
	var m Metric
	m.processRawKey("cvssV3_1", []byte("not_a_map"))
	if m.BestCVSSVersion != 0 {
		t.Errorf("expected BestCVSSVersion to be 0")
	}

	var n NVDMetrics
	n.processRawKey("cvssMetricV31", []byte("not_a_map"))
	if n.BestCVSSVersion != 0 {
		t.Errorf("expected BestCVSSVersion to be 0")
	}
}
