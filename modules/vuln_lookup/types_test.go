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

func TestMetric_UnmarshalJSON_FormatError(t *testing.T) {
	var m Metric
	err := m.UnmarshalJSON([]byte(`{"format": [1, 2, 3]}`))
	if err != nil {
		t.Errorf("expected no error from UnmarshalJSON even if format fails, got %v", err)
	}
	if m.Format != "" {
		t.Errorf("expected Format to be empty string on error, got %q", m.Format)
	}
}

func TestMetric_ProcessRawKey_NoVersion(t *testing.T) {
	var m Metric
	m.processRawKey("cvssV3_1", []byte(`{"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}`))
	if m.BestCVSSVersion != 3.1 {
		t.Errorf("expected BestCVSSVersion to be 3.1, got %v", m.BestCVSSVersion)
	}
}

func TestNVDMetrics_ProcessRawKey_NoPrefix(t *testing.T) {
	var m NVDMetrics
	m.processRawKey("otherData", []byte(`[{"cvssData": {}}]`))
	if m.BestCVSSVersion != 0 {
		t.Errorf("expected BestCVSSVersion to be 0, got %v", m.BestCVSSVersion)
	}
}

func TestNVDMetrics_ProcessRawKey_InvalidCVSSData(t *testing.T) {
	var m NVDMetrics
	m.processRawKey("cvssMetricV31", []byte(`[{"cvssData": [1, 2, 3]}]`))
	if m.BestCVSSVersion != 3.1 {
		t.Errorf("expected BestCVSSVersion to be 3.1, got %v", m.BestCVSSVersion)
	}
}

func TestNVDMetrics_ProcessRawKey_NoVersionV31(t *testing.T) {
	var m NVDMetrics
	m.processRawKey("cvssMetricV31", []byte(`[{"cvssData": {"vectorString": "AV:N"}}]`))
	if m.BestCVSSVersion != 3.1 {
		t.Errorf("expected BestCVSSVersion to be 3.1, got %v", m.BestCVSSVersion)
	}
}

func TestNVDMetrics_ProcessRawKey_NoVersionV2(t *testing.T) {
	var m NVDMetrics
	m.processRawKey("cvssMetricV2", []byte(`[{"cvssData": {"vectorString": "AV:N"}}]`))
	if m.BestCVSSVersion != 2.0 {
		t.Errorf("expected BestCVSSVersion to be 2.0, got %v", m.BestCVSSVersion)
	}
}
