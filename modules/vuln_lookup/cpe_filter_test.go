package vuln_lookup

import (
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"5.5.18", "5.5.16", 1},
		{"5.5.14", "5.5.17", -1},
		{"5.5", "5.5.0", 0},
		{"6.8.2", "6.8.2", 0},
		{"6.8", "6.8.4", -1},
		{"6.8.3", "6.8.1", 1},
		{"1.0.0-alpha", "1.0.0", 0},
		{"1.0.0", "1.0.0-alpha", 0},
		{"v2.0", "2.0", 0},
		{"1.10", "1.2", 1},
	}

	for _, tc := range tests {
		t.Run(tc.v1+"_vs_"+tc.v2, func(t *testing.T) {
			res := compareVersions(tc.v1, tc.v2)
			if res != tc.expected {
				t.Errorf("compareVersions(%q, %q) = %d, expected %d", tc.v1, tc.v2, res, tc.expected)
			}
		})
	}
}

func TestIsCveApplicable_ExactMatch(t *testing.T) {
	cve := &CIRCLCVEResponse{
		Containers: Containers{
			CNA: CNA{
				Affected: []Affected{
					{
						Product: "wordpress",
						Versions: []Version{
							{Version: "5.5.18", Status: StatusAffected},
							{Version: "5.5.19", Status: StatusUnaffected},
						},
					},
				},
			},
		},
	}

	if !isCveApplicable("wordpress", "5.5.18", cve) {
		t.Error("expected 5.5.18 to be affected")
	}

	if isCveApplicable("wordpress", "5.5.19", cve) {
		t.Error("expected 5.5.19 to be unaffected")
	}

	if isCveApplicable("wordpress", "5.5.20", cve) {
		t.Error("expected 5.5.20 to be unaffected")
	}
}

func TestIsCveApplicable_LessThanOrEqual(t *testing.T) {
	cve := &CIRCLCVEResponse{
		Containers: Containers{
			CNA: CNA{
				Affected: []Affected{
					{
						Product: "example_wp",
						Versions: []Version{
							{
								Version:         "5.5",
								LessThanOrEqual: "5.5.16",
								Status:          StatusAffected,
								Changes: []Change{
									{At: "5.5.15", Status: StatusUnaffected},
								},
							},
						},
					},
				},
			},
		},
	}

	if !isCveApplicable("example_wp", "5.5.14", cve) {
		t.Error("expected 5.5.14 to be affected")
	}
	if isCveApplicable("example_wp", "5.5.15", cve) {
		t.Error("expected 5.5.15 to be unaffected due to change")
	}
	if isCveApplicable("example_wp", "5.5.16", cve) {
		t.Error("expected 5.5.16 to be unaffected due to change")
	}
	if isCveApplicable("example_wp", "5.5.18", cve) {
		t.Error("expected 5.5.18 to be unaffected")
	}
}

func TestIsCveApplicable_DifferentProduct(t *testing.T) {
	cve := &CIRCLCVEResponse{
		Containers: Containers{
			CNA: CNA{
				Affected: []Affected{
					{
						Product: "phpmailer",
						Versions: []Version{
							{Version: "5.2.18", Status: StatusAffected},
						},
					},
				},
			},
		},
	}

	if isCveApplicable("another_wp", "5.5.18", cve) {
		t.Error("expected fallback to false for unlisted products")
	}
}

func TestIsCveApplicable_NA_Product(t *testing.T) {
	cve := &CIRCLCVEResponse{
		Containers: Containers{
			CNA: CNA{
				Affected: []Affected{
					{
						Product: ValueNA,
						Versions: []Version{
							{Version: ValueNA, Status: StatusAffected},
						},
					},
				},
			},
		},
	}

	if isCveApplicable("some_wp", "5.5.18", cve) {
		t.Error("expected fallback to false for n/a product and n/a version")
	}
}

func TestIsCveApplicable_UnspecifiedStart(t *testing.T) {
	cve := &CIRCLCVEResponse{
		Containers: Containers{
			CNA: CNA{
				Affected: []Affected{
					{
						Product: "unspec_wp",
						Versions: []Version{
							{
								Version:  "unspecified",
								LessThan: "6.0",
								Status:   StatusAffected,
							},
						},
					},
				},
			},
		},
	}

	if !isCveApplicable("unspec_wp", "5.5.18", cve) {
		t.Error("expected 5.5.18 to be affected (in range [unspecified, 6.0))")
	}

	if isCveApplicable("unspec_wp", "6.0", cve) {
		t.Error("expected 6.0 to be unaffected")
	}
}

func TestIsCveApplicable_LessThanInVersion(t *testing.T) {
	cve := &CIRCLCVEResponse{
		Containers: Containers{
			CNA: CNA{
				Affected: []Affected{
					{
						Product: "wordpress-develop",
						Versions: []Version{
							{
								Version: "< 5.8.3",
								Status:  StatusAffected,
							},
						},
					},
				},
			},
		},
	}

	if !isCveApplicable("wordpress", "5.8.2", cve) {
		t.Error("expected 5.8.2 to be affected")
	}

	if isCveApplicable("wordpress", "5.8.3", cve) {
		t.Error("expected 5.8.3 to be unaffected (it is not < 5.8.3)")
	}

	if isCveApplicable("wordpress", "7.0", cve) {
		t.Error("expected 7.0 to be unaffected")
	}
}

func TestIsCveApplicable_LegacyFormat(t *testing.T) {
	cve := &CIRCLCVEResponse{
		Containers: Containers{
			CNA: CNA{
				Affected: []Affected{
					{
						Product: "Apache HTTP Server",
						Versions: []Version{
							{
								Version: "Apache HTTP Server through 2.2.34 and 2.4.x through 2.4.27",
								Status:  StatusAffected,
							},
						},
					},
				},
			},
		},
	}

	if !isCveApplicable("http_server", "2.4", cve) {
		t.Error("expected generic 2.4 to be affected by legacy format string")
	}

	if !isCveApplicable("http_server", "2.2.10", cve) {
		t.Error("expected 2.2.10 to be affected by legacy format string")
	}

	if isCveApplicable("http_server", "2.5", cve) {
		t.Error("expected 2.5 to be unaffected by legacy format string")
	}
}
