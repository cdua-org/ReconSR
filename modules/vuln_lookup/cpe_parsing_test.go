package vuln_lookup

import (
	"context"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestExtractLeadingInt_Error(t *testing.T) {
	val := extractLeadingInt("999999999999999999999999999999")
	if val != 0 {
		t.Errorf("expected 0 on overflow, got %d", val)
	}
}

func TestIsCveApplicable_StrictLess(t *testing.T) {
	cve := &CIRCLCVEResponse{
		Containers: Containers{
			CNA: CNA{
				Affected: []Affected{
					{
						Product: "nginx",
						Versions: []Version{
							{
								Version: "< 1.25.0",
								Status:  StatusAffected,
							},
						},
					},
				},
			},
		},
	}

	if !isCveApplicable("nginx", "1.24.0", cve) {
		t.Errorf("expected 1.24.0 to be affected by < 1.25.0")
	}

	if isCveApplicable("nginx", "1.25.0", cve) {
		t.Errorf("expected 1.25.0 to not be affected by < 1.25.0")
	}
}

func TestEvaluateStatus_Changes(t *testing.T) {
	v := &Version{
		Version: "1.0",
		Status:  StatusAffected,
		Changes: []Change{
			{
				At:     "1.5",
				Status: "unaffected",
			},
		},
	}

	if s := evaluateStatus("1.2", v); s != StatusAffected {
		t.Errorf("expected affected, got %s", s)
	}

	if s := evaluateStatus("1.6", v); s != "unaffected" {
		t.Errorf("expected unaffected, got %s", s)
	}

	vEmptyStatus := &Version{
		Version: "2.0",
		Status:  "",
	}
	if s := evaluateStatus("2.0", vEmptyStatus); s != StatusAffected {
		t.Errorf("expected affected when status is empty, got %s", s)
	}
}

func TestParseLegacyVersionString_Matches(t *testing.T) {
	if !parseLegacyVersionString("1.1", "Vulnerable before 1.2") {
		t.Errorf("expected 1.1 to match before 1.2")
	}
	if parseLegacyVersionString("1.4", "Vulnerable before 1.2") {
		t.Errorf("expected 1.4 to not match before 1.2")
	}

	if !parseLegacyVersionString("1.1", "Vulnerable < 1.2") {
		t.Errorf("expected 1.1 to match < 1.2")
	}
	if parseLegacyVersionString("1.4", "Vulnerable < 1.2") {
		t.Errorf("expected 1.4 to not match < 1.2")
	}
}

func TestParseCPEResponse_EmptyCVEID(t *testing.T) {
	m := &module{}
	exec := modutil.NewExecution(constants.FuncSearchCirclCPE)
	gen := modutil.NewLocalIDGenerator()

	raw := []byte(`{"cvelistv5":[{"cveMetadata":{"cveId":""}}]}`)

	count := m.parseCPEResponse(&exec, raw, "cpe:/a:nginx", gen)

	if count != 1 {
		t.Errorf("expected parsed count to be 1, got %d", count)
	}

	if len(exec.Results) != 1 || exec.Results[0].Type != constants.TypeCPE {
		t.Errorf("expected exactly 1 result of type CPE, got %v", exec.Results)
	}
}

func TestIsVersionInRange_StartBoundViolation(t *testing.T) {
	v := &Version{
		Version: "1.5",
	}
	if isVersionInRange("1.0", v) {
		t.Errorf("expected 1.0 to be out of range (lower than 1.5)")
	}
	if !isVersionInRange("1.5", v) {
		t.Errorf("expected 1.5 to be in range (equal to 1.5)")
	}
}

func TestSearchCirclCPE_CacheHit(t *testing.T) {
	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	target := "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"
	m.cpeCache.Store(target, true)

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, target, gen)
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results on cache hit, got %d", len(exec.Results))
	}
}
