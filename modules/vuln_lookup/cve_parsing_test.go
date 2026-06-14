package vuln_lookup

import (
	"context"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestEnrichCirclCVE_CacheHit(t *testing.T) {
	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	target := "CVE-2000-0000"
	m.cveCache.Store(target, true)

	exec := m.enrichCirclCVE(context.Background(), constants.TypeCVE, target, gen)
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results on cache hit, got %d", len(exec.Results))
	}
}

func TestParseCVEResponse_InvalidJSON(t *testing.T) {
	m := &module{}
	exec := modutil.NewExecution(constants.FuncEnrichCirclCVE)
	gen := modutil.NewLocalIDGenerator()

	m.parseCVEResponse(&exec, []byte("{invalid"), "CVE-1234-5678", gen)
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results for invalid json, got %d", len(exec.Results))
	}
}

func TestExtractCVEResults_ReferenceEdgeCases(t *testing.T) {
	m := &module{}
	exec := modutil.NewExecution(constants.FuncEnrichCirclCVE)
	gen := modutil.NewLocalIDGenerator()

	resp := &CIRCLCVEResponse{
		Containers: Containers{
			CNA: CNA{
				References: []Reference{
					{URL: ""},
					{URL: "http://example.com", Tags: []string{"exploit"}},
					{URL: "http://example.com", Tags: []string{"exploit"}},
				},
			},
		},
	}

	m.extractCVEResults(&exec, resp, nil, gen)

	exploitCount := 0
	for _, res := range exec.Results {
		if res.Type == constants.TypeExploit {
			exploitCount++
		}
	}
	if exploitCount != 1 {
		t.Errorf("expected exactly 1 exploit result (due to empty URL and deduplication), got %d", exploitCount)
	}
}

func TestExtractVulnLookupMeta_EdgeCases(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()

	exec1 := modutil.NewExecution(constants.FuncEnrichCirclCVE)
	meta1 := &VulnLookupMeta{NVD: ""}
	extractVulnLookupMeta(&exec1, meta1, nil, false, false, gen)
	if len(exec1.Results) != 0 {
		t.Errorf("expected 0 results when NVD is empty")
	}

	exec2 := modutil.NewExecution(constants.FuncEnrichCirclCVE)
	meta2 := &VulnLookupMeta{NVD: "{invalid json}"}
	extractVulnLookupMeta(&exec2, meta2, nil, false, false, gen)
	if len(exec2.Results) != 0 {
		t.Errorf("expected 0 results when NVD JSON is invalid")
	}
}

func TestFormatAsPercentage_Error(t *testing.T) {
	val := formatAsPercentage("not a number")
	if val != "not a number" {
		t.Errorf("expected original string on error, got %q", val)
	}
}

func TestExtractNVDWeaknesses_ValidCWE(t *testing.T) {
	exec := modutil.NewExecution(constants.FuncEnrichCirclCVE)
	gen := modutil.NewLocalIDGenerator()

	weaknesses := []NVDWeakness{
		{
			Description: []NVDWeaknessDesc{
				{Value: "CWE-89"},
			},
		},
	}

	extractNVDWeaknesses(&exec, weaknesses, nil, gen)

	foundCWE := false
	foundDesc := false
	for _, res := range exec.Results {
		if res.Type == constants.TypeCWE {
			foundCWE = true
		}
		if res.Type == constants.TypeDescription && res.Value != "" {
			foundDesc = true
		}
	}

	if !foundCWE {
		t.Error("expected to find cwe")
	}
	if !foundDesc {
		t.Error("expected to find description for cwe")
	}
}

func TestBuildCVESearchURL_Error(t *testing.T) {
	originalURL := circlAPIBaseURL
	circlAPIBaseURL = "http://127.0.0.1:\x00"
	defer func() { circlAPIBaseURL = originalURL }()

	url := buildCVESearchURL("CVE-2000-0000")
	if url != "" {
		t.Errorf("expected empty string on parse error, got %q", url)
	}
}

func TestGetCWEDescription_NotFound(t *testing.T) {
	if desc := getCWEDescription("CWE-999999"); desc != "" {
		t.Errorf("expected empty description for unknown CWE, got %q", desc)
	}
}
