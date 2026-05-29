package leakix

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestLeakixSubdomains(t *testing.T) {
	teardown := newTestServer(t, "subdomains_response.json")
	defer teardown()

	m := &leakixModule{
		apiKey: testKey,
	}

	target := schema.Entity{Type: constants.TypeDomain, Value: testDomain}
	exec := m.getLeakixSubdomains(target, constants.FuncGetLeakIXSubdomains, modutil.NewLocalIDGenerator())

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %v", *exec.Error)
	}

	if len(exec.Results) == 0 {
		t.Fatalf("Expected results, got 0")
	}

	assertSubdomains(t, exec.Results)
	checkLocalIDs(t, exec.Results)
}

func assertSubdomains(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	var hasSub1, hasSub2, hasDistinctIPs, hasLastSeen bool
	for _, res := range results {
		if res.Type == constants.TypeSubdomain && res.Value == "www.example.com" {
			hasSub1 = true
		}
		if res.Type == constants.TypeDate && res.Value == "Last Seen: 2026-05-20T11:25:41.243Z" {
			hasLastSeen = true
		}
		if res.Type == constants.TypeSubdomain && res.Value == "staging.example.com" {
			hasSub2 = true
		}
		if res.Type == constants.TypeInfo && res.Value == "Distinct IPs: 2" {
			hasDistinctIPs = true
		}
	}

	if !hasSub1 || !hasSub2 {
		t.Errorf("Expected subdomains www.example.com and staging.example.com")
	}
	if !hasDistinctIPs {
		t.Errorf("Expected distinct IPs info")
	}
	if !hasLastSeen {
		t.Errorf("Expected Last Seen info")
	}
}
