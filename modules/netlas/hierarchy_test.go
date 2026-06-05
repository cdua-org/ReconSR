package netlas

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
	"testing"
)

func TestNetlasGetSubdomain(t *testing.T) {
	fixtureData := readNetlasFixture(t, "domain_responses_subdomain.json")
	server := setupMockServer(t, fixtureData)
	defer server.Close()

	originalURL := netlasAPIBaseURL
	netlasAPIBaseURL = server.URL
	defer func() { netlasAPIBaseURL = originalURL }()

	resolver.MaxRetriesNetlas = 1

	m := &netlasModule{apiKey: testAPIKey}

	target := schema.Entity{
		Type:  constants.TypeSubdomain,
		Value: "cpanel.example.com",
	}

	input := schema.ModuleInput{
		Target:    target,
		Functions: []string{constants.FuncGetNetlasDomain},
	}

	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	exec := out.Executions[0]
	if exec.Error != nil {
		t.Fatalf("expected no error, got %v", *exec.Error)
	}

	requireUniqueLocalIDs(t, exec.Results)
	requireValidSourceChaining(t, exec.Results, target.Type, target.Value)
}
