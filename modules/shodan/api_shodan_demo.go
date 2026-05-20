package shodan

import (
	"os"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

// getShodanAPIIPDemo is a demo function that loads a local JSON fixture
// instead of querying the Shodan API when the "demo-api-key" is used.
func (m *shodanModule) getShodanAPIIPDemo(exec *schema.ModuleExecution, target schema.Entity) schema.ModuleExecution {
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for Shodan (API key not configured)",
	})

	data, err := os.ReadFile("modules/shodan/testdata/ip_full.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return *exec
	}

	parseShodanAPIIP(exec, data, target.Value)
	modutil.SetRawFromBytes(exec, data)

	return *exec
}

// getShodanAPIDomainDemo is a demo function that loads a local JSON fixture
// instead of querying the Shodan API when the "demo-api-key" is used.
func (m *shodanModule) getShodanAPIDomainDemo(exec *schema.ModuleExecution, target schema.Entity) schema.ModuleExecution {
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for Shodan (API key not configured)",
	})

	data, err := os.ReadFile("modules/shodan/testdata/domain.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return *exec
	}

	parseShodanAPIDomain(exec, data, target.Value)
	modutil.SetRawFromBytes(exec, data)

	return *exec
}
