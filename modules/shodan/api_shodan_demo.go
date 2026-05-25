package shodan

import (
	"embed"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/ip_full.json testdata/domain.json
var demoData embed.FS

// getShodanAPIIPDemo is a demo function that loads a local JSON fixture
// instead of querying the Shodan API when the "demo-api-key" is used.
func (m *shodanModule) getShodanAPIIPDemo(exec *schema.ModuleExecution, target schema.Entity) schema.ModuleExecution {
	if !m.demoIPFired.CompareAndSwap(false, true) {
		dbg.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncGetShodanAPIIP, target.Value)
		return *exec
	}

	dbg.Printf("%s start stage=demo_mode", constants.FuncGetShodanAPIIP)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for Shodan (API key not configured)",
	})

	data, err := demoData.ReadFile("testdata/ip_full.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return *exec
	}

	parseShodanAPIIP(exec, data, target.Value)
	modutil.SetRawFromBytes(exec, data)

	dbg.Printf("%s success stage=demo_parsed", constants.FuncGetShodanAPIIP)

	return *exec
}

// getShodanAPIDomainDemo is a demo function that loads a local JSON fixture
// instead of querying the Shodan API when the "demo-api-key" is used.
func (m *shodanModule) getShodanAPIDomainDemo(exec *schema.ModuleExecution, target schema.Entity) schema.ModuleExecution {
	if !m.demoDomainFired.CompareAndSwap(false, true) {
		dbg.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncGetShodanAPIDomain, target.Value)
		return *exec
	}

	dbg.Printf("%s start stage=demo_mode", constants.FuncGetShodanAPIDomain)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for Shodan (API key not configured)",
	})

	data, err := demoData.ReadFile("testdata/domain.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return *exec
	}

	parseShodanAPIDomain(exec, data, target.Value)
	modutil.SetRawFromBytes(exec, data)

	dbg.Printf("%s success stage=demo_parsed", constants.FuncGetShodanAPIDomain)

	return *exec
}
