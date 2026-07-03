package leakix

import (
	_ "embed"
	"encoding/json"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/service_domain_response.json
var demoDomainResponse []byte

//go:embed testdata/service_ip_response.json
var demoIPResponse []byte

//go:embed testdata/subdomains_response.json
var demoSubdomainsResponse []byte

// getLeakixDomainDemo is a demo function that loads a local JSON fixture
// instead of querying the LeakIX API when the "demo-api-key" is used.
func (m *leakixModule) getLeakixDomainDemo(exec *schema.ModuleExecution, target schema.Entity, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	if !m.demoDomainFired.CompareAndSwap(false, true) {
		dbg.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncGetLeakIXDomain, target.Value)
		return *exec
	}

	dbg.Printf("%s start stage=demo_mode", constants.FuncGetLeakIXDomain)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for LeakIX Domain (API key not configured)",
		LocalID:  gen.NextID(),
	})

	resp, err := parseLeakixResponse(demoDomainResponse)
	if err != nil {
		modutil.SetError(exec, "parse json: %v", err)
		return *exec
	}
	formatLeakixResults(exec, resp, target, gen)
	modutil.SetRawFromBytes(exec, demoDomainResponse)

	dbg.Printf("%s success stage=demo_parsed", constants.FuncGetLeakIXDomain)

	return *exec
}

// getLeakixIPDemo is a demo function that loads a local JSON fixture
// instead of querying the LeakIX API when the "demo-api-key" is used.
func (m *leakixModule) getLeakixIPDemo(exec *schema.ModuleExecution, target schema.Entity, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	if !m.demoIPFired.CompareAndSwap(false, true) {
		dbg.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncGetLeakIXIP, target.Value)
		return *exec
	}

	dbg.Printf("%s start stage=demo_mode", constants.FuncGetLeakIXIP)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for LeakIX IP (API key not configured)",
		LocalID:  gen.NextID(),
	})

	resp, err := parseLeakixResponse(demoIPResponse)
	if err != nil {
		modutil.SetError(exec, "parse json: %v", err)
		return *exec
	}
	formatLeakixResults(exec, resp, target, gen)
	modutil.SetRawFromBytes(exec, demoIPResponse)

	dbg.Printf("%s success stage=demo_parsed", constants.FuncGetLeakIXIP)

	return *exec
}

// getLeakixSubdomainsDemo is a demo function that loads a local JSON fixture
// instead of querying the LeakIX API when the "demo-api-key" is used.
func (m *leakixModule) getLeakixSubdomainsDemo(exec *schema.ModuleExecution, target schema.Entity, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	if !m.demoSubdomainFired.CompareAndSwap(false, true) {
		dbg.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncGetLeakIXSubdomains, target.Value)
		return *exec
	}

	dbg.Printf("%s start stage=demo_mode", constants.FuncGetLeakIXSubdomains)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for LeakIX Subdomains (API key not configured)",
		LocalID:  gen.NextID(),
	})

	var resp []SubdomainResponse
	if err := json.Unmarshal(demoSubdomainsResponse, &resp); err != nil {
		modutil.SetError(exec, "parse json: %v", err)
		return *exec
	}

	formatLeakixSubdomains(exec, resp, target.Value, gen)
	modutil.SetRawFromBytes(exec, demoSubdomainsResponse)

	dbg.Printf("%s success stage=demo_parsed", constants.FuncGetLeakIXSubdomains)
	return *exec
}
