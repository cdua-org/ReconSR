package leakix

import (
	"embed"
	"encoding/json"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/service_domain_response.json testdata/service_ip_response.json testdata/subdomains_response.json
var demoData embed.FS

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

	data, err := demoData.ReadFile("testdata/service_domain_response.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return *exec
	}

	resp, err := parseLeakixResponse(data)
	if err != nil {
		modutil.SetError(exec, "parse json: %v", err)
		return *exec
	}
	formatLeakixResults(exec, resp, target, gen)
	modutil.SetRawFromBytes(exec, data)

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

	data, err := demoData.ReadFile("testdata/service_ip_response.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return *exec
	}

	resp, err := parseLeakixResponse(data)
	if err != nil {
		modutil.SetError(exec, "parse json: %v", err)
		return *exec
	}
	formatLeakixResults(exec, resp, target, gen)
	modutil.SetRawFromBytes(exec, data)

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

	data, err := demoData.ReadFile("testdata/subdomains_response.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return *exec
	}

	var resp []SubdomainResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		modutil.SetError(exec, "parse json: %v", err)
		return *exec
	}

	formatLeakixSubdomains(exec, resp, target.Value, gen)
	modutil.SetRawFromBytes(exec, data)

	dbg.Printf("%s success stage=demo_parsed", constants.FuncGetLeakIXSubdomains)
	return *exec
}
