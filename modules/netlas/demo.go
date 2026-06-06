package netlas

import (
	_ "embed"
	"encoding/json"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/domain_responses.json
var demoDomainResponses []byte

//go:embed testdata/ip_responses.json
var demoIPResponses []byte

//go:embed testdata/ip_download.json
var demoIPDownload []byte

func (m *netlasModule) runDemoDomain(exec schema.ModuleExecution, target schema.Entity, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec.RawData = string(demoDomainResponses)

	var resp netlasResponse
	if err := json.Unmarshal(demoDomainResponses, &resp); err != nil {
		modutil.SetError(&exec, "demo parse json: %v", err)
		return exec
	}

	parseDomainResponse(&exec, &resp, target, gen)
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for Netlas Domain (API key not configured)",
		LocalID:  gen.NextID(),
	})
	dbg.Printf("%s success stage=demo_parsed", constants.FuncGetNetlasDomain)
	return exec
}

func (m *netlasModule) runDemoIP(exec schema.ModuleExecution, target schema.Entity, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec.RawData = string(demoIPResponses)

	var resp netlasIPResponse
	if err := json.Unmarshal(demoIPResponses, &resp); err != nil {
		modutil.SetError(&exec, "demo parse json: %v", err)
		return exec
	}

	parseIPResponse(&exec, &resp, target, gen)
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for Netlas IP (API key not configured)",
		LocalID:  gen.NextID(),
	})
	dbg.Printf("%s success stage=demo_parsed", constants.FuncGetNetlasIP)
	return exec
}

//go:embed testdata/domain_download.json
var demoDomainDownload []byte

func (m *netlasModule) runDemoDownloadByQuery(exec schema.ModuleExecution, target schema.Entity, fn string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	var payload []byte
	if fn == constants.FuncGetNetlasDomainsByIP {
		payload = demoIPDownload
	} else {
		payload = demoDomainDownload
	}
	exec.RawData = string(payload)

	var items []downloadItem
	if err := json.Unmarshal(payload, &items); err != nil {
		modutil.SetError(&exec, "demo parse json: %v", err)
		return exec
	}

	emitTargetApplied(&exec, target, target.Value, gen)
	targetRef := &schema.EntityRef{Type: target.Type, Value: target.Value}
	emitDomainResults(&exec, items, targetRef, gen)
	var demoMsg string
	if fn == constants.FuncGetNetlasDomainsByIP {
		demoMsg = "⚠️ DEMO MODE: Showing sample data for Netlas Domains Download by IP (API key not configured)"
	} else {
		demoMsg = "⚠️ DEMO MODE: Showing sample data for Netlas Domains Download by Domain (API key not configured)"
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    demoMsg,
		LocalID:  gen.NextID(),
	})
	dbg.Printf("%s success stage=demo_parsed", fn)
	return exec
}
