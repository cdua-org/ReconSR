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

func (m *netlasModule) runDemoDomain(exec schema.ModuleExecution, target schema.Entity, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec.RawData = string(demoDomainResponses)

	var resp netlasResponse
	if err := json.Unmarshal(demoDomainResponses, &resp); err != nil {
		modutil.SetError(&exec, "demo parse json: %v", err)
		return exec
	}

	parseDomainResponse(&exec, &resp, target, gen)
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
	dbg.Printf("%s success stage=demo_parsed", constants.FuncGetNetlasIP)
	return exec
}
