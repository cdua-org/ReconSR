package vuln_lookup

import (
	"context"
	_ "embed"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/cpe_nginx.json
var demoCPENginx []byte

//go:embed testdata/cpe_nvd.json
var demoCPENVD []byte

//go:embed testdata/cve-2024-38063.json
var demoCVE1 []byte

//go:embed testdata/cve-2021-44228.json
var demoCVE2 []byte

//go:embed testdata/cve-2014-0160.json
var demoCVE3 []byte

func (m *module) searchCirclCPEDemo(ctx context.Context, exec *schema.ModuleExecution, target string, gen *modutil.LocalIDGenerator) {
	_ = ctx
	if !m.demoCPEFired.CompareAndSwap(false, true) {
		dlog.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncSearchCirclCPE, target)
		return
	}

	dlog.Printf("%s start stage=demo_mode", constants.FuncSearchCirclCPE)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for CIRCL CPE (API key not configured)",
	})

	fixtures := [][]byte{demoCPENginx, demoCPENVD}
	for _, data := range fixtures {
		modutil.SetRawFromBytes(exec, data)
		m.parseCPEResponse(exec, data, target, gen)
	}

	dlog.Printf("%s success target=%q results=%d stage=demo_parsed", constants.FuncSearchCirclCPE, target, len(exec.Results))
}

func (m *module) enrichCirclCVEDemo(ctx context.Context, exec *schema.ModuleExecution, target string, gen *modutil.LocalIDGenerator) {
	_ = ctx
	if !m.demoCVEFired.CompareAndSwap(false, true) {
		dlog.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncEnrichCirclCVE, target)
		return
	}

	dlog.Printf("%s start stage=demo_mode", constants.FuncEnrichCirclCVE)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for CIRCL CVE (API key not configured)",
	})

	fixtures := [][]byte{demoCVE1, demoCVE2, demoCVE3}
	for _, data := range fixtures {
		modutil.SetRawFromBytes(exec, data)
		m.parseCVEResponse(exec, data, target, gen)
	}

	dlog.Printf("%s success target=%q results=%d stage=demo_parsed", constants.FuncEnrichCirclCVE, target, len(exec.Results))
}
