package vuln_lookup

import (
	"context"
	"embed"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/*.json
var demoData embed.FS

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

	fixtures := []string{"testdata/cpe_nginx.json", "testdata/cpe_nvd.json"}
	for _, f := range fixtures {
		data, err := demoData.ReadFile(f)
		if err != nil {
			modutil.SetError(exec, "read fixture err: %v", err)
			continue
		}
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

	fixtures := []string{"testdata/cve-2024-38063.json", "testdata/cve-2021-44228.json", "testdata/cve-2014-0160.json"}
	for _, f := range fixtures {
		data, err := demoData.ReadFile(f)
		if err != nil {
			modutil.SetError(exec, "read fixture err: %v", err)
			continue
		}
		modutil.SetRawFromBytes(exec, data)
		m.parseCVEResponse(exec, data, target, gen)
	}

	dlog.Printf("%s success target=%q results=%d stage=demo_parsed", constants.FuncEnrichCirclCVE, target, len(exec.Results))
}
