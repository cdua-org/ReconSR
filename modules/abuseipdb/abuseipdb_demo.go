package abuseipdb

import (
	"embed"
	"encoding/json"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/ip.json
var demoData embed.FS

func (m *module) processCheckDemo(exec *schema.ModuleExecution, target string, gen *modutil.LocalIDGenerator) {
	if !m.demoFired.CompareAndSwap(false, true) {
		dbg.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncCheckAbuseIPDB, target)
		return
	}

	dbg.Printf("%s start stage=demo_mode", constants.FuncCheckAbuseIPDB)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for AbuseIPDB (API key not configured)",
		LocalID:  gen.NextID(),
	})

	data, err := demoData.ReadFile("testdata/ip.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return
	}
	modutil.SetRawFromBytes(exec, data)

	var parsed abuseIPDBResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		modutil.SetError(exec, "unmarshal fixture err: %v", err)
		return
	}

	populateResults(exec, &parsed, gen)

	dbg.Printf("%s success stage=demo_parsed score=%d reports=%d", constants.FuncCheckAbuseIPDB, parsed.Data.AbuseConfidenceScore, parsed.Data.TotalReports)
}
