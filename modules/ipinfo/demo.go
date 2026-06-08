package ipinfo

import (
	"embed"
	"encoding/json"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/fake-max-dirty.json
var demoData embed.FS

const defaultDemoIP = "203.0.113.30"
const defaultDemoFixture = "fake-max-dirty.json"

func (m *module) processCheckDemo(exec *schema.ModuleExecution, targetValue string, gen *modutil.LocalIDGenerator) {
	dbg.Printf("%s demo target=%q", constants.FuncGetIPInfo, targetValue)

	fileName := defaultDemoFixture

	content, err := demoData.ReadFile("testdata/" + fileName)
	if err != nil {
		modutil.SetError(exec, "read testdata: %v", err)
		return
	}

	var parsed ipinfoResponse
	if err := json.Unmarshal(content, &parsed); err != nil {
		modutil.SetError(exec, "parse testdata: %v", err)
		return
	}

	modutil.SetRawFromBytes(exec, content)
	populateResults(exec, &parsed, gen)
}
