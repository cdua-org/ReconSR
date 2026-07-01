package haveibeenpwned

import (
	"embed"
	"encoding/json"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/multiple-breaches.json
var demoData embed.FS

var (
	readDemoFile  = demoData.ReadFile
	unmarshalJSON = json.Unmarshal
)

func (m *module) getEmailBreachesDemo(exec *schema.ModuleExecution, email string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	dlog.Printf("%s success stage=demo email=%s", constants.FuncGetEmailBreaches, email)

	if !m.demoFired.CompareAndSwap(false, true) {
		return *exec
	}

	data, err := readDemoFile("testdata/multiple-breaches.json")
	if err != nil {
		modutil.SetError(exec, "demo failed to read testdata: %v", err)
		return *exec
	}

	var breaches []apiBreachEntry
	if err := unmarshalJSON(data, &breaches); err != nil {
		modutil.SetError(exec, "demo failed to parse testdata: %v", err)
		return *exec
	}

	processBreaches(exec, email, breaches, gen)
	modutil.SetRawFromBytes(exec, data)

	return *exec
}
