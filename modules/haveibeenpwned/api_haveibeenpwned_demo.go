package haveibeenpwned

import (
	"encoding/json"
	"os"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func (m *module) getEmailBreachesDemo(exec *schema.ModuleExecution, email string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	dlog.Printf("%s success stage=demo email=%s", constants.FuncGetEmailBreaches, email)

	if !m.demoFired.CompareAndSwap(false, true) {
		return *exec
	}

	data, err := os.ReadFile("modules/haveibeenpwned/testdata/multiple-breaches.json")
	if err != nil {
		data, err = os.ReadFile("testdata/multiple-breaches.json")
		if err != nil {
			modutil.SetError(exec, "demo failed to read testdata: %v", err)
			return *exec
		}
	}

	var breaches []apiBreachEntry
	if err := json.Unmarshal(data, &breaches); err != nil {
		modutil.SetError(exec, "demo failed to parse testdata: %v", err)
		return *exec
	}

	processBreaches(exec, email, breaches, gen)
	modutil.SetRawFromBytes(exec, data)

	return *exec
}
