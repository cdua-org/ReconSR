package leakix

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestLeakixDemoAll(t *testing.T) {
	m := &leakixModule{apiKey: demoIndicator}
	data := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: testDomain},
		Functions: []string{constants.FuncGetLeakIXDomain, constants.FuncGetLeakIXSubdomains},
	}
	out, err := m.Exec(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, exec := range out.Executions {
		checkLocalIDs(t, exec.Results)
	}
}
