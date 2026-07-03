package leakix

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestLeakixDemoAll(t *testing.T) {
	m := &leakixModule{apiKey: demoIndicator}
	data := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: testDomain},
		Functions: []string{constants.FuncGetLeakIXDomain, constants.FuncGetLeakIXSubdomains, constants.FuncGetLeakIXIP},
	}
	out, err := m.Exec(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, exec := range out.Executions {
		checkLocalIDs(t, exec.Results)
	}
}

func TestLeakixDemo_AlreadyFired(t *testing.T) {
	m := &leakixModule{apiKey: demoIndicator}
	gen := modutil.NewLocalIDGenerator()

	tests := []struct {
		run        func(*schema.ModuleExecution, schema.Entity, *modutil.LocalIDGenerator) schema.ModuleExecution
		name       string
		target     string
		entityType string
	}{
		{m.getLeakixDomainDemo, "domain", testDomain, constants.TypeDomain},
		{m.getLeakixIPDemo, "ip", "192.0.2.1", constants.TypeIPv4},
		{m.getLeakixSubdomainsDemo, "subdomains", testDomain, constants.TypeDomain},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec1 := &schema.ModuleExecution{Function: tt.name}
			tt.run(exec1, schema.Entity{Type: tt.entityType, Value: tt.target}, gen)
			exec2 := &schema.ModuleExecution{Function: tt.name}
			tt.run(exec2, schema.Entity{Type: tt.entityType, Value: tt.target}, gen)
			if len(exec2.Results) != 0 {
				t.Errorf("expected empty results for second call, got %d", len(exec2.Results))
			}
		})
	}
}

func TestLeakixDemo_JSONError(t *testing.T) {
	origDomain := demoDomainResponse
	origIP := demoIPResponse
	origSub := demoSubdomainsResponse

	demoDomainResponse = []byte("invalid json")
	demoIPResponse = []byte("invalid json")
	demoSubdomainsResponse = []byte("invalid json")

	defer func() {
		demoDomainResponse = origDomain
		demoIPResponse = origIP
		demoSubdomainsResponse = origSub
	}()

	m := &leakixModule{apiKey: demoIndicator}
	gen := modutil.NewLocalIDGenerator()

	tests := []struct {
		run        func(*schema.ModuleExecution, schema.Entity, *modutil.LocalIDGenerator) schema.ModuleExecution
		name       string
		target     string
		entityType string
	}{
		{m.getLeakixDomainDemo, "domain", testDomain, constants.TypeDomain},
		{m.getLeakixIPDemo, "ip", "192.0.2.1", constants.TypeIPv4},
		{m.getLeakixSubdomainsDemo, "subdomains", testDomain, constants.TypeDomain},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &schema.ModuleExecution{Function: tt.name}
			tt.run(exec, schema.Entity{Type: tt.entityType, Value: tt.target}, gen)
			if exec.Error == nil {
				t.Error("expected error for invalid json")
			}
		})
	}
}
