package hunterio

import (
	"errors"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestDemoCoverage(t *testing.T) {
	m, ok := New().(*module)
	if !ok {
		t.Fatal("expected module to be *module")
	}
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{}

	origRead := readDemoFile
	readDemoFile = func(_ string) ([]byte, error) {
		return nil, errors.New("mock read error")
	}
	m.demoFired.Store(false)
	m.getDomainSearchDemo(exec, constants.TypeDomain, "example.com", gen)
	if exec.Error == nil || *exec.Error == "" {
		t.Error("expected error for read fail")
	}
	readDemoFile = origRead

	origUnmarshal := unmarshalJSON
	unmarshalJSON = func(_ []byte, _ any) error {
		return errors.New("mock unmarshal error")
	}
	m.demoFired.Store(false)
	exec = &schema.ModuleExecution{}
	m.getDomainSearchDemo(exec, constants.TypeDomain, "example.com", gen)
	if exec.Error == nil || *exec.Error == "" {
		t.Error("expected error for unmarshal fail")
	}
	unmarshalJSON = origUnmarshal

	m.demoFired.Store(false)
	exec = &schema.ModuleExecution{}
	m.getDomainSearchDemo(exec, constants.TypeOrganization, "example.com", gen)
	if exec.Error != nil && *exec.Error != "" {
		t.Errorf("expected no error for success demo, got: %v", *exec.Error)
	}

	exec = &schema.ModuleExecution{}
	m.getDomainSearchDemo(exec, constants.TypeOrganization, "example.com", gen)
	if len(exec.Results) != 0 {
		t.Error("expected no results when already fired")
	}

	unmarshalJSON = func(_ []byte, v any) error {
		if resp, ok := v.(*apiDomainSearchResponse); ok {
			resp.Errors = []struct {
				Details string `json:"details"`
			}{{Details: "demo mock error"}}
		}
		return nil
	}
	m.demoFired.Store(false)
	exec = &schema.ModuleExecution{}
	m.getDomainSearchDemo(exec, constants.TypeDomain, "example.com", gen)
	if exec.Error != nil {
		t.Error("expected no execution error for API error branch, as it adds a result")
	}
	unmarshalJSON = origUnmarshal
}
