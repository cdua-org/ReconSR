package maxmind

import (
	"errors"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"

	"github.com/oschwald/geoip2-golang"
)

func TestModule_Name(t *testing.T) {
	m := New()
	if m.Name() != "maxmind" {
		t.Errorf("expected maxmind, got %s", m.Name())
	}
}

func TestModule_Capabilities_Empty(t *testing.T) {
	origCheck := checkFileExists
	defer func() { checkFileExists = origCheck }()

	checkFileExists = func(_ string) bool { return false }

	m := New()
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(caps.Functions) != 0 {
		t.Errorf("expected 0 functions, got %d", len(caps.Functions))
	}
}

func TestModule_Capabilities_All(t *testing.T) {
	origCheck := checkFileExists
	defer func() { checkFileExists = origCheck }()

	checkFileExists = func(_ string) bool { return true }

	m := New()
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedFuncs := []string{
		constants.FuncGetMMEnterpriseData,
		constants.FuncGetIPASN,
		constants.FuncGetProxyCheck,
	}

	if len(caps.Functions) != len(expectedFuncs) {
		t.Errorf("expected %d functions, got %d", len(expectedFuncs), len(caps.Functions))
	}

	for _, f := range expectedFuncs {
		if _, ok := caps.CustomFunctions[f]; !ok {
			t.Errorf("expected custom function config for %s", f)
		}
	}
}

func TestModule_Exec(t *testing.T) {
	m := &module{
		cityDBPath:  "mock-city.mmdb",
		asnDBPath:   "mock-asn.mmdb",
		proxyDBPath: "mock-proxy.mmdb",
	}

	origGeoQuery := geoQueryFunc
	defer func() { geoQueryFunc = origGeoQuery }()
	geoQueryFunc = func(_, _ string) (*geoip2.City, error) {
		return nil, errors.New("mock geo error")
	}

	data := schema.ModuleInput{
		Target: schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.1"},
		Functions: []string{
			constants.FuncGetGeoIP,
			"unsupported_function",
		},
	}

	out, err := m.Exec(data)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(out.Executions) != 2 {
		t.Fatalf("expected 2 executions, got %d", len(out.Executions))
	}

	if out.Executions[0].Function != constants.FuncGetGeoIP {
		t.Errorf("expected %s", constants.FuncGetGeoIP)
	}

	if out.Executions[1].Function != "unsupported_function" {
		t.Errorf("expected unsupported_function")
	}
	if out.Executions[1].Error == nil || *out.Executions[1].Error != "unsupported function: unsupported_function" {
		t.Errorf("expected unsupported function error")
	}
}
