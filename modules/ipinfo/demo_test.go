package ipinfo

import (
	"errors"
	"os"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestIPInfoDemoMode(t *testing.T) {
	if err := os.Setenv("RECONSR_IPINFO", "demo-api-key"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_IPINFO"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	m := New()
	data := schema.ModuleInput{
		Functions: []string{constants.FuncGetIPInfo},
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: defaultDemoIP},
	}

	out, err := m.Exec(data)
	if err != nil {
		t.Fatalf("Unexpected exec error: %v", err)
	}

	exec := out.Executions[0]
	if exec.Error != nil {
		t.Fatalf("Unexpected execution error: %v", *exec.Error)
	}
	if len(exec.Results) == 0 {
		t.Fatalf("Expected results, got 0")
	}

	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}

	if !hasResult(constants.TypeGeo, "City: AnotherFakeCity | Region: AnotherFakeRegion | Country: AnotherFakeCountry (YY) | Lat/Lon: 1.111100, -1.111100 | Zip: 11111 | TZ: Fake/Timezone_Two") {
		t.Errorf("Missing expected Geo location formatting in demo mode")
	}
	if !hasResult(constants.TypeTag, "anonymous") {
		t.Errorf("Missing anonymous tag in demo mode")
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestProcessCheckDemo_Errors(t *testing.T) {
	if err := os.Setenv("RECONSR_IPINFO", "demo-api-key"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_IPINFO"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	m := New()

	t.Run("ReadFile Error", func(t *testing.T) {
		oldRead := readDemoFile
		readDemoFile = func(_ string) ([]byte, error) {
			return nil, errors.New("simulated read error")
		}
		defer func() {
			readDemoFile = oldRead
		}()

		out, err := m.Exec(schema.ModuleInput{
			Functions: []string{constants.FuncGetIPInfo},
			Target:    schema.Entity{Type: constants.TypeIPv4, Value: "203.0.113.30"},
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if out.Executions[0].Error == nil || !strings.Contains(*out.Executions[0].Error, "simulated read error") {
			t.Errorf("expected read error, got: %v", *out.Executions[0].Error)
		}
	})

	t.Run("Unmarshal Error", func(t *testing.T) {
		oldRead := readDemoFile
		readDemoFile = func(_ string) ([]byte, error) {
			return []byte("invalid json"), nil
		}
		defer func() {
			readDemoFile = oldRead
		}()

		out, err := m.Exec(schema.ModuleInput{
			Functions: []string{constants.FuncGetIPInfo},
			Target:    schema.Entity{Type: constants.TypeIPv4, Value: "203.0.113.30"},
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if out.Executions[0].Error == nil || !strings.Contains(*out.Executions[0].Error, "parse testdata") {
			t.Errorf("expected parse error, got: %v", *out.Executions[0].Error)
		}
	})
}
