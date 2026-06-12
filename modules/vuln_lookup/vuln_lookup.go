// Package vuln_lookup queries the CIRCL Vulnerability API to enrich
// CVE entities with CVSS scores, CWE classifications, EPSS exploitation
// probabilities, and SSVC/KEV indicators.
package vuln_lookup

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

const (
	demoIndicator = "demo-api-key"
)

var dlog = debuglog.New("vuln_lookup")

type module struct {
	lastReqTime  time.Time
	cveCache     sync.Map
	cpeCache     sync.Map
	apiKey       string
	mu           sync.Mutex
	demoCPEFired atomic.Bool
	demoCVEFired atomic.Bool
}

// New instantiates the module for registration.
func New() schema.Module {
	return &module{
		apiKey: apiconfig.GetKey("Circl"),
	}
}

func (m *module) Name() string { return "vuln_lookup" }

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		CustomFunctions: map[string]schema.FunctionCapabilities{
			constants.FuncEnrichCirclCVE: {
				Limit:      1,
				DelayMs:    0,
				InputTypes: []string{constants.TypeCVE},
			},
			constants.FuncSearchCirclCPE: {
				Limit:      1,
				DelayMs:    0,
				InputTypes: []string{constants.TypeCPE, constants.TypeCPE23},
			},
		},
		Functions: []string{constants.FuncEnrichCirclCVE, constants.FuncSearchCirclCPE},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))
	ctx := context.Background()
	gen := modutil.NewLocalIDGenerator()

	for _, f := range data.Functions {
		switch f {
		case constants.FuncEnrichCirclCVE:
			executions = append(executions, m.enrichCirclCVE(ctx, data.Target.Type, data.Target.Value, gen))
		case constants.FuncSearchCirclCPE:
			executions = append(executions, m.searchCirclCPE(ctx, data.Target.Type, data.Target.Value, gen))
		default:
			exec := modutil.NewExecution(f)
			modutil.SetError(&exec, "unsupported function: %v", fmt.Errorf("%s", f))
			executions = append(executions, exec)
		}
	}

	return schema.ModuleOutput{Executions: executions}, nil
}
