// Package vuln_lookup queries the CIRCL Vulnerability API to enrich
// CVE entities with CVSS scores, CWE classifications, EPSS exploitation
// probabilities, and SSVC/KEV indicators.
package vuln_lookup

import (
	"context"
	"fmt"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

var dlog = debuglog.New("vuln_lookup")

type module struct{}

// New instantiates the module for registration.
func New() schema.Module { return &module{} }

func (m *module) Name() string { return "vuln_lookup" }

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    2000,
			InputTypes: []string{constants.TypeCVE},
		},
		Functions: []string{constants.FuncGetCirclVuln},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))
	ctx := context.Background()

	for _, f := range data.Functions {
		switch f {
		case constants.FuncGetCirclVuln:
			executions = append(executions, getCirclVuln(ctx, data.Target.Type, data.Target.Value))
		default:
			exec := modutil.NewExecution(f)
			modutil.SetError(&exec, "unsupported function: %v", fmt.Errorf("%s", f))
			executions = append(executions, exec)
		}
	}

	return schema.ModuleOutput{Executions: executions}, nil
}
