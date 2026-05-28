// Package ipinfo implements a module for IP metadata reconnaissance using the IPinfo API.
package ipinfo

import (
	"errors"

	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

var dbg = debuglog.New("ipinfo")

type module struct {
	apiKey string
}

// New creates a new ipinfo module instance.
func New() schema.Module {
	return &module{
		apiKey: apiconfig.GetKey("IPinfo"),
	}
}

func (m *module) Name() string { return "ipinfo" }

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	if m.apiKey == "" {
		return schema.ModuleCapabilities{}, nil
	}

	return schema.ModuleCapabilities{
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:      3,
			DelayMs:    200,
			InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
		},
		Functions: []string{constants.FuncGetIPInfo},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		exec := modutil.NewExecution(f)
		gen := modutil.NewLocalIDGenerator()

		if f == constants.FuncGetIPInfo {
			if m.apiKey == "demo-api-key" {
				m.processCheckDemo(&exec, data.Target.Value, gen)
			} else {
				processCheck(&exec, data.Target.Value, m.apiKey, gen)
			}
		} else {
			modutil.SetError(&exec, "unsupported function: %v", errors.New(f))
		}

		executions = append(executions, exec)
	}

	return schema.ModuleOutput{Executions: executions}, nil
}
