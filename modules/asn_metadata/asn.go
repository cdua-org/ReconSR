package asn_metadata

import "cdua-org/ReconSR/schema"

type module struct{}

// New instantiates the module for registration.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "asn_metadata"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_asn_peers"},
		InputTypes: []string{"asn"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case "get_asn_peers":
			execution = getASNPeers(data.Target.Value)
		default:
			errMsg := "unsupported function: " + f
			execution = schema.ModuleExecution{
				Function: f,
				Error:    &errMsg,
			}
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}
