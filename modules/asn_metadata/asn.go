package asn_metadata

import (
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

const errInvalidASNFormat = "invalid asn format"

var dbg = debuglog.New("asn_meta")

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
		Functions:  []string{"get_asn_peers", "get_asn_prefixes", "get_asn_info", "get_asn_abuse_contacts"},
		InputTypes: []string{"asn"},
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   10,
			DelayMs: 500,
		},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case "get_asn_peers":
			execution = getASNPeers(data.Target.Value)
		case "get_asn_prefixes":
			execution = getASNPrefixes(data.Target.Value)
		case "get_asn_info":
			execution = getASNInfo(data.Target.Value)
		case "get_asn_abuse_contacts":
			execution = getASNAbuseContacts(data.Target.Value)
		default:
			execution = modutil.NewExecution(f)
			errMsg := "unsupported function: " + f
			execution.Error = &errMsg
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}
