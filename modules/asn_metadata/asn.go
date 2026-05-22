package asn_metadata

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

const (
	errInvalidASNFormat = "invalid asn format"
	moduleName          = "asn_metadata"
)

var dbg = debuglog.New("asn_meta")

type module struct{}

// New instantiates the module for registration.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return moduleName
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{constants.FuncGetASNPeers, constants.FuncGetASNPrefixes, constants.FuncGetASNInfo, constants.FuncGetASNAbuseContacts},
		InputTypes: []string{constants.TypeASN},
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
		gen := modutil.NewLocalIDGenerator()

		switch f {
		case constants.FuncGetASNPeers:
			execution = getASNPeers(data.Target.Value, gen)
		case constants.FuncGetASNPrefixes:
			execution = getASNPrefixes(data.Target.Value, gen)
		case constants.FuncGetASNInfo:
			execution = getASNInfo(data.Target.Value, gen)
		case constants.FuncGetASNAbuseContacts:
			execution = getASNAbuseContacts(data.Target.Value, gen)
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
