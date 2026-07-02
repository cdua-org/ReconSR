// Package ip_metadata provides IP and ASN intelligence gathering.
package ip_metadata

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

var dbg = debuglog.New("ip_meta")

const errInvalidIPFormat = "invalid ip address format: "

type module struct{}

// New instantiates the IP metadata module for the Dispatcher.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "ip_metadata"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions: []string{
			constants.FuncGetPTR,
			constants.FuncGetASN,
			constants.FuncGetTOR,
			constants.FuncGetRBL,
			constants.FuncGetIPInfo,
			constants.FuncGetIPAbuseContacts,
		},
		InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   50,
			DelayMs: 0,
		},
		CustomFunctions: map[string]schema.FunctionCapabilities{
			constants.FuncGetIPInfo: {
				Limit:   3,
				DelayMs: 1000,
			},
			constants.FuncGetIPAbuseContacts: {
				Limit:   3,
				DelayMs: 1000,
			},
			constants.FuncGetTOR: {
				Limit: 10,
			},
			constants.FuncGetRBL: {
				Limit: 10,
			},
		},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case constants.FuncGetPTR:
			execution = getPTRData(data.Target.Value)
		case constants.FuncGetASN:
			execution = getASNData(data.Target.Value)
		case constants.FuncGetTOR:
			execution = getTorData(data.Target.Value)
		case constants.FuncGetRBL:
			execution = getRBLData(data.Target.Value)
		case constants.FuncGetIPInfo:
			execution = getIPInfo(data.Target.Value)
		case constants.FuncGetIPAbuseContacts:
			execution = getIPAbuseContacts(data.Target.Value)
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
