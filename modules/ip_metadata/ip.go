package ip_metadata

import (
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

var dbg = debuglog.New("ip_meta")

const (
	errInvalidIPFormat = "invalid ip address format: "
	typeASN            = "asn"
	typeCIDR           = "cidr"
	typeTag            = "tag"
	typePTR            = "ptr"
)

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
		Functions:  []string{"get_ptr", "get_asn", "get_tor", "get_rbl", "get_ip_info", "get_ip_abuse_contacts"},
		InputTypes: []string{"ipv4", "ipv6"},
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   50,
			DelayMs: 0,
		},
		CustomFunctions: map[string]schema.FunctionCapabilities{
			"get_ip_info": {
				Limit:   3,
				DelayMs: 1000,
			},
			"get_ip_abuse_contacts": {
				Limit:   3,
				DelayMs: 1000,
			},
			"get_tor": {
				Limit: 10,
			},
			"get_rbl": {
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
		case "get_ptr":
			execution = getPTRData(data.Target.Value)
		case "get_asn":
			execution = getASNData(data.Target.Value)
		case "get_tor":
			execution = getTorData(data.Target.Value)
		case "get_rbl":
			execution = getRBLData(data.Target.Value)
		case "get_ip_info":
			execution = getIPInfo(data.Target.Value)
		case "get_ip_abuse_contacts":
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
