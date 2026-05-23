package maxmind

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

var dbg = debuglog.New("maxmind")

type module struct {
	enterpriseDBPath string
	cityDBPath       string
	asnDBPath        string
	proxyDBPath      string
}

// New initializes the MaxMind module dependencies to satisfy the Dispatcher contract for localized intelligence gathering.
func New() schema.Module {
	mod := &module{}

	mod.enterpriseDBPath = resolveDBPath("GeoIP2-Enterprise.mmdb")
	mod.cityDBPath = resolveDBPath("GeoIP2-City.mmdb", "GeoLite2-City.mmdb")
	mod.asnDBPath = resolveDBPath("GeoIP2-ISP.mmdb", "GeoIP2-ASN.mmdb", "GeoLite2-ASN.mmdb")
	mod.proxyDBPath = resolveDBPath("GeoIP-Anonymous-Plus.mmdb", "GeoIP2-Anonymous-IP.mmdb")

	return mod
}

func (m *module) Name() string {
	return "maxmind"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	if m.cityDBPath == "" && m.asnDBPath == "" && m.proxyDBPath == "" {
		return schema.ModuleCapabilities{}, nil
	}

	caps := schema.ModuleCapabilities{
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   500,
			DelayMs: 0,
		},
		CustomFunctions: make(map[string]schema.FunctionCapabilities),
	}

	if m.enterpriseDBPath != "" {
		caps.Functions = append(caps.Functions, constants.FuncGetMMEnterpriseData)
		caps.CustomFunctions[constants.FuncGetMMEnterpriseData] = schema.FunctionCapabilities{
			InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
		}
	} else if m.cityDBPath != "" {
		caps.Functions = append(caps.Functions, constants.FuncGetGeoIP)
		caps.CustomFunctions[constants.FuncGetGeoIP] = schema.FunctionCapabilities{
			InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
		}
	}

	if m.asnDBPath != "" {
		caps.Functions = append(caps.Functions, constants.FuncGetIPASN)
		caps.CustomFunctions[constants.FuncGetIPASN] = schema.FunctionCapabilities{
			InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
		}
	}

	if m.proxyDBPath != "" {
		caps.Functions = append(caps.Functions, constants.FuncGetProxyCheck)
		caps.CustomFunctions[constants.FuncGetProxyCheck] = schema.FunctionCapabilities{
			InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
		}
	}

	return caps, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case constants.FuncGetMMEnterpriseData:
			if m.enterpriseDBPath != "" {
				execution = getEnterpriseData(data.Target.Value, m.enterpriseDBPath)
			} else {
				execution = modutil.NewExecution(f)
			}
		case constants.FuncGetGeoIP:
			if m.cityDBPath != "" {
				execution = getGeoIP(data.Target.Value, m.cityDBPath)
			} else {
				execution = modutil.NewExecution(f)
			}
		case constants.FuncGetIPASN:
			if m.asnDBPath != "" {
				execution = getIPASN(data.Target.Value, m.asnDBPath)
			} else {
				execution = modutil.NewExecution(f)
			}
		case constants.FuncGetProxyCheck:
			if m.proxyDBPath != "" {
				execution = getProxyCheck(data.Target.Value, m.proxyDBPath)
			} else {
				execution = modutil.NewExecution(f)
			}
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
