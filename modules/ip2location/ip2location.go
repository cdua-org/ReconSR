// Package ip2location provides IP intelligence gathering using local IP2Location databases.
package ip2location

import (
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

var dbg = debuglog.New("ip2loc")

type module struct {
	geoDBPath   string
	asnDBPath   string
	proxyDBPath string
	proxyIsLite bool
}

// New instantiates the IP2Location module for the Dispatcher.
// It checks for the existence of database files at startup.
func New() schema.Module {
	mod := &module{}

	mod.geoDBPath = resolveDBPath("IP2LOCATION-DB11.IPV6.BIN", "IP2LOCATION-LITE-DB11.IPV6.BIN")
	mod.asnDBPath = resolveDBPath("IP2LOCATION-ASN.IPV6.BIN", "IP2LOCATION-LITE-ASN.IPV6.BIN")
	mod.proxyDBPath = resolveDBPath("IP2PROXY-PX12.BIN", "IP2PROXY-LITE-PX12.BIN")

	if mod.proxyDBPath != "" {
		mod.proxyIsLite = strings.Contains(strings.ToUpper(mod.proxyDBPath), "LITE")
	}

	return mod
}

func (m *module) Name() string {
	return "ip2location"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	if m.geoDBPath == "" && m.asnDBPath == "" && m.proxyDBPath == "" {
		return schema.ModuleCapabilities{}, nil
	}

	caps := schema.ModuleCapabilities{
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   500,
			DelayMs: 0,
		},
		CustomFunctions: make(map[string]schema.FunctionCapabilities),
	}

	if m.geoDBPath != "" {
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
		proxyInputTypes := []string{constants.TypeIPv4}
		if !m.proxyIsLite {
			proxyInputTypes = append(proxyInputTypes, constants.TypeIPv6)
		}
		caps.CustomFunctions[constants.FuncGetProxyCheck] = schema.FunctionCapabilities{
			InputTypes: proxyInputTypes,
		}
	}

	return caps, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case constants.FuncGetGeoIP:
			if m.geoDBPath != "" {
				execution = getGeoIP(data.Target.Value, m.geoDBPath)
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
