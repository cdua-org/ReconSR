// Package shodan provides integration with Shodan APIs and InternetDB.
package shodan

import (
	"sync"
	"time"

	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
	"sync/atomic"
)

const moduleName = "shodan"

type shodanModule struct {
	lastReqTime     time.Time
	apiKey          string
	queryCredits    int
	preflightOnce   sync.Once
	mu              sync.Mutex
	keyInvalid      bool
	demoDomainFired atomic.Bool
	demoIPFired     atomic.Bool
}

// New returns a new instance of the Shodan module.
func New() schema.Module {
	return &shodanModule{
		apiKey: apiconfig.GetKey("Shodan"),
	}
}

func (m *shodanModule) Name() string {
	return moduleName
}

func (m *shodanModule) Capabilities() (schema.ModuleCapabilities, error) {
	customFns := make(map[string]schema.FunctionCapabilities, 2)

	if m.apiKey == "" {
		customFns[constants.FuncGetIDBShodan] = getInternetDBCapabilities()
	} else {
		customFns[constants.FuncGetShodanAPIIP] = schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    0,
			InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
		}
		inputTypes := []string{constants.TypeDomain}
		if resolver.ShodanScanSubdomains {
			inputTypes = append(inputTypes, constants.TypeSubdomain)
		}

		customFns[constants.FuncGetShodanAPIDomain] = schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    0,
			InputTypes: inputTypes,
		}
	}

	return schema.ModuleCapabilities{
		CustomFunctions: customFns,
	}, nil
}

func (m *shodanModule) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	execs := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, fn := range data.Functions {
		switch fn {
		case constants.FuncGetIDBShodan:
			if m.apiKey == "" {
				execs = append(execs, getInternetDB(data.Target))
				continue
			}
		case constants.FuncGetShodanAPIIP:
			if m.apiKey != "" {
				execs = append(execs, m.getShodanAPIIP(data.Target))
				continue
			}
		case constants.FuncGetShodanAPIDomain:
			if m.apiKey != "" {
				execs = append(execs, m.getShodanAPIDomain(data.Target))
				continue
			}
		}

		exec := modutil.NewExecution(fn)
		errMsg := "unsupported function: " + fn
		exec.Error = &errMsg
		execs = append(execs, exec)
	}

	return schema.ModuleOutput{Executions: execs}, nil
}
