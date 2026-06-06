package netlas

import (
	"sync"
	"sync/atomic"
	"time"

	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	moduleName    = "netlas"
	demoIndicator = "demo-api-key"
)

var dbg = debuglog.New(moduleName)

type netlasModule struct {
	lastReqTime     time.Time
	apiKey          string
	invalidMsg      string
	mu              sync.Mutex
	preflightSync   sync.Once
	coins           int
	limitPerDl      int
	keyInvalid      atomic.Bool
	quotaBlocked    atomic.Bool
	demoDomainFired atomic.Bool
	demoIPFired     atomic.Bool
}

// New initializes the Netlas module to enable host and domain enrichment via the netlas.io API.
func New() schema.Module {
	return &netlasModule{
		apiKey: apiconfig.GetKey("Netlas"),
	}
}

func (m *netlasModule) Name() string {
	return moduleName
}

func (m *netlasModule) Capabilities() (schema.ModuleCapabilities, error) {
	customFns := make(map[string]schema.FunctionCapabilities)

	if m.apiKey != "" {
		domainTypes := []string{constants.TypeDomain}
		if resolver.NetlasScanSubdomains {
			domainTypes = append(domainTypes, constants.TypeSubdomain)
		}
		ipTypes := []string{constants.TypeIPv4}

		customFns[constants.FuncGetNetlasDomain] = schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    0,
			InputTypes: domainTypes,
		}
		customFns[constants.FuncGetNetlasIP] = schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    0,
			InputTypes: ipTypes,
		}

		if resolver.NetlasLimitPerOneDownload > 0 {
			customFns[constants.FuncGetNetlasDomainsByIP] = schema.FunctionCapabilities{
				Limit:      1,
				DelayMs:    0,
				InputTypes: []string{constants.TypeIPv4},
			}
			customFns[constants.FuncGetNetlasDomainsByDomain] = schema.FunctionCapabilities{
				Limit:      1,
				DelayMs:    0,
				InputTypes: []string{constants.TypeDomain},
			}
		}
	}

	return schema.ModuleCapabilities{
		CustomFunctions: customFns,
	}, nil
}

func (m *netlasModule) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	execs := make([]schema.ModuleExecution, 0, len(data.Functions))
	gen := modutil.NewLocalIDGenerator()

	m.handlePreflightAPI()

	for _, fn := range data.Functions {
		switch fn {
		case constants.FuncGetNetlasDomain:
			if m.apiKey != "" {
				execs = append(execs, m.getNetlasDomain(data.Target, fn, gen))
				continue
			}
		case constants.FuncGetNetlasIP:
			if m.apiKey != "" {
				execs = append(execs, m.getNetlasIP(data.Target, fn, gen))
				continue
			}
		case constants.FuncGetNetlasDomainsByIP, constants.FuncGetNetlasDomainsByDomain:
			if m.apiKey != "" && resolver.NetlasLimitPerOneDownload > 0 {
				execs = append(execs, m.getNetlasDomainsByQuery(data.Target, fn, gen))
				continue
			}
		}

		exec := modutil.NewExecution(fn)
		errMsg := "unsupported function or no api key: " + fn
		exec.Error = &errMsg
		execs = append(execs, exec)
	}

	return schema.ModuleOutput{Executions: execs}, nil
}
