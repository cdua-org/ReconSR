package leakix

import (
	"sync"
	"time"

	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
	"sync/atomic"
)

const (
	moduleName    = "leakix"
	demoIndicator = "demo-api-key"
	msgInvalidKey = "API key invalid (HTTP 401)"
)

var dbg = debuglog.New(moduleName)

type leakixModule struct {
	lastReqTime        time.Time
	apiKey             string
	mu                 sync.Mutex
	blockedStatus      atomic.Int32
	demoDomainFired    atomic.Bool
	demoIPFired        atomic.Bool
	demoSubdomainFired atomic.Bool
}

// New returns a new instance of the LeakIX module.
func New() schema.Module {
	return &leakixModule{
		apiKey: apiconfig.GetKey("LeakIX"),
	}
}

func (m *leakixModule) Name() string {
	return moduleName
}

func (m *leakixModule) Capabilities() (schema.ModuleCapabilities, error) {
	customFns := make(map[string]schema.FunctionCapabilities)

	if m.apiKey != "" {
		domainTypes := []string{constants.TypeDomain}
		ipTypes := []string{constants.TypeIPv4, constants.TypeIPv6}
		subdomainTypes := []string{constants.TypeDomain}

		customFns[constants.FuncGetLeakIXDomain] = schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    0,
			InputTypes: domainTypes,
		}
		customFns[constants.FuncGetLeakIXIP] = schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    0,
			InputTypes: ipTypes,
		}
		customFns[constants.FuncGetLeakIXSubdomains] = schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    0,
			InputTypes: subdomainTypes,
		}
	}

	return schema.ModuleCapabilities{
		CustomFunctions: customFns,
	}, nil
}

func (m *leakixModule) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	execs := make([]schema.ModuleExecution, 0, len(data.Functions))

	gen := modutil.NewLocalIDGenerator()

	for _, fn := range data.Functions {
		switch fn {
		case constants.FuncGetLeakIXDomain:
			if m.apiKey != "" {
				execs = append(execs, m.getLeakixDomain(data.Target, fn, gen))
				continue
			}
		case constants.FuncGetLeakIXIP:
			if m.apiKey != "" {
				execs = append(execs, m.getLeakixIP(data.Target, fn, gen))
				continue
			}
		case constants.FuncGetLeakIXSubdomains:
			if m.apiKey != "" {
				execs = append(execs, m.getLeakixSubdomains(data.Target, fn, gen))
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
