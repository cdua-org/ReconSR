// Package hunterio provides integration with the Hunter.io API.
package hunterio

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var dlog = debuglog.New("hunterio")

type module struct {
	lastReqTime   time.Time
	apiKey        string
	preflightOnce sync.Once
	mu            sync.Mutex
	keyInvalid    bool
	quotaExceeded bool
	queryCredits  int
}

func (m *module) waitRateLimit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	elapsed := time.Since(m.lastReqTime)
	if elapsed < 120*time.Millisecond {
		time.Sleep(120*time.Millisecond - elapsed)
	}
	m.lastReqTime = time.Now()
}

// New instantiates the module for registration.
func New() schema.Module {
	return &module{
		apiKey: apiconfig.GetKey("Hunterio"),
	}
}

func (m *module) Name() string { return "hunterio" }

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	if m.apiKey == "" {
		return schema.ModuleCapabilities{}, nil
	}

	inputTypes := []string{constants.TypeDomain}
	if resolver.HunterioScanOrg {
		inputTypes = append(inputTypes, constants.TypeOrganization)
	}

	return schema.ModuleCapabilities{
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:      15,
			DelayMs:    150,
			InputTypes: inputTypes,
		},
		Functions: []string{constants.FuncGetHunterioDomainSearch},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))
	ctx := context.Background()

	for _, f := range data.Functions {
		switch f {
		case constants.FuncGetHunterioDomainSearch:
			if m.apiKey != "" {
				executions = append(executions, m.getDomainSearch(ctx, data.Target.Type, data.Target.Value))
			}
		default:
			exec := modutil.NewExecution(f)
			modutil.SetError(&exec, "unsupported function: %v", fmt.Errorf("%s", f))
			executions = append(executions, exec)
		}
	}

	return schema.ModuleOutput{Executions: executions}, nil
}
