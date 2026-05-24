// Package haveibeenpwned provides integration with the Have I Been Pwned API.
package haveibeenpwned

import (
	"context"
	"fmt"
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

var dlog = debuglog.New("haveibeenpwned")

type module struct {
	lastReqTime time.Time
	apiKey      string
	mu          sync.Mutex
	demoFired   atomic.Bool
}

func (m *module) waitRateLimit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	elapsed := time.Since(m.lastReqTime)
	delay := time.Duration(resolver.HaveIBeenPwnedDelayMs) * time.Millisecond
	if elapsed < delay {
		time.Sleep(delay - elapsed)
	}
	m.lastReqTime = time.Now()
}

// New instantiates the module for registration.
func New() schema.Module {
	return &module{
		apiKey: apiconfig.GetKey("HaveIBeenPwned"),
	}
}

func (m *module) Name() string { return "haveibeenpwned" }

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	if m.apiKey == "" {
		return schema.ModuleCapabilities{}, nil
	}

	return schema.ModuleCapabilities{
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:      15,
			DelayMs:    65,
			InputTypes: []string{constants.TypeEmail},
		},
		Functions: []string{constants.FuncGetEmailBreaches},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))
	ctx := context.Background()

	for _, f := range data.Functions {
		switch f {
		case constants.FuncGetEmailBreaches:
			if m.apiKey != "" {
				executions = append(executions, m.getEmailBreaches(ctx, data.Target.Value))
			}
		default:
			exec := modutil.NewExecution(f)
			modutil.SetError(&exec, "unsupported function: %v", fmt.Errorf("%s", f))
			executions = append(executions, exec)
		}
	}

	return schema.ModuleOutput{Executions: executions}, nil
}
