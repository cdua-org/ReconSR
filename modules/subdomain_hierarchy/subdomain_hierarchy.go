// Package subdomain_hierarchy provides hierarchical decomposition of subdomains.
package subdomain_hierarchy

import (
	"cdua-org/ReconSR/schema"
	"strings"

	"golang.org/x/net/publicsuffix"
)

const (
	funcDecompose = "decompose"
	typeSubdomain = "subdomain"
)

type module struct{}

// New instantiates the subdomain_hierarchy module.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "subdomain_hierarchy"
}

// Exec decomposes the target subdomain into its constituent hierarchical levels.
func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		execution := schema.ModuleExecution{
			Function: f,
			Results:  []schema.ModuleResult{},
		}

		switch f {
		case funcDecompose:
			target := data.Target.Value
			targetType := data.Target.Type
			org, err := publicsuffix.EffectiveTLDPlusOne(target)
			if err != nil {
				errMsg := err.Error()
				execution.Error = &errMsg
				execution.RawData = "decompose failed for " + target
				break
			}

			parts := strings.Split(target, ".")
			orgParts := strings.Split(org, ".")

			currentSource := &schema.EntityRef{
				Type:  targetType,
				Value: target,
			}

			if len(parts) > len(orgParts) {
				for i := 1; i <= len(parts)-len(orgParts); i++ {
					val := strings.Join(parts[i:], ".")
					resType := typeSubdomain
					applied := true

					if val == org {
						resType = "domain"
						applied = false
					}

					execution.Results = append(execution.Results, schema.ModuleResult{
						Type:    resType,
						Value:   val,
						Applied: applied,
						Source:  currentSource,
					})

					currentSource = &schema.EntityRef{
						Type:  resType,
						Value: val,
					}
				}
			} else {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:   "domain",
					Value:  org,
					Source: currentSource,
				})
			}
		default:
			errMsg := "unsupported function: " + f
			execution.Error = &errMsg
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

// Capabilities returns the functions and input types supported by this module.
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		CustomFunctions: map[string]schema.FunctionCapabilities{
			funcDecompose: {
				Limit:      1000,
				DelayMs:    0,
				InputTypes: []string{typeSubdomain},
			},
		},
	}, nil
}
