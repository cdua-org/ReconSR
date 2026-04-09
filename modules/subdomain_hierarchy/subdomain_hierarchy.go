// Package subdomain_hierarchy provides hierarchical decomposition of subdomains.
package subdomain_hierarchy

import (
	"cdua-org/ReconSR/schema"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// HandleData decomposes the target subdomain into its constituent hierarchical levels.
func HandleData(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		execution := schema.ModuleExecution{
			Function: f,
			Results:  []schema.ModuleResult{},
		}

		switch f {
		case "decompose":
			target := data.Target.Value
			org, err := publicsuffix.EffectiveTLDPlusOne(target)
			if err != nil {
				errMsg := err.Error()
				execution.Error = &errMsg
				execution.RawData = "decompose failed for " + target
				break
			}

			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:    "domain",
				Value:   org,
				Context: "Organizational domain",
			})

			if target != org {
				parts := strings.Split(target, ".")
				orgParts := strings.Split(org, ".")

				for i := len(parts) - len(orgParts) - 1; i > 0; i-- {
					sub := strings.Join(parts[i:], ".")
					if sub != target && sub != org {
						execution.Results = append(execution.Results, schema.ModuleResult{
							Type:    "subdomain",
							Value:   sub,
							Context: "Parent subdomain",
							Applied: true,
						})
					}
				}
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

// GetCapabilities returns the functions and input types supported by this module.
func GetCapabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"decompose"},
		InputTypes: []string{"subdomain"},
	}, nil
}
