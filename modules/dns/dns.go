// Package dns provides unified, robust DNS resolution capabilities
// including Plain and DoH protocols with fallback and retry logic.
package dns

import (
	"cdua-org/ReconSR/schema"
)

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

// Name provides the unique identifier used by the dispatcher for routing.
func (m *module) Name() string {
	return "dns"
}

// Capabilities declares the module's contract (inputs and functions) to the system core.
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_ip", "get_caa", "get_ns", "get_soa", "get_cname", "check_wildcard", "get_domainkey", "get_dmarc"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

// Exec acts as the stateless execution pipeline for incoming requests,
// isolating the core routing from the underlying network extraction logic.
func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case "get_ip":
			execution = getIPData(data.Target.Value)
		case "get_caa":
			execution = getCAAData(data.Target.Value)
		case "get_ns":
			execution = getNSData(data.Target.Value)
		case "get_soa":
			execution = getSOAData(data.Target.Value)
		case "get_cname":
			execution = getCNAMEData(data.Target.Value)
		case "check_wildcard":
			execution = checkWildcard(data.Target.Value)
		case "get_domainkey":
			execution = getDomainKeyData(data.Target.Value)
		case "get_dmarc":
			execution = getDMARCData(data.Target.Value)
		default:
			errMsg := "unsupported function: " + f
			execution = schema.ModuleExecution{
				Function: f,
				Error:    &errMsg,
			}
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}
