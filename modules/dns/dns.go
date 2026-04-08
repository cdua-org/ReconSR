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
		Functions:  []string{"get_ip", "get_caa", "get_ns", "get_soa", "get_cname", "check_wildcard", "get_domainkey", "get_dmarc", "get_dkim", "get_mx", "get_txt", "get_srv", "get_nsec", "get_loc", "get_hinfo", "get_rp", "get_uri", "get_svcb", "get_sshfp", "get_naptr", "get_tlsa"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

// Exec acts as the stateless execution pipeline for incoming requests,
// isolating the core routing from the underlying network extraction logic.
//
//nolint:gocyclo // router switch naturally grows linearly
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
		case "get_dkim":
			execution = getDKIMData(data.Target.Value)
		case "get_mx":
			execution = getMXData(data.Target.Value)
		case "get_txt":
			execution = getTXTData(data.Target.Value)
		case "get_srv":
			execution = getSRVData(data.Target.Value)
		case "get_nsec":
			execution = getNSECData(data.Target.Value)
		case "get_loc":
			execution = getLOCData(data.Target.Value)
		case "get_hinfo":
			execution = getHINFOData(data.Target.Value)
		case "get_rp":
			execution = getRPData(data.Target.Value)
		case "get_uri":
			execution = getURIData(data.Target.Value)
		case "get_svcb":
			execution = getSVCBData(data.Target.Value)
		case "get_sshfp":
			execution = getSSHFPData(data.Target.Value)
		case "get_naptr":
			execution = getNAPTRData(data.Target.Value)
		case "get_tlsa":
			execution = getTLSAData(data.Target.Value)
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
