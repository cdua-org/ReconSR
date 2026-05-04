// Package dns provides unified, robust DNS resolution capabilities
// including Plain and DoH protocols with fallback and retry logic.
package dns

import (
	"context"
	"errors"
	"time"

	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/preflightcheck"
	"cdua-org/ReconSR/schema"
)

var log = debuglog.New("dns")

const parentTimeout = 120 * time.Second

type handlerFunc func(ctx context.Context, target string) schema.ModuleExecution

var handlers = map[string]handlerFunc{
	"get_ip":         getIPData,
	"get_caa":        getCAAData,
	"get_ns":         getNSData,
	"get_soa":        getSOAData,
	"get_cname":      getCNAMEData,
	"check_wildcard": checkWildcard,
	"get_domainkey":  getDomainKeyData,
	"get_dmarc":      getDMARCData,
	"get_dkim":       getDKIMData,
	"get_mx":         getMXData,
	"get_txt":        getTXTData,
	"get_srv":        getSRVData,
	"get_nsec":       getNSECData,
	"get_loc":        getLOCData,
	"get_hinfo":      getHINFOData,
	"get_rp":         getRPData,
	"get_uri":        getURIData,
	"get_svcb":       getSVCBData,
	"get_sshfp":      getSSHFPData,
	"get_naptr":      getNAPTRData,
	"get_tlsa":       getTLSAData,
	"get_dnskey":     getDNSKEYData,
	"get_ds":         getDSData,
	"get_cert":       getCERTData,
	"get_hip":        getHIPData,
	"get_ipseckey":   getIPSECKEYData,
}

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "dns"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	functions := make([]string, 0, len(handlers)+1)
	for name := range handlers {
		functions = append(functions, name)
	}
	functions = append(functions, "preflight_dns")

	customFuncs := map[string]schema.FunctionCapabilities{
		"get_dkim":      {Limit: 1},
		"get_srv":       {Limit: 1},
		"get_tlsa":      {Limit: 1},
		"preflight_dns": {},
	}

	for name := range handlers {
		c := customFuncs[name]
		c.RequiredTags = [][]string{{"dns_ok"}}
		customFuncs[name] = c
	}

	return schema.ModuleCapabilities{
		Functions:  functions,
		InputTypes: []string{"domain", "subdomain"},
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   2,
			DelayMs: 50,
		},
		CustomFunctions: customFuncs,
	}, nil
}

// Exec acts as the stateless execution pipeline for incoming requests,
// routing each requested function to the corresponding DNS handler.
func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), parentTimeout)
	defer cancel()

	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "preflight_dns" {
			execution = handlePreflightDNS(ctx, data.Target)
		} else if handler, ok := handlers[f]; ok {
			execution = handler(ctx, data.Target.Value)
		} else {
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

func handlePreflightDNS(ctx context.Context, target schema.Entity) schema.ModuleExecution {
	execution := modutil.NewExecution("preflight_dns")
	err := preflightcheck.PreFlightCheck(ctx, target.Value)
	if err != nil {
		if errors.Is(err, preflightcheck.ErrZoneBroken) {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     "status",
				Category: "property",
				Value:    "Broken DNS Zone",
				Tags:     []string{"dns_bad"},
			})
		} else {
			errMsg := err.Error()
			execution.Error = &errMsg
		}
	} else {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:  target.Type,
			Value: target.Value,
			Tags:  []string{"dns_ok"},
		})
	}
	return execution
}
