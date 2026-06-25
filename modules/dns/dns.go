// Package dns provides unified, robust DNS resolution capabilities
// including Plain and DoH protocols with fallback and retry logic.
package dns

import (
	"context"
	"errors"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/preflightcheck"
	"cdua-org/ReconSR/schema"
)

var log = debuglog.New("dns")

const (
	parentTimeout  = 120 * time.Second
	domainKeyLabel = "_domainkey"
)

type handlerFunc func(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution

var handlers = map[string]handlerFunc{
	constants.FuncGetIP:         getIPData,
	constants.FuncGetCAA:        getCAAData,
	constants.FuncGetNS:         getNSData,
	constants.FuncGetSOA:        getSOAData,
	constants.FuncGetCNAME:      getCNAMEData,
	constants.FuncCheckWildcard: checkWildcard,
	constants.FuncGetDomainKey:  getDomainKeyData,
	constants.FuncGetDMARC:      getDMARCData,
	constants.FuncGetDKIM:       getDKIMData,
	constants.FuncGetMX:         getMXData,
	constants.FuncGetTXT:        getTXTData,
	constants.FuncGetSRV:        getSRVData,
	constants.FuncGetNSEC:       getNSECData,
	constants.FuncGetLOC:        getLOCData,
	constants.FuncGetHINFO:      getHINFOData,
	constants.FuncGetRP:         getRPData,
	constants.FuncGetURI:        getURIData,
	constants.FuncGetSVCB:       getSVCBData,
	constants.FuncGetSSHFP:      getSSHFPData,
	constants.FuncGetNAPTR:      getNAPTRData,
	constants.FuncGetTLSA:       getTLSAData,
	constants.FuncGetDNSKEY:     getDNSKEYData,
	constants.FuncGetDS:         getDSData,
	constants.FuncGetCERT:       getCERTData,
	constants.FuncGetHIP:        getHIPData,
	constants.FuncGetIPSECKEY:   getIPSECKEYData,
}

// trustedTaggingFuncs defines functions that prove a domain is actively configured and used.
// If these find records, the domain gets "alive". If they return NXDOMAIN, it gets "dead".
var trustedTaggingFuncs = map[string]bool{
	constants.FuncGetIP:       true,
	constants.FuncGetCNAME:    true,
	constants.FuncGetMX:       true,
	constants.FuncGetTXT:      true,
	constants.FuncGetSRV:      true,
	constants.FuncGetCAA:      true,
	constants.FuncGetCERT:     true,
	constants.FuncGetTLSA:     true,
	constants.FuncGetSSHFP:    true,
	constants.FuncGetSVCB:     true,
	constants.FuncGetURI:      true,
	constants.FuncGetNAPTR:    true,
	constants.FuncGetLOC:      true,
	constants.FuncGetHINFO:    true,
	constants.FuncGetHIP:      true,
	constants.FuncGetIPSECKEY: true,
	constants.FuncGetRP:       true,
	constants.FuncGetDKIM:     true,
	constants.FuncGetDMARC:    true,
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
	functions = append(functions, constants.FuncPreflightDNS)

	customFuncs := map[string]schema.FunctionCapabilities{
		constants.FuncGetDKIM:      {Limit: 1},
		constants.FuncGetSRV:       {Limit: 1},
		constants.FuncGetTLSA:      {Limit: 1},
		constants.FuncPreflightDNS: {},
	}

	for name := range handlers {
		c := customFuncs[name]
		if c.DelayMs == 0 {
			c.DelayMs = -1
		}
		c.RequiredTags = [][]string{{constants.TagDNSOK}}
		customFuncs[name] = c
	}

	return schema.ModuleCapabilities{
		Functions:  functions,
		InputTypes: []string{constants.TypeDomain, constants.TypeSubdomain},
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
		gen := modutil.NewLocalIDGenerator()

		if f == constants.FuncPreflightDNS {
			execution = handlePreflightDNS(ctx, data.Target, gen)
		} else if handler, ok := handlers[f]; ok {
			execution = handler(ctx, data.Target.Value, gen)
			applyOSINTTags(f, data.Target, &execution, gen)
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

func handlePreflightDNS(ctx context.Context, target schema.Entity, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncPreflightDNS)
	err := preflightCheckFunc(ctx, target.Value)
	if err != nil {
		if errors.Is(err, preflightcheck.ErrZoneBroken) {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeStatus,
				Category: constants.CategoryProperty,
				Value:    constants.StatusBrokenDNSZone,
				Tags:     []string{constants.TagDNSBad},
				LocalID:  gen.NextID(),
			}, schema.ModuleResult{
				Type:    target.Type,
				Value:   target.Value,
				Tags:    []string{constants.TagDead},
				LocalID: gen.NextID(),
			})
		} else {
			errMsg := err.Error()
			execution.Error = &errMsg
		}
	} else {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    target.Type,
			Value:   target.Value,
			Tags:    []string{constants.TagDNSOK},
			LocalID: gen.NextID(),
		})
	}
	return execution
}

func applyOSINTTags(f string, target schema.Entity, execution *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	if !trustedTaggingFuncs[f] {
		return
	}

	if len(execution.Results) > 0 {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    target.Type,
			Value:   target.Value,
			Tags:    []string{constants.TagAlive},
			LocalID: gen.NextID(),
		})
	} else if execution.Error != nil && strings.Contains(*execution.Error, "no such host") {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    target.Type,
			Value:   target.Value,
			Tags:    []string{constants.TagDead},
			LocalID: gen.NextID(),
		})
	}
}
