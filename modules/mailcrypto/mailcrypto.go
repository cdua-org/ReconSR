// Package mailcrypto manages the automated discovery of email cryptographic records
// such as OPENPGPKEY and SMIMEA, mapping generic aliases to deterministic hashes.
package mailcrypto

import (
	"context"
	"errors"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/preflightcheck"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	hashPrefixOpenPGPKey = "._openpgpkey."
	hashPrefixSMIMEA     = "._smimecert."
	ctxOpenPGPKey        = "OPENPGPKEY"
	ctxSMIMEA            = "SMIMEA"
)

var dbg = debuglog.New("mailcrypto")

var resolveRecord = resolver.ResolveRecord

// CommonEmailLocalParts are standard infrastructure email aliases used for discovery.
var CommonEmailLocalParts = []string{
	"admin", "administrator", "postmaster", "hostmaster", "security",
	"webmaster", "info", "it", "support", "sales", "contact",
	"billing", "noc", "abuse", "hello",
}

type module struct{}

// New instantiates the mailcrypto module for dispatcher registration.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "mailcrypto"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	var inputTypes []string
	if resolver.DisableMailcryptoBruteForce {
		inputTypes = []string{constants.TypeEmail}
	} else {
		inputTypes = []string{constants.TypeDomain, constants.TypeSubdomain, constants.TypeEmail}
	}

	return schema.ModuleCapabilities{
		Functions:  []string{constants.FuncGetOpenpgpkey, constants.FuncGetSmimea, constants.FuncPreflightDNS},
		InputTypes: inputTypes,
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   5,
			DelayMs: 200,
			Meta: map[string]any{
				"timeout_override": 300,
			},
		},
		CustomFunctions: map[string]schema.FunctionCapabilities{
			constants.FuncPreflightDNS: {},
			constants.FuncGetOpenpgpkey: {
				RequiredTags: [][]string{{constants.TagDNSOK}},
			},
			constants.FuncGetSmimea: {
				RequiredTags: [][]string{{constants.TagDNSOK}},
			},
		},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	var localParts []string
	var domain string

	if strings.Contains(data.Target.Value, "@") {
		parts := strings.SplitN(data.Target.Value, "@", 2)
		localParts = []string{parts[0]}
		domain = parts[1]
	} else {
		localParts = CommonEmailLocalParts
		domain = data.Target.Value
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case constants.FuncPreflightDNS:
			execution = handlePreflightDNS(ctx, domain, data.Target)
		case constants.FuncGetOpenpgpkey:
			execution = getOPENPGPKEYData(localParts, domain)
		case constants.FuncGetSmimea:
			execution = getSMIMEAData(localParts, domain)
		default:
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

func handlePreflightDNS(ctx context.Context, domain string, target schema.Entity) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncPreflightDNS)
	gen := modutil.NewLocalIDGenerator()
	dbg.Printf("%s target=%q domain=%q", constants.FuncPreflightDNS, target.Value, domain)
	err := preflightcheck.PreFlightCheck(ctx, domain)
	if err != nil {
		if errors.Is(err, preflightcheck.ErrZoneBroken) {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeStatus,
				Category: constants.CategoryProperty,
				Value:    constants.StatusBrokenDNSZone,
				Tags:     []string{constants.TagDNSBad},
				LocalID:  gen.NextID(),
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
