// Package mailcrypto manages the automated discovery of email cryptographic records
// such as OPENPGPKEY and SMIMEA, mapping generic aliases to deterministic hashes.
package mailcrypto

import (
	"context"
	"errors"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/preflightcheck"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var dbg = debuglog.New("mailcrypto")

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
		inputTypes = []string{"email"}
	} else {
		inputTypes = []string{"domain", "subdomain", "email"}
	}

	return schema.ModuleCapabilities{
		Functions:  []string{"get_openpgpkey", "get_smimea", "preflight_dns"},
		InputTypes: inputTypes,
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   5,
			DelayMs: 200,
			Meta: map[string]any{
				"timeout_override": 300,
			},
		},
		CustomFunctions: map[string]schema.FunctionCapabilities{
			"preflight_dns": {},
			"get_openpgpkey": {
				RequiredTags: [][]string{{"dns_ok"}},
			},
			"get_smimea": {
				RequiredTags: [][]string{{"dns_ok"}},
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
		case "preflight_dns":
			execution = handlePreflightDNS(ctx, domain, data.Target)
		case "get_openpgpkey":
			execution = getOPENPGPKEYData(localParts, domain)
		case "get_smimea":
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
	execution := modutil.NewExecution("preflight_dns")
	dbg.Printf("preflight_dns target=%q domain=%q", target.Value, domain)
	err := preflightcheck.PreFlightCheck(ctx, domain)
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
