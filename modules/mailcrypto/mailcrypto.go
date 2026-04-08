// Package mailcrypto manages the automated discovery of email cryptographic records
// such as OPENPGPKEY and SMIMEA, mapping generic aliases to deterministic hashes.
package mailcrypto

import (
	"strings"

	"cdua-org/ReconSR/schema"
)

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

// Name provides the dispatcher routing identifier.
func (m *module) Name() string {
	return "mailcrypto"
}

// Capabilities declares the module's contract (inputs and functions).
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_openpgpkey", "get_smimea"},
		InputTypes: []string{"domain", "subdomain", "email"},
	}, nil
}

// Exec manages the router logic, distinguishing targeted vs wide searches.
func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	// The system validator provided either a pure domain or an email.
	// We extract local parts based on that.
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

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case "get_openpgpkey":
			execution = getOPENPGPKEYData(localParts, domain)
		case "get_smimea":
			execution = getSMIMEAData(localParts, domain)
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
