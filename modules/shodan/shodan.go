// Package shodan provides integration with Shodan APIs.
package shodan

import (
	"cdua-org/ReconSR/schema"
)

const moduleName = "shodan"

type shodanModule struct{}

// New returns a new instance of the Shodan module.
func New() schema.Module {
	return &shodanModule{}
}

func (m *shodanModule) Name() string {
	return moduleName
}

func (m *shodanModule) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		CustomFunctions: map[string]schema.FunctionCapabilities{
			"get_idb_shodan": getInternetDBCapabilities(),
		},
	}, nil
}

func (m *shodanModule) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	var execs []schema.ModuleExecution

	for _, fn := range data.Functions {
		if fn == "get_idb_shodan" {
			execs = append(execs, getInternetDB(data.Target))
		}
	}

	return schema.ModuleOutput{Executions: execs}, nil
}
