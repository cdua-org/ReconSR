// Package shodan provides integration with Shodan APIs and InternetDB.
package shodan

import (
	"sync"
	"time"

	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

const (
	moduleName = "shodan"

	functionInternetDB      = "get_idb_shodan"
	functionShodanAPIIP     = "get_shodan_api_ip"
	functionShodanAPIDomain = "get_shodan_api_domain"

	entityTypeDomain = "domain"
	entityTypeIP     = "ip"
	entityTypeIPv4   = "ipv4"
	entityTypeIPv6   = "ipv6"

	resultCategoryNode     = "node"
	resultCategoryProperty = "property"

	resultTypeCertIssuer        = "cert_issuer"
	resultTypeCertNotAfter      = "cert_not_after"
	resultTypeCPE               = "cpe"
	resultTypeCVE               = "cve"
	resultTypeInfo              = "info"
	resultTypeLastUpdate        = "last_update"
	resultTypePort              = "port"
	resultTypeSANDomain         = "san_domain"
	resultTypeService           = "service"
	resultTypeSubdomain         = "subdomain"
	resultTypeTLSVersions       = "tls_versions"
	resultTypeWebServer         = "web_server"
	resultTypeWildcardSANDomain = "wildcard_san_domain"
)

type shodanModule struct {
	lastReqTime   time.Time
	apiKey        string
	queryCredits  int
	preflightOnce sync.Once
	mu            sync.Mutex
	keyInvalid    bool
}

// New returns a new instance of the Shodan module.
func New() schema.Module {
	return &shodanModule{
		apiKey: apiconfig.GetKey("Shodan"),
	}
}

func (m *shodanModule) Name() string {
	return moduleName
}

func (m *shodanModule) Capabilities() (schema.ModuleCapabilities, error) {
	customFns := make(map[string]schema.FunctionCapabilities, 2)

	if m.apiKey == "" {
		customFns[functionInternetDB] = getInternetDBCapabilities()
	} else {
		customFns[functionShodanAPIIP] = schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    0,
			InputTypes: []string{entityTypeIPv4, entityTypeIPv6},
		}
		customFns[functionShodanAPIDomain] = schema.FunctionCapabilities{
			Limit:      1,
			DelayMs:    0,
			InputTypes: []string{entityTypeDomain},
		}
	}

	return schema.ModuleCapabilities{
		CustomFunctions: customFns,
	}, nil
}

func (m *shodanModule) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	execs := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, fn := range data.Functions {
		switch fn {
		case functionInternetDB:
			if m.apiKey == "" {
				execs = append(execs, getInternetDB(data.Target))
				continue
			}
		case functionShodanAPIIP:
			if m.apiKey != "" {
				execs = append(execs, m.getShodanAPIIP(data.Target))
				continue
			}
		case functionShodanAPIDomain:
			if m.apiKey != "" {
				execs = append(execs, m.getShodanAPIDomain(data.Target))
				continue
			}
		}

		exec := modutil.NewExecution(fn)
		errMsg := "unsupported function: " + fn
		exec.Error = &errMsg
		execs = append(execs, exec)
	}

	return schema.ModuleOutput{Executions: execs}, nil
}
