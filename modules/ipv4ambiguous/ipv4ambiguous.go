// Package ipv4ambiguous resolves ambiguous IPv4 addresses containing leading zeros
// into standard decimal and POSIX formats to identify both misconfigurations
// and potential obfuscation attempts.
package ipv4ambiguous

import (
	"cdua-org/ReconSR/schema"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type module struct{}

func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "ipv4ambiguous"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"parse_ambiguous"},
		InputTypes: []string{"ipv4_ambiguous"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	var executions []schema.ModuleExecution

	for _, f := range data.Functions {
		execution := schema.ModuleExecution{
			Function: f,
			Results:  []schema.ModuleResult{},
		}

		switch f {
		case "parse_ambiguous":
			execution.Results = extractIPs(data.Target.Value)
		default:
			errMsg := fmt.Sprintf("unsupported function: %s", f)
			execution.Error = &errMsg
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

func extractIPs(val string) []schema.ModuleResult {
	parts := strings.Split(val, ".")
	var results []schema.ModuleResult

	decimalParts := make([]string, len(parts))
	for i, p := range parts {
		trimmed := strings.TrimLeft(p, "0")
		if trimmed == "" {
			trimmed = "0"
		}
		decimalParts[i] = trimmed
	}

	decStr := strings.Join(decimalParts, ".")
	if net.ParseIP(decStr) != nil {
		results = append(results, schema.ModuleResult{
			Type:    "ip",
			Value:   decStr,
			Context: "Normalized",
		})
	}

	posixParts := make([]string, 0, len(parts))
	posixValid := true
	for _, p := range parts {
		parsed, err := strconv.ParseInt(p, 0, 64)
		if err != nil || parsed < 0 || parsed > 255 {
			posixValid = false
			break
		}
		posixParts = append(posixParts, strconv.FormatInt(parsed, 10))
	}

	if posixValid {
		posixStr := strings.Join(posixParts, ".")
		if posixStr != decStr && net.ParseIP(posixStr) != nil {
			results = append(results, schema.ModuleResult{
				Type:    "ip",
				Value:   posixStr,
				Context: "Deobfuscated",
			})
		}
	}

	if results == nil {
		return []schema.ModuleResult{}
	}
	return results
}
