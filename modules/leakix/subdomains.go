package leakix

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dateutil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

func (m *leakixModule) getLeakixSubdomains(target schema.Entity, funcName string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(funcName)

	if blocked := m.blockedStatus.Load(); blocked > 0 {
		var msg string
		if blocked == http.StatusUnauthorized {
			msg = msgInvalidKey
		} else {
			msg = fmt.Sprintf("API access blocked (HTTP %d)", blocked)
		}
		dbg.Printf("%s error target=%q state=blocked status=%d", funcName, target.Value, blocked)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    msg,
			LocalID:  gen.NextID(),
		})
		return exec
	}

	if m.apiKey == demoIndicator {
		return m.getLeakixSubdomainsDemo(&exec, target, gen)
	}

	if target.Value == "" {
		modutil.SetError(&exec, "get subdomains: %v", errors.New("empty target"))
		return exec
	}

	targetValue := target.Value
	u := fmt.Sprintf("%s/api/subdomains/%s", leakixAPIBaseURL, url.PathEscape(targetValue))
	dbg.Printf("%s target=%q", constants.FuncGetLeakIXSubdomains, targetValue)

	rawBody, status, ok := m.doAPIRequest(&exec, u, targetValue)
	dbg.Printf("%s request_complete target=%q body_present=%t status=%d", constants.FuncGetLeakIXSubdomains, targetValue, rawBody != nil, status)

	if !ok || rawBody == nil {
		return exec
	}

	if status != 200 {
		modutil.SetError(&exec, "get subdomains: %v", fmt.Errorf("api returned non-200 status: %d", status))
		return exec
	}

	modutil.SetRawFromBytes(&exec, rawBody)

	var resp []SubdomainResponse
	if err := json.Unmarshal(rawBody, &resp); err != nil {
		modutil.SetError(&exec, "parse json: %v", err)
		return exec
	}

	formatLeakixSubdomains(&exec, resp, target.Value, gen)
	dbg.Printf("%s success target=%q results=%d", constants.FuncGetLeakIXSubdomains, targetValue, len(exec.Results))

	return exec
}

func formatLeakixSubdomains(exec *schema.ModuleExecution, resp []SubdomainResponse, target string, gen *modutil.LocalIDGenerator) {
	for _, sub := range resp {
		if sub.Subdomain == "" {
			continue
		}

		val, err := validator.Validate(constants.TypeDomain, sub.Subdomain)
		if err != nil {
			continue
		}
		sub.Subdomain = val.Value
		nodeType := val.Type

		subID := gen.NextID()

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       nodeType,
			Category:   constants.CategoryNode,
			Value:      sub.Subdomain,
			LocalID:    subID,
			Applied:    true,
			OutOfScope: orgdomain.IsOutOfScope(sub.Subdomain, target),
			Tags:       []string{constants.TagPDNS},
		})

		if sub.LastSeen != "" {
			lastSeen := sub.LastSeen
			if day, ok := dateutil.NormalizeDay(lastSeen); ok {
				lastSeen = day
			}
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeDate,
				Category: constants.CategoryProperty,
				Value:    "Last Seen: " + lastSeen,
				Source: &schema.EntityRef{
					Type:    nodeType,
					Value:   sub.Subdomain,
					LocalID: subID,
				},
			})
		}

		if sub.DistinctIPs > 0 {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeInfo,
				Category: constants.CategoryProperty,
				Value:    fmt.Sprintf("Distinct IPs: %d", sub.DistinctIPs),
				Source: &schema.EntityRef{
					Type:    nodeType,
					Value:   sub.Subdomain,
					LocalID: subID,
				},
			})
		}
	}
}
