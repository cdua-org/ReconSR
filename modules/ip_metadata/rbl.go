package ip_metadata

import (
	"fmt"
	"strings"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getRBLData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_rbl",
		Results:  []schema.ModuleResult{},
	}

	rev, _, err := resolver.ReverseIP(target)
	if err != nil {
		errMsg := "invalid ip address format: " + target
		execution.Error = &errMsg
		return execution
	}

	zones := []struct {
		suffix string
		tag    string
	}{
		{".zen.spamhaus.org", "DNSBL Check (spamhaus.org)"},
		{".b.barracudacentral.org", "DNSBL Check (barracudacentral.org)"},
		{".bl.spamcop.net", "DNSBL Check (spamcop.net)"},
	}

	var isListed bool
	var detectedContext string
	var lastErr error
	var rawData []string

	for _, zone := range zones {
		query := rev + zone.suffix
		ips, lookupErr := performAQuery(target, query, "get_rbl")

		if lookupErr != nil {
			lastErr = lookupErr
			continue
		}

		isHit := false
		isBlockedByProvider := false

		for _, ip := range ips {
			// Spamhaus and others return 127.255.255.254/255 when the public DNS resolver (like 8.8.8.8)
			// is blocked due to query volume. We must treat this as a failure and fallback to the next zone,
			// rather than falsely flagging the target IP as a spammer.
			if ip == "127.255.255.254" || ip == "127.255.255.255" {
				isBlockedByProvider = true
				break
			}
			if strings.HasPrefix(ip, "127.0.0.") {
				isHit = true
				rawData = append(rawData, ip)
			}
		}

		if isBlockedByProvider {
			lastErr = fmt.Errorf("provider %s blocked public resolver", zone.suffix)
			continue
		}

		if isHit {
			isListed = true
			detectedContext = zone.tag
			break
		}
	}

	if !isListed && lastErr != nil {
		errMsg := "rbl lookup failed after retries: " + lastErr.Error()
		execution.Error = &errMsg
		return execution
	}

	if isListed {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "tag",
			Value:   "spam_botnet",
			Context: detectedContext,
		})
		if len(rawData) > 0 {
			execution.RawData = strings.Join(rawData, ", ")
		}
	}

	return execution
}
