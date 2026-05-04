package ip_metadata

import (
	"fmt"
	"strings"

	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func checkRBLZone(target, query string, rawBuffer *strings.Builder) (isHit, isBlocked bool, err error) {
	ips, lookupErr := performAQuery(target, query, "get_rbl")
	if lookupErr != nil {
		return false, false, lookupErr
	}

	for _, ip := range ips {
		if ip == "127.255.255.254" || ip == "127.255.255.255" {
			return false, true, nil
		}
		if strings.HasPrefix(ip, "127.0.0.") {
			isHit = true
			if rawBuffer.Len() > 0 {
				rawBuffer.WriteString(", ")
			}
			rawBuffer.WriteString(ip)
		}
	}

	return isHit, false, nil
}

func getRBLData(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution("get_rbl")

	dbg.Printf("getRBLData target=%q", target)

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	rev, _, err := resolver.ReverseIP(target)
	if err != nil {
		errMsg := errInvalidIPFormat + target
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

	for _, zone := range zones {
		query := rev + zone.suffix
		isHit, isBlocked, lookupErr := checkRBLZone(target, query, &rawBuffer)

		if lookupErr != nil {
			lastErr = lookupErr
			continue
		}

		if isBlocked {
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
		errMsg := fmt.Errorf("rbl lookup failed after retries: %w", lastErr).Error()
		execution.Error = &errMsg
		return execution
	}

	if isListed {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     typeTag,
			Category: "property",
			Value:    "spam_botnet",
			Context:  detectedContext,
		})
	}

	return execution
}
