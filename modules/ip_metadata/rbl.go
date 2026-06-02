package ip_metadata

import (
	"fmt"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func checkRBLZone(target, query string, rawBuffer *strings.Builder) (isHit, isBlocked bool, err error) {
	maxAttempts := max(resolver.MaxRetriesIPMeta, 1)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ips, lookupErr := aQueryFunc(target, query, constants.FuncGetRBL)
		if lookupErr != nil {
			return false, false, lookupErr
		}

		zoneHit, zoneBlocked := parseRBLZoneRecords(ips, rawBuffer)
		if zoneHit {
			return true, false, nil
		}
		if zoneBlocked {
			isBlocked = true
			dbg.Printf("%s target=%q stage=lookup_rbl attempt=%d query=%q blocked_resolver=%q", constants.FuncGetRBL, target, attempt, query, resolver.GetLastUsedPlain())
			continue
		}

		return false, false, nil
	}

	return false, isBlocked, nil
}

func parseRBLZoneRecords(ips []string, rawBuffer *strings.Builder) (isHit, isBlocked bool) {
	for _, ip := range ips {
		if ip == "127.255.255.254" || ip == "127.255.255.255" {
			return false, true
		}
	}

	for _, ip := range ips {
		if strings.HasPrefix(ip, "127.0.0.") {
			isHit = true
			if rawBuffer.Len() > 0 {
				rawBuffer.WriteString(", ")
			}
			rawBuffer.WriteString(ip)
		}
	}

	return isHit, false
}

func getRBLData(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetRBL)
	gen := modutil.NewLocalIDGenerator()

	dbg.Printf("%s target=%q", constants.FuncGetRBL, target)

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	rev, _, err := resolver.ReverseIP(target)
	if err != nil {
		dbg.Printf("%s error target=%q stage=validate_input err=%v", constants.FuncGetRBL, target, err)
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
			dbg.Printf("%s target=%q stage=lookup_rbl provider=%q skipped=true reason=blocked_public_resolver", constants.FuncGetRBL, target, zone.suffix)
			continue
		}

		if isHit {
			isListed = true
			detectedContext = zone.tag
			break
		}
	}

	if !isListed && lastErr != nil {
		dbg.Printf("%s error target=%q stage=lookup_rbl err=%v", constants.FuncGetRBL, target, lastErr)
		errMsg := fmt.Errorf("rbl lookup failed after retries: %w", lastErr).Error()
		execution.Error = &errMsg
		return execution
	}

	if isListed {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    constants.TagSpamBotnet,
			Context:  detectedContext,
			LocalID:  gen.NextID(),
		})
		dbg.Printf("%s success target=%q context=%q", constants.FuncGetRBL, target, detectedContext)
	} else {
		dbg.Printf("%s target=%q listed=false", constants.FuncGetRBL, target)
	}

	return execution
}
