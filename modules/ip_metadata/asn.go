package ip_metadata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func performTXTQuery(target, query, queryType string) ([]string, error) {
	var lastErr error
	var names []string

	for attempt := 1; attempt <= resolver.MaxRetriesIPMeta; attempt++ {
		err := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), resolver.Timeout)
			defer cancel()
			var lookupErr error
			names, lookupErr = plainLookupTXT(ctx, resolver.GetResolver(), query)
			if lookupErr != nil {
				return fmt.Errorf("lookup: %w", lookupErr)
			}
			return nil
		}()

		if err == nil {
			dbg.Printf("%s success target=%q stage=lookup_txt query_type=%s attempt=%d query=%q records=%d", constants.FuncGetASN, target, queryType, attempt, query, len(names))
			return names, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "server misbehaving")) {
			dbg.Printf("%s target=%q stage=lookup_txt query_type=%s attempt=%d query=%q nxdomain", constants.FuncGetASN, target, queryType, attempt, query)
			return nil, nil
		}

		lastErr = err
		dbg.Printf("%s error target=%q stage=lookup_txt query_type=%s attempt=%d query=%q err=%v", constants.FuncGetASN, target, queryType, attempt, query, err)
		if attempt < resolver.MaxRetriesIPMeta {
			httputil.SleepContext(context.Background(), resolver.RetryBaseDelay)
		}
	}
	return nil, lastErr
}

func getASNInfo(asn string) string {
	val := strings.ToUpper(asn)
	if !strings.HasPrefix(val, "AS") {
		val = "AS" + val
	}

	names, err := txtQueryFunc(val, val+".asn.cymru.com", "asn_info")
	if err != nil || len(names) == 0 {
		return ""
	}

	parts := strings.Split(names[0], "|")
	if len(parts) >= 5 {
		country := strings.TrimSpace(parts[1])
		company := strings.TrimSpace(parts[4])

		if company != "" {
			return fmt.Sprintf(" (%s, %s)", country, company)
		} else if country != "" {
			return fmt.Sprintf(" (%s)", country)
		}
	} else if len(parts) >= 2 {
		country := strings.TrimSpace(parts[1])
		if country != "" {
			return fmt.Sprintf(" (%s)", country)
		}
	}
	return ""
}

func getASNData(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetASN)
	gen := modutil.NewLocalIDGenerator()

	dbg.Printf("%s target=%q", constants.FuncGetASN, target)

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	rev, isIPv4, err := resolver.ReverseIP(target)
	if err != nil {
		dbg.Printf("%s error target=%q stage=validate_input err=%v", constants.FuncGetASN, target, err)
		errMsg := errInvalidIPFormat + target
		execution.Error = &errMsg
		return execution
	}

	originZone := "origin6.asn.cymru.com"
	if isIPv4 {
		originZone = "origin.asn.cymru.com"
	}

	originNames, originErr := txtQueryFunc(target, rev+"."+originZone, "origin")

	if originErr != nil {
		dbg.Printf("%s error target=%q stage=lookup_origin err=%v", constants.FuncGetASN, target, originErr)
		errMsg := fmt.Errorf("asn lookup failed after retries: %w", originErr).Error()
		execution.Error = &errMsg
		return execution
	}

	for _, txt := range originNames {
		if rawBuffer.Len() > 0 {
			rawBuffer.WriteString("\n")
		}
		rawBuffer.WriteString(txt)

		parts := strings.Split(txt, "|")
		if len(parts) >= 2 {
			asnPart := strings.TrimSpace(parts[0])
			prefix := strings.TrimSpace(parts[1])

			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeCIDR,
				Category: constants.CategoryNode,
				Value:    prefix,
				Context:  "BGP Prefix",
				LocalID:  gen.NextID(),
			})

			for asn := range strings.FieldsSeq(asnPart) {
				val := asn
				if !strings.HasPrefix(strings.ToUpper(val), "AS") {
					val = "AS" + val
				}

				info := getASNInfo(val)

				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:     constants.TypeASN,
					Category: constants.CategoryNode,
					Value:    val,
					Context:  "ASN Origin" + info,
					LocalID:  gen.NextID(),
				})
			}
		}
	}

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q result_count=%d", constants.FuncGetASN, target, len(execution.Results))
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetASN, target)
	}

	return execution
}
