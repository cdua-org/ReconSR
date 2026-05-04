// Package ip_metadata provides IP and ASN intelligence gathering.
package ip_metadata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

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
			names, lookupErr = resolver.GetResolver().LookupTXT(ctx, query)
			if lookupErr != nil {
				return fmt.Errorf("lookup: %w", lookupErr)
			}
			return nil
		}()

		if err == nil {
			dbg.Printf("get_asn %s attempt=%d target=%q records=%d", queryType, attempt, target, len(names))
			return names, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "server misbehaving")) {
			dbg.Printf("get_asn %s attempt=%d target=%q nxdomain", queryType, attempt, target)
			return nil, nil
		}

		lastErr = err
		dbg.Printf("get_asn %s attempt=%d target=%q err=%v", queryType, attempt, target, err)
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

	names, err := performTXTQuery(val, val+".asn.cymru.com", "asn_info")
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
	execution = modutil.NewExecution("get_asn")

	dbg.Printf("getASNData target=%q", target)

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	rev, isIPv4, err := resolver.ReverseIP(target)
	if err != nil {
		errMsg := errInvalidIPFormat + target
		execution.Error = &errMsg
		return execution
	}

	originZone := "origin6.asn.cymru.com"
	if isIPv4 {
		originZone = "origin.asn.cymru.com"
	}

	originNames, originErr := performTXTQuery(target, rev+"."+originZone, "origin")

	if originErr != nil {
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
				Type:     typeCIDR,
				Category: "property",
				Value:    prefix,
				Context:  "BGP Prefix",
			})

			for asn := range strings.FieldsSeq(asnPart) {
				val := asn
				if !strings.HasPrefix(strings.ToUpper(val), "AS") {
					val = "AS" + val
				}

				info := getASNInfo(val)

				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:     typeASN,
					Category: "node",
					Value:    val,
					Context:  "ASN Origin" + info,
				})
			}
		}
	}

	return execution
}
