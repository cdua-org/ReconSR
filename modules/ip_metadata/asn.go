package ip_metadata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func performTXTQuery(target, query, queryType string) ([]string, error) {
	debug := isDebug()
	var lastErr error
	var names []string

	for attempt := 1; attempt <= resolver.MaxRetriesIPMeta; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), resolver.Timeout)
		r := resolver.GetResolver()
		var err error
		names, err = r.LookupTXT(ctx, query)
		cancel()

		if err == nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[ip_meta-debug] get_asn %s attempt=%d target=%q records=%d\n", queryType, attempt, target, len(names))
			}
			return names, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "server misbehaving")) {
			if debug {
				fmt.Fprintf(os.Stderr, "[ip_meta-debug] get_asn %s attempt=%d target=%q nxdomain\n", queryType, attempt, target)
			}
			return nil, nil
		}

		lastErr = err
		if debug {
			fmt.Fprintf(os.Stderr, "[ip_meta-debug] get_asn %s attempt=%d target=%q err=%v\n", queryType, attempt, target, err)
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

func getASNData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_asn",
		Results:  []schema.ModuleResult{},
	}

	rev, isIPv4, err := resolver.ReverseIP(target)
	if err != nil {
		errMsg := "invalid ip address format: " + target
		execution.Error = &errMsg
		return execution
	}

	originZone := "origin6.asn.cymru.com"
	if isIPv4 {
		originZone = "origin.asn.cymru.com"
	}

	originNames, originErr := performTXTQuery(target, rev+"."+originZone, "origin")

	if originErr != nil {
		errMsg := "asn lookup failed after retries: " + originErr.Error()
		execution.Error = &errMsg
		return execution
	}

	var rawData []string

	for _, txt := range originNames {
		rawData = append(rawData, txt)
		parts := strings.Split(txt, "|")
		if len(parts) >= 2 {
			asnPart := strings.TrimSpace(parts[0])
			prefix := strings.TrimSpace(parts[1])

			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:    "cidr",
				Value:   prefix,
				Context: "BGP Prefix",
			})

			for asn := range strings.FieldsSeq(asnPart) {
				val := asn
				if !strings.HasPrefix(strings.ToUpper(val), "AS") {
					val = "AS" + val
				}

				info := getASNInfo(val)

				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "asn",
					Value:   val,
					Context: "ASN Origin" + info,
				})
			}
		}
	}

	if len(rawData) > 0 {
		execution.RawData = strings.Join(rawData, "\n")
	}

	return execution
}
