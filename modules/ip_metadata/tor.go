package ip_metadata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func performAQuery(target, query, queryType string) ([]string, error) {
	debug := isDebug()
	var lastErr error
	var ips []string

	for attempt := 1; attempt <= resolver.MaxRetriesIPMeta; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), resolver.Timeout)
		r := resolver.GetResolver()
		var err error
		ips, err = r.LookupHost(ctx, query)
		cancel()

		if err == nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[ip_meta-debug] %s attempt=%d target=%q records=%d\n", queryType, attempt, target, len(ips))
			}
			return ips, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "server misbehaving")) {
			if debug {
				fmt.Fprintf(os.Stderr, "[ip_meta-debug] %s attempt=%d target=%q nxdomain\n", queryType, attempt, target)
			}
			return nil, nil
		}

		lastErr = err
		if debug {
			fmt.Fprintf(os.Stderr, "[ip_meta-debug] %s attempt=%d target=%q err=%v\n", queryType, attempt, target, err)
		}
	}
	return nil, lastErr
}

func getTorData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_tor",
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
		{".dnsel.torproject.org", "DNSBL Check (torproject.org)"},
		{".torexit.dan.me.uk", "DNSBL Check (dan.me.uk)"},
	}

	var isTor bool
	var detectedContext string
	var lastErr error

	for _, zone := range zones {
		query := rev + zone.suffix
		ips, lookupErr := performAQuery(target, query, "get_tor")

		if lookupErr != nil {
			lastErr = lookupErr
			continue
		}

		if slices.Contains(ips, "127.0.0.2") || slices.Contains(ips, "127.0.0.100") {
			isTor = true
			detectedContext = zone.tag
			break
		}
	}

	if !isTor && lastErr != nil {
		errMsg := "tor lookup failed after retries: " + lastErr.Error()
		execution.Error = &errMsg
		return execution
	}

	if isTor {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "tag",
			Value:   "tor_exit",
			Context: detectedContext,
		})
		execution.RawData = "127.0.0.2"
	}

	return execution
}
