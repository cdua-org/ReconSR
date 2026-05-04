package ip_metadata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func performAQuery(target, query, queryType string) ([]string, error) {
	var lastErr error
	var ips []string

	for attempt := 1; attempt <= resolver.MaxRetriesIPMeta; attempt++ {
		err := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), resolver.Timeout)
			defer cancel()
			var lookupErr error
			ips, lookupErr = resolver.GetResolver().LookupHost(ctx, query)
			if lookupErr != nil {
				return fmt.Errorf("lookup: %w", lookupErr)
			}
			return nil
		}()

		if err == nil {
			dbg.Printf("%s attempt=%d target=%q records=%d", queryType, attempt, target, len(ips))
			return ips, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "server misbehaving")) {
			dbg.Printf("%s attempt=%d target=%q nxdomain", queryType, attempt, target)
			return nil, nil
		}

		lastErr = err
		dbg.Printf("%s attempt=%d target=%q err=%v", queryType, attempt, target, err)
		if attempt < resolver.MaxRetriesIPMeta {
			httputil.SleepContext(context.Background(), resolver.RetryBaseDelay)
		}
	}
	return nil, lastErr
}

func getTorData(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution("get_tor")

	dbg.Printf("getTorData target=%q", target)

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
		errMsg := fmt.Errorf("tor lookup failed after retries: %w", lastErr).Error()
		execution.Error = &errMsg
		return execution
	}

	if isTor {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     typeTag,
			Category: "property",
			Value:    "tor_exit",
			Context:  detectedContext,
		})
		execution.RawData = "127.0.0.2"
	}

	return execution
}
