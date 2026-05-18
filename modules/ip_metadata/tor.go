package ip_metadata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	dnsblPositive    = "127.0.0.2"
	dnsblPositiveAlt = "127.0.0.100"
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
			dbg.Printf("%s success target=%q stage=lookup_host attempt=%d query=%q records=%d", queryType, target, attempt, query, len(ips))
			return ips, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "server misbehaving")) {
			dbg.Printf("%s target=%q stage=lookup_host attempt=%d query=%q nxdomain", queryType, target, attempt, query)
			return nil, nil
		}

		lastErr = err
		dbg.Printf("%s error target=%q stage=lookup_host attempt=%d query=%q err=%v", queryType, target, attempt, query, err)
		if attempt < resolver.MaxRetriesIPMeta {
			httputil.SleepContext(context.Background(), resolver.RetryBaseDelay)
		}
	}
	return nil, lastErr
}

func getTorData(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetTOR)

	dbg.Printf("%s target=%q", constants.FuncGetTOR, target)

	rev, _, err := resolver.ReverseIP(target)
	if err != nil {
		dbg.Printf("%s error target=%q stage=validate_input err=%v", constants.FuncGetTOR, target, err)
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
		ips, lookupErr := aQueryFunc(target, query, constants.FuncGetTOR)

		if lookupErr != nil {
			lastErr = lookupErr
			continue
		}

		if slices.Contains(ips, dnsblPositive) || slices.Contains(ips, dnsblPositiveAlt) {
			isTor = true
			detectedContext = zone.tag
			break
		}
	}

	if !isTor && lastErr != nil {
		dbg.Printf("%s error target=%q stage=lookup_tor err=%v", constants.FuncGetTOR, target, lastErr)
		errMsg := fmt.Errorf("tor lookup failed after retries: %w", lastErr).Error()
		execution.Error = &errMsg
		return execution
	}

	if isTor {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    constants.TagTorExit,
			Context:  detectedContext,
		})
		execution.RawData = dnsblPositive
		dbg.Printf("%s success target=%q context=%q", constants.FuncGetTOR, target, detectedContext)
	} else {
		dbg.Printf("%s target=%q listed=false", constants.FuncGetTOR, target)
	}

	return execution
}
