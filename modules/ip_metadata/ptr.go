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

func getPTRData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_ptr",
		Results:  []schema.ModuleResult{},
	}

	debug := isDebug()
	var lastErr error
	var names []string

	for attempt := 1; attempt <= resolver.MaxRetriesIPMeta; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), resolver.Timeout)

		r := resolver.GetResolver()
		var err error
		names, err = r.LookupAddr(ctx, target)
		cancel()

		if err == nil {
			lastErr = nil
			if debug {
				fmt.Fprintf(os.Stderr, "[ip_meta-debug] get_ptr attempt=%d target=%q records=%d\n", attempt, target, len(names))
			}
			break
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host")) {
			if debug {
				fmt.Fprintf(os.Stderr, "[ip_meta-debug] get_ptr attempt=%d target=%q nxdomain\n", attempt, target)
			}
			return execution
		}
		if strings.Contains(err.Error(), "unrecognized address") {
			errMsg := "invalid ip address format: " + target
			execution.Error = &errMsg
			if debug {
				fmt.Fprintf(os.Stderr, "[ip_meta-debug] get_ptr target=%q invalid_ip\n", target)
			}
			return execution
		}
		lastErr = err
		if debug {
			fmt.Fprintf(os.Stderr, "[ip_meta-debug] get_ptr attempt=%d target=%q err=%v\n", attempt, target, err)
		}
	}

	if lastErr != nil {
		errMsg := "ptr lookup failed after retries: " + lastErr.Error()
		execution.Error = &errMsg
		return execution
	}

	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name == "" {
			continue
		}
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "domain",
			Value:   name,
			Context: "PTR Record",
		})
	}

	if len(names) > 0 {
		execution.RawData = strings.Join(names, ", ")
	}

	return execution
}
