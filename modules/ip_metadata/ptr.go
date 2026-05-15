package ip_metadata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func performPTRQuery(target string) ([]string, error) {
	var lastErr error
	var names []string

	for attempt := 1; attempt <= resolver.MaxRetriesIPMeta; attempt++ {
		err := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), resolver.Timeout)
			defer cancel()
			rev, isIPv4, revErr := resolver.ReverseIP(target)
			if revErr != nil {
				return fmt.Errorf("invalid ip: %w", revErr)
			}
			suffix := ".in-addr.arpa."
			if !isIPv4 {
				suffix = ".ip6.arpa."
			}

			var lookupErr error
			names, _, lookupErr = resolver.ResolveRecord(ctx, rev+suffix, 12, func(c context.Context, r *net.Resolver) ([]string, error) {
				return r.LookupAddr(c, target)
			})

			if lookupErr != nil {
				return fmt.Errorf("lookup: %w", lookupErr)
			}
			return nil
		}()

		if err == nil {
			dbg.Printf("get_ptr attempt=%d target=%q records=%d", attempt, target, len(names))
			return names, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host")) {
			dbg.Printf("get_ptr attempt=%d target=%q nxdomain", attempt, target)
			return nil, nil
		}

		if strings.Contains(err.Error(), "unrecognized address") {
			dbg.Printf("get_ptr target=%q invalid_ip", target)
			return nil, err
		}

		lastErr = err
		dbg.Printf("get_ptr attempt=%d target=%q err=%v", attempt, target, err)
		if attempt < resolver.MaxRetriesIPMeta {
			httputil.SleepContext(context.Background(), resolver.RetryBaseDelay)
		}
	}

	return nil, lastErr
}

func getPTRData(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetPTR)

	dbg.Printf("getPTRData target=%q", target)

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	names, err := ptrQueryFunc(target)

	if err != nil {
		if strings.Contains(err.Error(), "unrecognized address") {
			errMsg := errInvalidIPFormat + target
			execution.Error = &errMsg
			return execution
		}
		errMsg := fmt.Errorf("ptr lookup failed after retries: %w", err).Error()
		execution.Error = &errMsg
		return execution
	}

	if len(names) > 0 {
		rawBuffer.WriteString(strings.Join(names, ", "))
	}

	for _, name := range names {
		appendPTRResult(&execution, name)
	}

	return execution
}

func appendPTRResult(execution *schema.ModuleExecution, name string) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return
	}

	if validated, err := validator.Validate(constants.TypeDomain, name); err == nil {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     validated.Type,
			Category: constants.CategoryNode,
			Value:    validated.Value,
			Context:  "PTR Record",
			Tags:     []string{constants.TagReverseIP},
		})
		return
	}

	execution.Results = append(execution.Results, schema.ModuleResult{
		Type:     constants.TypePTR,
		Category: constants.CategoryProperty,
		Value:    name,
	})
}
