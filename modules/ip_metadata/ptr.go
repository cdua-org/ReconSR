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
			dbg.Printf("%s success target=%q stage=lookup_ptr attempt=%d records=%d", constants.FuncGetPTR, target, attempt, len(names))
			return names, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host")) {
			dbg.Printf("%s target=%q stage=lookup_ptr attempt=%d nxdomain", constants.FuncGetPTR, target, attempt)
			return nil, nil
		}

		if strings.Contains(err.Error(), "unrecognized address") {
			dbg.Printf("%s error target=%q stage=validate_input err=%v", constants.FuncGetPTR, target, err)
			return nil, err
		}

		lastErr = err
		dbg.Printf("%s error target=%q stage=lookup_ptr attempt=%d err=%v", constants.FuncGetPTR, target, attempt, err)
		if attempt < resolver.MaxRetriesIPMeta {
			httputil.SleepContext(context.Background(), resolver.RetryBaseDelay)
		}
	}

	return nil, lastErr
}

func getPTRData(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetPTR)

	dbg.Printf("%s target=%q", constants.FuncGetPTR, target)

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
		dbg.Printf("%s error target=%q stage=lookup_ptr err=%v", constants.FuncGetPTR, target, err)
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

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q result_count=%d", constants.FuncGetPTR, target, len(execution.Results))
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetPTR, target)
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
