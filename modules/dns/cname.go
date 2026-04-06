package dns

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"cdua-org/ReconSR/schema"
)

func getCNAMEData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_cname",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	var cname, wwwCname string
	var cnameErr, wwwCnameErr error
	var rawDataBuilder strings.Builder

	wg.Add(1)
	//nolint:modernize // wg.Go has edge cases with context cancellation that cause panics
	go func() {
		defer wg.Done()
		var raw []byte
		cname, raw, cnameErr = lookupCNAME(ctx, target)
		if len(raw) > 0 {
			mu.Lock()
			rawDataBuilder.Write(raw)
			rawDataBuilder.WriteString("\n")
			mu.Unlock()
		}
	}()

	wwwTarget := "www." + target
	wg.Add(1)
	//nolint:modernize // wg.Go has edge cases with context cancellation that cause panics
	go func() {
		defer wg.Done()
		var raw []byte
		wwwCname, raw, wwwCnameErr = lookupCNAME(ctx, wwwTarget)
		if len(raw) > 0 {
			mu.Lock()
			rawDataBuilder.Write(raw)
			rawDataBuilder.WriteString("\n")
			mu.Unlock()
		}
	}()

	wg.Wait()

	if cnameErr != nil {
		errMsg := "cname lookup failed: " + cnameErr.Error()
		execution.Error = &errMsg
		return execution
	}

	if rawDataBuilder.Len() > 0 {
		execution.RawData = strings.TrimSpace(rawDataBuilder.String())
	}

	if cname != "" && !strings.EqualFold(cname, strings.TrimSuffix(target, ".")) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   cname,
			Context: "CNAME Record",
		})
	}

	if wwwCnameErr == nil && wwwCname != "" && !strings.EqualFold(wwwCname, strings.TrimSuffix(wwwTarget, ".")) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   wwwCname,
			Context: "CNAME Record: www",
		})
	}

	return execution
}

func lookupCNAME(ctx context.Context, target string) (cnameStr string, rawData []byte, err error) {
	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		cname, cErr := r.LookupCNAME(fallbackCtx, target)
		if cErr != nil {
			return nil, fmt.Errorf("plain lookup cname failed: %w", cErr)
		}
		if cname != "" {
			return []string{cname}, nil
		}
		return nil, nil
	}

	// QTYPE 5 is CNAME
	records, raw, err := resolver.ResolveRecord(ctx, target, 5, plainFallback)
	if err != nil {
		return "", nil, fmt.Errorf("cname resolution failed: %w", err)
	}

	var cname string
	for _, rec := range records {
		c := strings.TrimSuffix(rec, ".")
		if c != "" {
			cname = c
			break
		}
	}

	if len(raw) == 0 && cname != "" {
		raw = []byte(cname)
	}

	return cname, raw, nil
}
