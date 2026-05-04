package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getCNAMEData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_cname")

	log.Printf("get_cname starting query for target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	var cname, wwwCname string
	var cnameErr, wwwCnameErr error
	var rawDataBuilder strings.Builder

	wg.Go(func() {
		var raw []byte
		cname, raw, cnameErr = lookupCNAME(queryCtx, target)
		if len(raw) > 0 {
			mu.Lock()
			rawDataBuilder.Write(raw)
			rawDataBuilder.WriteString("\n")
			mu.Unlock()
		}
	})

	wwwTarget := "www." + target
	wg.Go(func() {
		var raw []byte
		wwwCname, raw, wwwCnameErr = lookupCNAME(queryCtx, wwwTarget)
		if len(raw) > 0 {
			mu.Lock()
			rawDataBuilder.Write(raw)
			rawDataBuilder.WriteString("\n")
			mu.Unlock()
		}
	})

	wg.Wait()

	if cnameErr != nil {
		log.Printf("get_cname error for target=%q: %v", target, cnameErr)
		modutil.SetError(&exec, "cname lookup failed: %v", cnameErr)
		return exec
	}

	if rawDataBuilder.Len() > 0 {
		exec.RawData = strings.TrimSpace(rawDataBuilder.String())
	}

	if cname != "" && !strings.EqualFold(cname, strings.TrimSuffix(target, ".")) {
		result, ok := buildCNAMEResult(cname, target, "CNAME Record")
		if ok {
			log.Printf("get_cname target=%q entity=%q type=%q oos=%v", target, result.Value, result.Type, result.OutOfScope)
			exec.Results = append(exec.Results, result)
		}
	}

	if wwwCnameErr == nil && wwwCname != "" && !strings.EqualFold(wwwCname, strings.TrimSuffix(wwwTarget, ".")) {
		result, ok := buildCNAMEResult(wwwCname, wwwTarget, "CNAME Record (www)")
		if ok {
			log.Printf("get_cname target=%q entity=%q type=%q oos=%v", wwwTarget, result.Value, result.Type, result.OutOfScope)
			exec.Results = append(exec.Results, result)
		}
	}

	log.Printf("get_cname completed for target=%q results=%d", target, len(exec.Results))

	return exec
}

func buildCNAMEResult(cname, target, relationContext string) (schema.ModuleResult, bool) {
	res, err := validator.Validate("domain", cname)
	if err != nil {
		log.Printf("get_cname skipping invalid cname target=%q entity=%q err=%v", target, cname, err)
		return schema.ModuleResult{}, false
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	resultType := res.Type
	if isOOS {
		resultType = "cname_target"
	}

	return schema.ModuleResult{
		Type:       resultType,
		Category:   "node",
		Value:      res.Value,
		Context:    relationContext,
		OutOfScope: isOOS,
	}, true
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
