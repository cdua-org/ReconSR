package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getCNAMEData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetCNAME)

	log.Printf("%s query_start target=%q", constants.FuncGetCNAME, target)

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
		log.Printf("%s error target=%q stage=lookup_root_cname err=%v", constants.FuncGetCNAME, target, cnameErr)
		modutil.SetError(&exec, "cname lookup failed: %v", cnameErr)
		return exec
	}

	if rawDataBuilder.Len() > 0 {
		exec.RawData = strings.TrimSpace(rawDataBuilder.String())
	}

	if cname != "" && !strings.EqualFold(cname, strings.TrimSuffix(target, ".")) {
		result, ok := buildCNAMEResult(cname, target, "CNAME Record", gen)
		if ok {
			log.Printf("%s result_entity target=%q entity=%q type=%q oos=%v", constants.FuncGetCNAME, target, result.Value, result.Type, result.OutOfScope)
			exec.Results = append(exec.Results, result)
		}
	}

	if wwwCnameErr == nil && wwwCname != "" && !strings.EqualFold(wwwCname, strings.TrimSuffix(wwwTarget, ".")) {
		result, ok := buildCNAMEResult(wwwCname, wwwTarget, "CNAME Record (www)", gen)
		if ok {
			log.Printf("%s result_entity target=%q entity=%q type=%q oos=%v", constants.FuncGetCNAME, wwwTarget, result.Value, result.Type, result.OutOfScope)
			exec.Results = append(exec.Results, result)
		}
	}

	log.Printf("%s success target=%q results=%d", constants.FuncGetCNAME, target, len(exec.Results))

	return exec
}

func buildCNAMEResult(cname, target, relationContext string, gen *modutil.LocalIDGenerator) (schema.ModuleResult, bool) {
	res, err := validator.Validate(constants.TypeDomain, cname)
	if err != nil {
		log.Printf("%s skip_invalid_cname target=%q entity=%q err=%v", constants.FuncGetCNAME, target, cname, err)
		return schema.ModuleResult{}, false
	}

	if res.Value == target {
		return schema.ModuleResult{}, false
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)

	return schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagCNAME},
		Context:    relationContext,
		OutOfScope: isOOS,
		LocalID:    gen.NextID(),
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
