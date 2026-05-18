package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

type mxRecord struct {
	host string
	pref uint16
}

func getMXData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetMX)

	log.Printf("%s query_start target=%q", constants.FuncGetMX, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		mxs, err := r.LookupMX(fallbackCtx, target)
		if err != nil {
			return nil, fmt.Errorf("plain lookup mx failed: %w", err)
		}
		var res []string
		for _, mx := range mxs {
			res = append(res, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
		return res, nil
	}

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 15, plainFallback)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetMX, target, err)
		modutil.SetError(&exec, "mx lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFallback(&exec, raw, records, "\n")

	var mxs []mxRecord
	for _, rec := range records {
		mx, parseErr := parseMX(rec)
		if parseErr == nil {
			mxs = append(mxs, mx)
		}
	}

	if len(mxs) == 0 {
		return exec
	}

	sort.Slice(mxs, func(i, j int) bool {
		return mxs[i].pref < mxs[j].pref
	})

	for _, mx := range mxs {
		mxValue := fmt.Sprintf("%d %s", mx.pref, mx.host)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeMX,
			Category: constants.CategoryProperty,
			Value:    mxValue,
		})

		mxRef := &schema.EntityRef{Type: constants.TypeMX, Value: mxValue}
		hostResult := buildMXHostResult(mxRef, mx.host, target)
		if hostResult != nil {
			exec.Results = append(exec.Results, *hostResult)
		}
	}

	log.Printf("%s success target=%q results=%d", constants.FuncGetMX, target, len(exec.Results))

	return exec
}

func buildMXHostResult(source *schema.EntityRef, host, target string) *schema.ModuleResult {
	res, err := validator.Validate(constants.TypeDomain, host)
	if err != nil {
		log.Printf("%s skip_invalid_mx_host target=%q entity=%q err=%v", constants.FuncGetMX, target, host, err)
		return nil
	}

	if res.Value == target {
		log.Printf("%s skip_self_referential_mx_host target=%q", constants.FuncGetMX, target)
		return nil
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	log.Printf("%s result_host target=%q entity=%q oos=%v", constants.FuncGetMX, target, res.Value, isOOS)

	return &schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagMX},
		OutOfScope: isOOS,
		Source:     source,
	}
}

func parseMX(data string) (mxRecord, error) {
	host, err := dnsutils.ParseMXHost(data)
	if err != nil {
		return mxRecord{}, fmt.Errorf("parse mx host: %w", err)
	}

	parts := strings.Fields(data)
	pref, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return mxRecord{}, fmt.Errorf("parse priority: %w", err)
	}

	return mxRecord{
		host: host,
		pref: uint16(pref),
	}, nil
}
