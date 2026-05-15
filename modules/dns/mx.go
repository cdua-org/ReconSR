package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
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

	log.Printf("get_mx starting query for target=%q", target)

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
		log.Printf("get_mx error for target=%q: %v", target, err)
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
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeMX,
			Category: constants.CategoryProperty,
			Value:    fmt.Sprintf("%d %s", mx.pref, mx.host),
		})

		hostResult, ok := buildMXHostResult(mx.host, target)
		if ok {
			exec.Results = append(exec.Results, hostResult)
		}
	}

	log.Printf("get_mx completed for target=%q results=%d", target, len(exec.Results))

	return exec
}

func buildMXHostResult(host, target string) (schema.ModuleResult, bool) {
	res, err := validator.Validate(constants.TypeDomain, host)
	if err != nil {
		log.Printf("get_mx skipping invalid mx host target=%q entity=%q err=%v", target, host, err)
		return schema.ModuleResult{}, false
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	log.Printf("get_mx target=%q entity=%q oos=%v", target, res.Value, isOOS)

	return schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagMX},
		OutOfScope: isOOS,
	}, true
}

func parseMX(data string) (mxRecord, error) {
	parts := strings.Fields(data)
	if len(parts) < 2 {
		return mxRecord{}, errors.New("invalid MX record format")
	}

	host := strings.TrimSuffix(parts[1], ".")
	if host == "" {
		return mxRecord{}, errors.New("invalid MX record format")
	}

	pref, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return mxRecord{}, fmt.Errorf("parse priority: %w", err)
	}

	return mxRecord{
		host: host,
		pref: uint16(pref),
	}, nil
}
