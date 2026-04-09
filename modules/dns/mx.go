package dns

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

type mxRecord struct {
	host string
	pref uint16
}

func getMXData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_mx",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		mxs, err := r.LookupMX(fallbackCtx, target)
		if err != nil {
			return nil, fmt.Errorf("plain lookup mx failed: %w", err)
		}
		var res []string
		for _, mx := range mxs {
			// Format to match DoH JSON output: "priority host."
			res = append(res, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
		return res, nil
	}

	// QTYPE 15 is MX
	records, raw, err := resolver.ResolveRecord(ctx, target, 15, plainFallback)
	if err != nil {
		errMsg := "mx lookup failed: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	} else if len(records) > 0 {
		execution.RawData = strings.Join(records, "\n")
	}

	var mxs []mxRecord
	for _, rec := range records {
		mx, parseErr := parseMX(rec)
		if parseErr == nil {
			mxs = append(mxs, mx)
		}
	}

	if len(mxs) == 0 {
		return execution
	}

	sort.Slice(mxs, func(i, j int) bool {
		return mxs[i].pref < mxs[j].pref
	})

	for _, mx := range mxs {
		targetClean := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(target)), ".")
		mxHostClean := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(mx.host)), ".")

		// An MX host is In Scope if it's the target itself, a subdomain, or a parent domain
		// (e.g., if target is dev.example.com, then example.com is also In Scope).
		isSame := mxHostClean == targetClean
		isSubdomain := strings.HasSuffix(mxHostClean, "."+targetClean)
		isParent := strings.HasSuffix(targetClean, "."+mxHostClean)

		targetOOS := !isSame && !isSubdomain && !isParent

		// Always emit the full MX record as a string to guarantee visibility on the graph,
		// preventing it from being hidden if the host matches the target (self-discovery skip in core).
		// Also emit the host as a domain type to trigger further pivoting (IP resolution).
		execution.Results = append(execution.Results,
			schema.ModuleResult{
				Type:    "string",
				Value:   fmt.Sprintf("%d %s", mx.pref, mx.host),
				Context: "MX Record",
			},
			schema.ModuleResult{
				Type:       "domain",
				Value:      mx.host,
				Context:    "MX Host",
				OutOfScope: targetOOS,
			},
		)
	}

	return execution
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
