package dns

import (
	"context"
	"fmt"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getSVCBData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetSVCB)
	log.Printf("%s query_start target=%q", constants.FuncGetSVCB, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	type queryResult struct {
		records []string
		qtype   string
		raw     []byte
	}

	ch := make(chan queryResult, 2)

	for _, qt := range []struct {
		name string
		code int
	}{
		{"SVCB", 64},
		{"HTTPS", 65},
	} {
		go func(code int, name string) {
			recs, raw, err := resolveRecordFunc(queryCtx, target, code, nil)
			if err != nil {
				log.Printf("%s error target=%q rrtype=%s stage=resolve_record err=%v", constants.FuncGetSVCB, target, name, err)
				ch <- queryResult{qtype: name}
				return
			}
			ch <- queryResult{records: recs, qtype: name, raw: raw}
		}(qt.code, qt.name)
	}

	var rawParts []string

	for range 2 {
		res := <-ch

		if len(res.raw) > 0 {
			rawParts = append(rawParts, string(res.raw))
		}

		for _, rec := range res.records {
			priority, svcTarget, params, decoded := dnsutils.ParseSVCB(rec)

			if !decoded {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeSVCB,
					Category: constants.CategoryProperty,
					Value:    rec,
					Context:  res.qtype + " Record",
					LocalID:  gen.NextID(),
				})
				continue
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "priority=%d target=%s", priority, svcTarget)
			for k, v := range params {
				fmt.Fprintf(&sb, " %s=%s", k, v)
			}

			val := sb.String()
			svcbRef := &schema.EntityRef{Type: constants.TypeSVCB, Value: val}

			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeSVCB,
				Category: constants.CategoryProperty,
				Value:    val,
				Context:  res.qtype + " Record",
				LocalID:  gen.NextID(),
			})

			if v, ok := params["ipv4hint"]; ok {
				for ip := range strings.SplitSeq(v, ",") {
					exec.Results = append(exec.Results, schema.ModuleResult{
						Type:     constants.TypeIPv4,
						Category: constants.CategoryNode,
						Value:    ip,
						Context:  res.qtype + " IPv4 Hint",
						Source:   svcbRef,
						LocalID:  gen.NextID(),
					})
				}
			}
			if v, ok := params["ipv6hint"]; ok {
				for ip := range strings.SplitSeq(v, ",") {
					exec.Results = append(exec.Results, schema.ModuleResult{
						Type:     constants.TypeIPv6,
						Category: constants.CategoryNode,
						Value:    ip,
						Context:  res.qtype + " IPv6 Hint",
						Source:   svcbRef,
						LocalID:  gen.NextID(),
					})
				}
			}

			if v, ok := params["alpn"]; ok {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeSVCB,
					Category: constants.CategoryProperty,
					Value:    v,
					Context:  res.qtype + " ALPN Protocols",
					Source:   svcbRef,
					LocalID:  gen.NextID(),
				})
			}

			if v, ok := params["ech"]; ok {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeSVCB,
					Category: constants.CategoryProperty,
					Value:    v,
					Context:  res.qtype + " ECH Config",
					Source:   svcbRef,
					LocalID:  gen.NextID(),
				})
			}
		}
	}

	if len(rawParts) > 0 {
		exec.RawData = strings.Join(rawParts, "\n")
	}

	log.Printf("%s success target=%q results=%d", constants.FuncGetSVCB, target, len(exec.Results))
	return exec
}
