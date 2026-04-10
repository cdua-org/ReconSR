package asn_metadata

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getASNPeers(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_asn_peers",
		Results:  []schema.ModuleResult{},
	}

	debug := isDebug()
	if debug {
		fmt.Fprintf(os.Stderr, "[asn_meta-debug] getASNPeers target=%q\n", target)
	}

	originASN := normalizeASN(target)
	if originASN == "" {
		errMsg := "invalid asn format"
		execution.Error = &errMsg
		if debug {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] getASNPeers target=%q invalid_format\n", target)
		}
		return execution
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.TimeoutASNMeta)
	defer cancel()

	var rawBuffer strings.Builder
	chain, err := buildTransitChain(ctx, originASN, &rawBuffer)
	if err != nil {
		errMsg := "asn peers lookup failed: " + err.Error()
		execution.Error = &errMsg
		if debug {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] getASNPeers target=%q build_chain_error=%v\n", target, err)
		}
		return execution
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[asn_meta-debug] getASNPeers target=%q chain_length=%d\n", target, len(chain))
	}

	if len(chain) == 0 {
		return execution
	}

	execution.Results = append(execution.Results, schema.ModuleResult{
		Type:    "asn",
		Value:   originASN,
		Context: "Origin AS",
		Applied: true,
	})

	if len(chain) > 0 {
		chainLine := buildRawChain(chain, originASN)
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "peers_chain",
			Value:   chainLine,
			Context: "ASN Peers",
		})
	}

	execution.RawData = rawBuffer.String()

	return execution
}

func buildTransitChain(ctx context.Context, originASN string, rawOut *strings.Builder) ([]string, error) {
	visited := make(map[string]bool)
	var chain []string

	if err := traverseUpstream(ctx, originASN, 0, visited, &chain, rawOut); err != nil {
		return nil, err
	}

	return chain, nil
}

func extractUpstreamASNs(neighbours []neighbour, originASN string) []string {
	var upstreams []string
	for _, n := range neighbours {
		if n.Position == "right" && n.PathCount > 0 {
			nASN := normalizeASN(strconv.Itoa(n.ASN))
			if nASN != originASN && nASN != "" {
				upstreams = append(upstreams, nASN)
			}
		}
		if len(upstreams) >= 3 {
			break
		}
	}
	return upstreams
}

func recursivelyTraverseUpstreams(ctx context.Context, upstreams []string, depth int, visited map[string]bool, chain *[]string, rawOut *strings.Builder, debug bool) error {
	for _, upstream := range upstreams {
		*chain = append(*chain, upstream)
		if err := traverseUpstream(ctx, upstream, depth+1, visited, chain, rawOut); err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[asn_meta-debug] traverseUpstream upstream=%q recursive_error=%v\n", upstream, err)
			}
			return err
		}
	}
	return nil
}

func traverseUpstream(ctx context.Context, asn string, depth int, visited map[string]bool, chain *[]string, rawOut *strings.Builder) error {
	debug := isDebug()

	if depth >= resolver.MaxRecursionDepth {
		if debug {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] traverseUpstream asn=%q depth=%d max_depth_reached\n", asn, depth)
		}
		return nil
	}

	asn = normalizeASN(asn)
	if visited[asn] {
		if debug {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] traverseUpstream asn=%q depth=%d already_visited\n", asn, depth)
		}
		return nil
	}
	visited[asn] = true

	if debug {
		fmt.Fprintf(os.Stderr, "[asn_meta-debug] traverseUpstream asn=%q depth=%d querying_ripestat\n", asn, depth)
	}

	var resp ripeAPIResponse
	if err := queryRIPEstat(ctx, asn, "asn-neighbours", &resp); err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] traverseUpstream asn=%q depth=%d ripestat_error=%v\n", asn, depth, err)
		}
		return err
	}

	if rawOut != nil && resp.RawJSON != "" {
		rawOut.WriteString(resp.RawJSON)
		rawOut.WriteString("\n")
	}

	upstreams := extractUpstreamASNs(resp.Data.Neighbours, asn)

	if debug {
		fmt.Fprintf(os.Stderr, "[asn_meta-debug] traverseUpstream asn=%q depth=%d found_upstreams=%d\n", asn, depth, len(upstreams))
	}

	return recursivelyTraverseUpstreams(ctx, upstreams, depth, visited, chain, rawOut, debug)
}

func buildChainString(chain []string, originASN string) string {
	if len(chain) == 0 {
		return "Transit chain: " + originASN
	}

	var parts []string
	for i := len(chain) - 1; i >= 0; i-- {
		parts = append(parts, chain[i])
	}
	parts = append(parts, originASN)

	return "Transit chain: " + strings.Join(parts, " <- ")
}

func buildRawChain(chain []string, originASN string) string {
	var sb strings.Builder
	for _, v := range chain {
		sb.WriteString(v)
		sb.WriteString(" <- ")
	}
	sb.WriteString(originASN)
	return sb.String()
}
