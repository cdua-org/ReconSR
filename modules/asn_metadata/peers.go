package asn_metadata

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/modules/utils/ripestat"
	"cdua-org/ReconSR/schema"
)

const (
	chainSeparator         = " <- "
	chainTooManyPeers      = "[TOO_MANY_PEERS]"
	neighbourPositionRight = "right"
)

func getASNPeers(target string, gen *modutil.LocalIDGenerator) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetASNPeers)

	dbg.Printf("%s target=%q", constants.FuncGetASNPeers, target)

	originASN := target
	if originASN == "" {
		errMsg := errInvalidASNFormat
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=validate_input err=invalid_asn_format", constants.FuncGetASNPeers, target)
		return execution
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.TimeoutASNMeta)
	defer cancel()

	var rawBuffer strings.Builder
	defer func() {
		execution.RawData = rawBuffer.String()
	}()

	chain, err := buildTransitChain(ctx, originASN, &rawBuffer)
	if err != nil {
		dbg.Printf("%s error target=%q stage=build_transit_chain err=%v", constants.FuncGetASNPeers, target, err)
		chain = append(chain, chainTooManyPeers)
	}

	dbg.Printf("%s success target=%q chain_length=%d", constants.FuncGetASNPeers, target, len(chain))

	if len(chain) == 0 {
		return execution
	}

	execution.Results = append(execution.Results, schema.ModuleResult{
		Type:     constants.TypeASN,
		Category: constants.CategoryNode,
		Value:    originASN,
		Context:  "Origin AS",
		Applied:  true,
		LocalID:  gen.NextID(),
	})

	chainLine := buildChainString(chain, originASN)
	execution.Results = append(execution.Results, schema.ModuleResult{
		Type:     constants.TypePeersChain,
		Category: constants.CategoryProperty,
		Value:    chainLine,
		Context:  "ASN Peers",
		LocalID:  gen.NextID(),
	})

	return execution
}

func buildTransitChain(ctx context.Context, originASN string, rawOut *strings.Builder) ([]string, error) {
	visited := make(map[string]bool)
	var chain []string

	if err := traverseUpstream(ctx, originASN, 0, visited, &chain, rawOut); err != nil {
		return chain, err
	}

	return chain, nil
}

func extractLargestUpstreamASN(neighbours []ripestat.Neighbour, originASN string) string {
	var largestASN string
	var maxPeers int

	for _, n := range neighbours {
		if n.Position == neighbourPositionRight {
			nASN := "AS" + strconv.Itoa(n.ASN)
			if nASN != originASN && n.ASN != 0 {
				if n.PeerCount > maxPeers {
					maxPeers = n.PeerCount
					largestASN = nASN
				}
			}
		}
	}
	return largestASN
}

func traverseUpstream(ctx context.Context, asn string, depth int, visited map[string]bool, chain *[]string, rawOut *strings.Builder) error {
	if depth >= resolver.MaxRecursionDepth {
		dbg.Printf("%s asn=%q depth=%d max_depth_reached", constants.FuncGetASNPeers, asn, depth)
		return nil
	}

	if visited[asn] {
		dbg.Printf("%s asn=%q depth=%d already_visited", constants.FuncGetASNPeers, asn, depth)
		return nil
	}
	visited[asn] = true

	dbg.Printf("%s asn=%q depth=%d querying_ripestat", constants.FuncGetASNPeers, asn, depth)

	var resp ripestat.APIResponse
	if err := ripestatQueryFunc(ctx, asn, constants.RIPEstatEndpointASNNeighbours, &resp, resolver.MaxRetriesASNMeta); err != nil {
		dbg.Printf("%s error asn=%q depth=%d stage=query_ripestat err=%v", constants.FuncGetASNPeers, asn, depth, err)
		return fmt.Errorf("ripestat query: %w", err)
	}

	if rawOut != nil && resp.RawJSON != "" {
		rawOut.WriteString(resp.RawJSON)
		rawOut.WriteString("\n")
	}

	upstream := extractLargestUpstreamASN(resp.Data.Neighbours, asn)

	dbg.Printf("%s asn=%q depth=%d largest_upstream=%q", constants.FuncGetASNPeers, asn, depth, upstream)

	if upstream != "" {
		*chain = append(*chain, upstream)
		return traverseUpstream(ctx, upstream, depth+1, visited, chain, rawOut)
	}

	return nil
}

func buildChainString(chain []string, originASN string) string {
	if len(chain) == 0 {
		return originASN
	}

	parts := make([]string, 0, len(chain)+1)
	for i := range slices.Backward(chain) {
		parts = append(parts, chain[i])
	}
	parts = append(parts, originASN)

	return strings.Join(parts, chainSeparator)
}
