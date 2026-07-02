package ip_metadata

import (
	"context"
	"fmt"
	"net"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/modules/utils/ripestat"
)

var (
	txtQueryFunc         = performTXTQuery
	ptrQueryFunc         = performPTRQuery
	aQueryFunc           = performAQuery
	ripestatQueryFunc    = ripestat.Query
	plainLookupTXT       = defaultLookupTXT
	plainLookupHost      = defaultLookupHost
	ptrResolveRecordFunc = resolver.ResolveRecord
)

func defaultLookupTXT(ctx context.Context, r *net.Resolver, target string) ([]string, error) {
	res, err := r.LookupTXT(ctx, target)
	if err != nil {
		err = fmt.Errorf("lookup txt error: %w", err)
	}
	return res, err
}

func defaultLookupHost(ctx context.Context, r *net.Resolver, target string) ([]string, error) {
	res, err := r.LookupHost(ctx, target)
	if err != nil {
		err = fmt.Errorf("lookup host error: %w", err)
	}
	return res, err
}
