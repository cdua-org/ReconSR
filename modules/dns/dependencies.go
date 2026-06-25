package dns

import (
	"context"
	"net"

	"cdua-org/ReconSR/modules/utils/preflightcheck"
	"cdua-org/ReconSR/modules/utils/resolver"
)

var (
	resolveRecordFunc = resolver.ResolveRecord
	resolveIPFunc     = resolver.ResolveIP
	plainLookupCNAME  = func(ctx context.Context, r *net.Resolver, target string) (string, error) {
		return r.LookupCNAME(ctx, target)
	}
	plainLookupMX = func(ctx context.Context, r *net.Resolver, target string) ([]*net.MX, error) {
		return r.LookupMX(ctx, target)
	}
	plainLookupTXT = func(ctx context.Context, r *net.Resolver, target string) ([]string, error) {
		return r.LookupTXT(ctx, target)
	}
	preflightCheckFunc = preflightcheck.PreFlightCheck
)
