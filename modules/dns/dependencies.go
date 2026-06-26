package dns

import (
	"context"
	"crypto/rand"
	"net"

	"cdua-org/ReconSR/modules/utils/preflightcheck"
	"cdua-org/ReconSR/modules/utils/resolver"
)

var (
	resolveRecordFunc = resolver.ResolveRecord
	resolveIPFunc     = resolver.ResolveIP
	randReadFunc      = rand.Read
	plainLookupCNAME  = func(ctx context.Context, r *net.Resolver, target string) (string, error) {
		return r.LookupCNAME(ctx, target)
	}
	plainLookupNS = func(ctx context.Context, r *net.Resolver, target string) ([]*net.NS, error) {
		return r.LookupNS(ctx, target)
	}
	plainLookupMX = func(ctx context.Context, r *net.Resolver, target string) ([]*net.MX, error) {
		return r.LookupMX(ctx, target)
	}
	plainLookupTXT = func(ctx context.Context, r *net.Resolver, target string) ([]string, error) {
		return r.LookupTXT(ctx, target)
	}
	plainLookupSRV = func(ctx context.Context, r *net.Resolver, service, proto, name string) (string, []*net.SRV, error) {
		return r.LookupSRV(ctx, service, proto, name)
	}
	queryDoHDnsFunc    = resolver.QueryDoHDns
	preflightCheckFunc = preflightcheck.PreFlightCheck
)
