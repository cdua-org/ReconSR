package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"

	"cdua-org/ReconSR/modules/utils/preflightcheck"
	"cdua-org/ReconSR/modules/utils/resolver"
)

var (
	resolveRecordFunc  = resolver.ResolveRecord
	resolveIPFunc      = resolver.ResolveIP
	randReadFunc       = rand.Read
	plainLookupCNAME   = defaultLookupCNAME
	plainLookupNS      = defaultLookupNS
	plainLookupMX      = defaultLookupMX
	plainLookupTXT     = defaultLookupTXT
	plainLookupSRV     = defaultLookupSRV
	queryDoHDnsFunc    = resolver.QueryDoHDns
	preflightCheckFunc = preflightcheck.PreFlightCheck
)

func defaultLookupCNAME(ctx context.Context, r *net.Resolver, target string) (string, error) {
	res, err := r.LookupCNAME(ctx, target)
	if err != nil {
		err = fmt.Errorf("lookup CNAME error: %w", err)
	}
	return res, err
}

func defaultLookupNS(ctx context.Context, r *net.Resolver, target string) ([]*net.NS, error) {
	res, err := r.LookupNS(ctx, target)
	if err != nil {
		err = fmt.Errorf("lookup NS error: %w", err)
	}
	return res, err
}

func defaultLookupMX(ctx context.Context, r *net.Resolver, target string) ([]*net.MX, error) {
	res, err := r.LookupMX(ctx, target)
	if err != nil {
		err = fmt.Errorf("lookup MX error: %w", err)
	}
	return res, err
}

func defaultLookupTXT(ctx context.Context, r *net.Resolver, target string) ([]string, error) {
	res, err := r.LookupTXT(ctx, target)
	if err != nil {
		err = fmt.Errorf("lookup TXT error: %w", err)
	}
	return res, err
}

func defaultLookupSRV(ctx context.Context, r *net.Resolver, service, proto, name string) (string, []*net.SRV, error) {
	cname, srvs, err := r.LookupSRV(ctx, service, proto, name)
	if err != nil {
		err = fmt.Errorf("lookup SRV error: %w", err)
	}
	return cname, srvs, err
}
