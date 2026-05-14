package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var srvPrefixes = []string{
	"_autodiscover._tcp",
	"_caldav._tcp",
	"_caldavs._tcp",
	"_carddav._tcp",
	"_carddavs._tcp",
	"_collab-edge._tls",
	"_ftp._tcp",
	"_http._tcp",
	"_imap._tcp",
	"_imaps._tcp",
	"_jabber._tcp",
	"_kerberos._tcp",
	"_kerberos._udp",
	"_kpasswd._tcp",
	"_kpasswd._udp",
	"_ldap._tcp",
	"_ldaps._tcp",
	"_matrix-identity._tcp",
	"_minecraft._tcp",
	"_pop3._tcp",
	"_pop3s._tcp",
	"_sip._tcp",
	"_sip._tls",
	"_sip._udp",
	"_sipfederationtls._tcp",
	"_sipinternal._tcp",
	"_stun._tcp",
	"_stun._udp",
	"_stuns._tcp",
	"_turn._tcp",
	"_turn._udp",
	"_turns._tcp",
	"_xmpp-client._tcp",
	"_xmpp-server._tcp",
}

type srvResult struct {
	prefix string
	record string
	host   string
}

func getSRVData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetSRV)
	log.Printf("get_srv target=%q", target)

	bruteCtx, cancel := context.WithTimeout(ctx, resolver.DNSBruteTimeout)
	defer cancel()

	results := make(chan srvResult, len(srvPrefixes))
	var wg sync.WaitGroup
	sem := make(chan struct{}, resolver.DNSConcurrency)

	for _, prefix := range srvPrefixes {
		wg.Add(1)

		go func(pfx string, threadCtx context.Context, s chan struct{}, w *sync.WaitGroup, resChan chan<- srvResult, trgt string) {
			defer w.Done()

			select {
			case s <- struct{}{}:
			case <-threadCtx.Done():
				return
			}
			defer func() { <-s }()

			domain := fmt.Sprintf("%s.%s", pfx, trgt)

			fallback := makeSRVFallback(domain)

			records, _, err := resolver.ResolveRecord(threadCtx, domain, 33, fallback)
			if err != nil || len(records) == 0 {
				return
			}

			for _, rec := range records {
				host, parseErr := parseSRVHost(rec)
				if parseErr == nil {
					resChan <- srvResult{prefix: pfx, record: rec, host: host}
				}
			}
		}(prefix, bruteCtx, sem, &wg, results, target)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var rawDataBuilder strings.Builder
	for res := range results {
		if rawDataBuilder.Len() > 0 {
			rawDataBuilder.WriteString("\n")
		}
		rawDataBuilder.WriteString(res.prefix)
		rawDataBuilder.WriteString(".")
		rawDataBuilder.WriteString(target)
		rawDataBuilder.WriteString(": ")
		rawDataBuilder.WriteString(res.record)

		exec.Results = append(exec.Results,
			schema.ModuleResult{
				Type:     constants.TypeSRV,
				Category: constants.CategoryProperty,
				Value:    res.record,
			},
		)

		if srvHost, ok := buildSRVHostResult(res.host, target); ok {
			exec.Results = append(exec.Results, srvHost)
		}
	}

	if rawDataBuilder.Len() > 0 {
		exec.RawData = rawDataBuilder.String()
	}

	log.Printf("get_srv target=%q results=%d", target, len(exec.Results))
	return exec
}

func buildSRVHostResult(host, target string) (schema.ModuleResult, bool) {
	res, err := validator.Validate(constants.TypeDomain, host)
	if err != nil {
		log.Printf("get_srv skipping invalid srv host target=%q entity=%q err=%v", target, host, err)
		return schema.ModuleResult{}, false
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	log.Printf("get_srv target=%q entity=%q oos=%v", target, res.Value, isOOS)

	return schema.ModuleResult{
		Type:       constants.TypeDomain,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagSRV},
		OutOfScope: isOOS,
	}, true
}

func parseSRVHost(data string) (string, error) {
	parts := strings.Fields(data)
	if len(parts) < 4 {
		return "", errors.New("invalid SRV record format")
	}

	host := strings.TrimSuffix(parts[3], ".")
	if host == "" {
		return "", errors.New("invalid SRV host")
	}

	for i := range 3 {
		if _, err := strconv.ParseUint(parts[i], 10, 16); err != nil {
			return "", fmt.Errorf("invalid numeric field %d: %w", i, err)
		}
	}

	return host, nil
}

func makeSRVFallback(domain string) func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
	return func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		_, srvs, err := r.LookupSRV(fallbackCtx, "", "", domain)
		if err != nil {
			return nil, fmt.Errorf("plain lookup srv failed: %w", err)
		}
		var res []string
		for _, srv := range srvs {
			res = append(res, fmt.Sprintf("%d %d %d %s", srv.Priority, srv.Weight, srv.Port, srv.Target))
		}
		return res, nil
	}
}
