package dns

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

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

func getSRVData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_srv",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results := make(chan srvResult, len(srvPrefixes))
	var wg sync.WaitGroup
	// Limit concurrency to avoid overloading the resolver
	sem := make(chan struct{}, 10)

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

			// QTYPE 33 is SRV
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
		}(prefix, ctx, sem, &wg, results, target)
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

		targetClean := strings.TrimSuffix(strings.ToLower(target), ".")
		hostClean := strings.TrimSuffix(strings.ToLower(res.host), ".")

		isSame := hostClean == targetClean
		isSubdomain := strings.HasSuffix(hostClean, "."+targetClean)
		isParent := strings.HasSuffix(targetClean, "."+hostClean)
		oos := !isSame && !isSubdomain && !isParent

		execution.Results = append(execution.Results,
			schema.ModuleResult{
				Type:    "string",
				Value:   res.record,
				Context: "SRV Record: " + res.prefix,
			},
			schema.ModuleResult{
				Type:       "domain",
				Value:      res.host,
				Context:    "SRV Target (" + res.prefix + ")",
				OutOfScope: oos,
			},
		)
	}

	if rawDataBuilder.Len() > 0 {
		execution.RawData = rawDataBuilder.String()
	}

	return execution
}

// parseSRVHost extracts the target domain from the SRV record string.
// Format: <priority> <weight> <port> <target>
func parseSRVHost(data string) (string, error) {
	parts := strings.Fields(data)
	if len(parts) < 4 {
		return "", errors.New("invalid SRV record format")
	}

	host := strings.TrimSuffix(parts[3], ".")
	if host == "" {
		return "", errors.New("invalid SRV host")
	}

	// Validate the first three parts are numbers
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
