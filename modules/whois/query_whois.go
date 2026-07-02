package whois

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/resolver"
)

var (
	ianaWhoisServer = "whois.iana.org"
	whoisPort       = "43"
)

func queryWHOIS(ctx context.Context, domain string) (string, error) {
	ianaRes, err := dialWHOIS(ctx, ianaWhoisServer, domain)
	if err != nil {
		return "", fmt.Errorf("failed to query IANA: %w", err)
	}

	referServer := ""
	scanner := bufio.NewScanner(strings.NewReader(ianaRes))
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if strings.HasPrefix(line, "refer:") || strings.HasPrefix(line, "whois:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				referServer = parts[1]
				break
			}
		}
	}

	if referServer == "" {
		if strings.Contains(strings.ToLower(ianaRes), "identity digital") {
			referServer = "whois.identitydigital.services"
		}
	}

	if referServer == "" || referServer == ianaWhoisServer {
		return ianaRes, nil
	}

	res, err := dialWHOIS(ctx, referServer, domain)
	if err != nil {
		return ianaRes, fmt.Errorf("failed to query refer server: %w", err)
	}
	return res, nil
}

func defaultDialContextFunc(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := resolver.GetDialer().DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial context: %w", err)
	}
	return conn, nil
}

var dialContextFunc = defaultDialContextFunc

func dialWHOIS(ctx context.Context, server, query string) (string, error) {
	query = formatWHOISQuery(server, query)
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesWhois; attempt++ {
		res, err := func() (string, error) {
			attemptCtx, cancel := context.WithTimeout(ctx, resolver.Timeout)
			defer cancel()

			conn, err := dialContextFunc(attemptCtx, "tcp", net.JoinHostPort(server, whoisPort))
			if err != nil {
				return "", fmt.Errorf("dial error: %w", err)
			}
			defer func() {
				if cerr := conn.Close(); cerr != nil {
					dbg.Printf("%s whois_connection_close_failed err=%v", constants.FuncGetWhois, cerr)
				}
			}()

			if deadline, ok := attemptCtx.Deadline(); ok {
				if sErr := conn.SetDeadline(deadline); sErr != nil {
					return "", fmt.Errorf("set deadline error: %w", sErr)
				}
			}

			if _, wErr := fmt.Fprintf(conn, "%s\r\n", query); wErr != nil {
				return "", fmt.Errorf("write error: %w", wErr)
			}

			b, rErr := io.ReadAll(conn)
			if rErr != nil {
				return "", fmt.Errorf("read error: %w", rErr)
			}
			return string(b), nil
		}()

		if err == nil {
			return res, nil
		}

		lastErr = err
		if attempt < resolver.MaxRetriesWhois {
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				break
			}
			continue
		}
	}

	return "", lastErr
}

func formatWHOISQuery(server, query string) string {
	switch {
	case strings.HasSuffix(server, "jprs.jp") && !strings.HasSuffix(query, "/e"):
		return query + "/e"
	case strings.HasSuffix(server, "verisign-grs.com") && !strings.HasPrefix(query, "="):
		return "=" + query
	case strings.HasSuffix(server, "denic.de") && !strings.HasPrefix(query, "-T dn "):
		return "-T dn " + query
	case strings.HasSuffix(server, "nic.name") && !strings.HasPrefix(query, "domain="):
		return "domain=" + query
	}
	return query
}
