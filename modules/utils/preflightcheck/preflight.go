// Package preflightcheck provides a thread-safe DNS zone health validation utility
// that detects broken authoritative DNS zones before heavy OSINT scanning begins.
package preflightcheck

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
)

var log = debuglog.New("preflight")

var dnsQueryCache sync.Map

// domainChecks implements singleflight: concurrent PreFlightCheck calls for the
// same domain coalesce into a single network probe.
var domainChecks sync.Map

type domainCheck struct {
	done chan struct{}
	err  error
}

type cacheKey struct {
	domain string
	nsIP   string
}

type cacheValue struct {
	timestamp time.Time
	rcode     uint8
}

const (
	dnsTimeout      = 2 * time.Second
	cacheValidity   = 5 * time.Minute
	rcodeServfail   = 2
	rcodeNotimp     = 4
	rcodeRefused    = 5
	rcodeNotauth    = 9
	dnsTypeSOA      = 6
	dnsClassINET    = 1
	dnsHeaderSize   = 12
	dnsMaxPacketLen = 512

	strNoError  = "NOERROR"
	strFormerr  = "FORMERR"
	strServfail = "SERVFAIL"
	strNxdomain = "NXDOMAIN"
	strNotimp   = "NOTIMP"
	strRefused  = "REFUSED"
	strNotauth  = "NOTAUTH"
)

// ErrZoneBroken indicates the target's authoritative DNS zone is unusable
// (SERVFAIL, REFUSED, NOTIMP, or NOTAUTH from the delegated nameserver).
var ErrZoneBroken = errors.New("DNS zone is broken")

func isBrokenZone(rcode uint8) bool {
	return rcode == rcodeServfail || rcode == rcodeRefused ||
		rcode == rcodeNotimp || rcode == rcodeNotauth
}

func rcodeToString(rcode uint8) string {
	switch rcode {
	case 0:
		return strNoError
	case 1:
		return strFormerr
	case 2:
		return strServfail
	case 3:
		return strNxdomain
	case rcodeNotimp:
		return strNotimp
	case rcodeRefused:
		return strRefused
	case rcodeNotauth:
		return strNotauth
	default:
		return fmt.Sprintf("UNKNOWN(%d)", rcode)
	}
}

// PreFlightCheck verifies if a target subdomain's authoritative DNS zone
// is physically broken (e.g., returns SERVFAIL or REFUSED). A zone is only
// marked as broken when at least two independent nameservers confirm the
// failure. If the parent zone has a single NS, one confirmation suffices.
//
// NS records are sorted lexicographically to guarantee deterministic server
// selection across concurrent calls, which ensures consistent cache hits.
func PreFlightCheck(ctx context.Context, target string) error {
	check := &domainCheck{done: make(chan struct{})}
	if existing, loaded := domainChecks.LoadOrStore(target, check); loaded {
		prev, ok := existing.(*domainCheck)
		if !ok {
			return fmt.Errorf("preflight: unexpected cache type for %s", target)
		}
		<-prev.done
		return prev.err
	}

	check.err = doPreFlightCheck(ctx, target)
	close(check.done)
	return check.err
}

func doPreFlightCheck(ctx context.Context, target string) error {
	if _, err := validator.Validate(constants.TypeDomain, target); err != nil {
		return ErrZoneBroken
	}

	baseDomain := orgdomain.GetOrganizationalDomain(target)

	nsRecords, err := fetchNSRecords(ctx, target, baseDomain)
	if err != nil {
		if errors.Is(err, ErrZoneBroken) {
			return ErrZoneBroken
		}
		return fmt.Errorf("failed to fetch NS records for %s: %w", baseDomain, err)
	}

	slices.Sort(nsRecords)

	limit := min(len(nsRecords), 2)
	confirmations := 0
	checked := 0

	for i := range limit {
		nsIP, resolveErr := resolveNSAddress(ctx, target, nsRecords[i])
		if resolveErr != nil {
			log.Printf("resolveNS error target=%q nsHost=%q err=%v", target, nsRecords[i], resolveErr)
			continue
		}

		key := cacheKey{domain: target, nsIP: nsIP}

		var rcode uint8
		if cached, ok := loadFromCache(key); ok {
			rcode = cached.rcode
		} else {
			var queryErr error
			rcode, queryErr = performDirectSOAQuery(ctx, target, nsRecords[i], nsIP)
			if queryErr != nil {
				log.Printf("performDirectSOAQuery error target=%q nsHost=%q nsIP=%q err=%v", target, nsRecords[i], nsIP, queryErr)
				continue
			}
			storeInCache(key, rcode)
		}

		checked++

		if isBrokenZone(rcode) {
			confirmations++
		} else {
			return nil
		}
	}

	if confirmations > 0 && confirmations == checked {
		return ErrZoneBroken
	}

	return nil
}

var overridePlainServers []string

func getPlainServers() []string {
	if overridePlainServers != nil {
		return overridePlainServers
	}
	return resolver.GetPlainServers()
}

func fetchNSRecords(ctx context.Context, target, domain string) ([]string, error) {
	servers := getPlainServers()
	startIdx := int(resolver.PlainStartIndex())
	maxAttempts := min(resolver.MaxRetriesPreflight, len(servers))
	var lastErr error

	for i := range maxAttempts {
		server := servers[(startIdx+i)%len(servers)]

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				host := server
				port := "53"
				if h, p, err := net.SplitHostPort(server); err == nil {
					host = h
					port = p
				}
				d := net.Dialer{Timeout: resolver.Timeout}
				return d.DialContext(dialCtx, "udp", net.JoinHostPort(host, port))
			},
		}

		queryCtx, cancel := context.WithTimeout(ctx, resolver.PreflightTimeout)
		nsRecords, err := r.LookupNS(queryCtx, domain)
		cancel()

		if err == nil {
			log.Printf("fetchNS success target=%q domain=%q attempt=%d/%d via=%q",
				target, domain, i+1, maxAttempts, server)
			result := make([]string, 0, len(nsRecords))
			for _, ns := range nsRecords {
				result = append(result, ns.Host)
			}
			return result, nil
		}

		if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
			if dnsErr.IsNotFound || strings.Contains(dnsErr.Error(), "no such host") ||
				strings.Contains(dnsErr.Error(), "server misbehaving") {
				log.Printf("fetchNS error target=%q domain=%q via=%q err=%v",
					target, domain, server, err)
				return nil, ErrZoneBroken
			}
		}

		log.Printf("fetchNS error target=%q domain=%q attempt=%d/%d via=%q err=%v",
			target, domain, i+1, maxAttempts, server, err)
		lastErr = err
	}

	log.Printf("fetchNS error target=%q domain=%q attempts=%d err=%v",
		target, domain, maxAttempts, lastErr)
	return nil, fmt.Errorf("NS lookup failed: %w", lastErr)
}

func resolveNSAddress(ctx context.Context, target, nsHost string) (string, error) {
	nsHost = stripTrailingDot(nsHost)
	servers := getPlainServers()
	startIdx := int(resolver.PlainStartIndex())
	maxAttempts := min(resolver.MaxRetriesPreflight, len(servers))
	var lastErr error

	for i := range maxAttempts {
		server := servers[(startIdx+i)%len(servers)]

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				host := server
				port := "53"
				if h, p, err := net.SplitHostPort(server); err == nil {
					host = h
					port = p
				}
				d := net.Dialer{Timeout: resolver.Timeout}
				return d.DialContext(dialCtx, "udp", net.JoinHostPort(host, port))
			},
		}

		queryCtx, cancel := context.WithTimeout(ctx, resolver.PreflightTimeout)
		ips, err := r.LookupIP(queryCtx, "ip4", nsHost)
		cancel()

		if err == nil && len(ips) > 0 {
			log.Printf("resolveNS success target=%q nsHost=%q attempt=%d/%d via=%q",
				target, nsHost, i+1, maxAttempts, server)
			return ips[0].String(), nil
		}

		if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
			if dnsErr.IsNotFound || strings.Contains(dnsErr.Error(), "no such host") {
				log.Printf("resolveNS error target=%q nsHost=%q via=%q err=%v",
					target, nsHost, server, err)
				break
			}
		}

		log.Printf("resolveNS error target=%q nsHost=%q attempt=%d/%d via=%q err=%v",
			target, nsHost, i+1, maxAttempts, server, err)
		lastErr = err
	}

	log.Printf("resolveNS error target=%q nsHost=%q attempts=%d err=%v",
		target, nsHost, maxAttempts, lastErr)
	return "", fmt.Errorf("failed to resolve %s: %w", nsHost, lastErr)
}

func performDirectSOAQuery(_ context.Context, target, nsHost, nsIP string) (uint8, error) {
	host := nsIP
	port := 53
	if h, p, err := net.SplitHostPort(nsIP); err == nil {
		host = h
		if parsedPort, err := strconv.Atoi(p); err == nil {
			port = parsedPort
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", host)
	}

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   ip,
		Port: port,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("performDirectSOAQuery error target=%q nsIP=%q err=%v", target, nsIP, closeErr)
		}
	}()

	if deadlineErr := conn.SetDeadline(time.Now().Add(resolver.PreflightTimeout)); deadlineErr != nil {
		return 0, fmt.Errorf("failed to set deadline: %w", deadlineErr)
	}

	query := buildDNSQuery(target)

	if _, writeErr := conn.Write(query); writeErr != nil {
		return 0, fmt.Errorf("failed to send DNS query: %w", writeErr)
	}

	buffer := make([]byte, dnsMaxPacketLen)
	n, err := conn.Read(buffer)
	if err != nil {
		if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
			return 0, errors.New("DNS query timeout")
		}
		return 0, fmt.Errorf("failed to read DNS response: %w", err)
	}

	if n < dnsHeaderSize {
		return 0, fmt.Errorf("DNS response too short: %d bytes", n)
	}

	rcode := buffer[3] & 0x0F
	zoneStatus := "dns_ok"
	if isBrokenZone(rcode) {
		zoneStatus = "dns_bad"
	}
	log.Printf("performDirectSOAQuery success target=%q nsHost=%q nsIP=%q query=%x rcode=%s(%d) size=%d zone=%q",
		target, nsHost, nsIP, query, rcodeToString(rcode), rcode, n, zoneStatus)
	return rcode, nil
}

func buildDNSQuery(domain string) []byte {
	var packet [dnsMaxPacketLen]byte
	offset := 0

	binary.BigEndian.PutUint16(packet[offset:], uint16(time.Now().UnixNano()&0xFFFF))
	offset += 2

	flags := uint16(0x0100)
	binary.BigEndian.PutUint16(packet[offset:], flags)
	offset += 2

	binary.BigEndian.PutUint16(packet[offset:], 1)
	offset += 2
	binary.BigEndian.PutUint16(packet[offset:], 0)
	offset += 2
	binary.BigEndian.PutUint16(packet[offset:], 0)
	offset += 2
	binary.BigEndian.PutUint16(packet[offset:], 0)
	offset += 2

	labels := splitDomain(domain)
	for _, label := range labels {
		l := len(label)
		if l >= 256 {
			l = 255
		}
		packet[offset] = byte(l)
		offset++
		copy(packet[offset:], label)
		offset += len(label)
	}

	packet[offset] = 0
	offset++

	binary.BigEndian.PutUint16(packet[offset:], dnsTypeSOA)
	offset += 2
	binary.BigEndian.PutUint16(packet[offset:], dnsClassINET)
	offset += 2

	return packet[:offset]
}

func splitDomain(domain string) []string {
	domain = stripTrailingDot(domain)
	if domain == "" {
		return nil
	}

	var labels []string
	start := 0
	for i := range len(domain) {
		if domain[i] == '.' {
			labels = append(labels, domain[start:i])
			start = i + 1
		}
	}
	labels = append(labels, domain[start:])
	return labels
}

func stripTrailingDot(s string) string {
	if s != "" && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func loadFromCache(key cacheKey) (cacheValue, bool) {
	if val, ok := dnsQueryCache.Load(key); ok {
		if cached, ok := val.(cacheValue); ok {
			if time.Since(cached.timestamp) < cacheValidity {
				return cached, true
			}
			dnsQueryCache.Delete(key)
		}
	}
	return cacheValue{}, false
}

func storeInCache(key cacheKey, rcode uint8) {
	dnsQueryCache.Store(key, cacheValue{
		rcode:     rcode,
		timestamp: time.Now(),
	})
}
