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
)

// ErrZoneBroken indicates the target's authoritative DNS zone is unusable
// (SERVFAIL, REFUSED, NOTIMP, or NOTAUTH from the delegated nameserver).
var ErrZoneBroken = errors.New("DNS zone is broken")

func isBrokenZone(rcode uint8) bool {
	return rcode == rcodeServfail || rcode == rcodeRefused ||
		rcode == rcodeNotimp || rcode == rcodeNotauth
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
	if baseDomain == "" {
		baseDomain = target
	}

	nsRecords, err := fetchNSRecords(ctx, baseDomain)
	if err != nil {
		if errors.Is(err, ErrZoneBroken) {
			return ErrZoneBroken
		}
		return fmt.Errorf("failed to fetch NS records for %s: %w", baseDomain, err)
	}
	if len(nsRecords) == 0 {
		return ErrZoneBroken
	}

	slices.Sort(nsRecords)

	// Probe up to 2 NS servers; declare broken only when all probed agree.
	limit := min(len(nsRecords), 2)
	confirmations := 0
	checked := 0

	for i := range limit {
		nsIP, resolveErr := resolveNSAddress(ctx, nsRecords[i])
		if resolveErr != nil {
			log.Printf("skipping NS %s: %v", nsRecords[i], resolveErr)
			continue
		}

		key := cacheKey{domain: target, nsIP: nsIP}
		var rcode uint8

		if cached, ok := loadFromCache(key); ok {
			rcode = cached.rcode
		} else {
			var queryErr error
			rcode, queryErr = performDirectSOAQuery(ctx, target, nsIP)
			if queryErr != nil {
				log.Printf("SOA query to %s for %s failed: %v", nsIP, target, queryErr)
				continue
			}
			storeInCache(key, rcode)
		}

		checked++

		if isBrokenZone(rcode) {
			confirmations++
		} else {
			// At least one NS reports a healthy zone — trust it.
			return nil
		}
	}

	if confirmations > 0 && confirmations == checked {
		return ErrZoneBroken
	}

	return nil
}

func fetchNSRecords(ctx context.Context, domain string) ([]string, error) {
	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	nsRecords, err := resolver.GetResolver().LookupNS(queryCtx, domain)
	if err != nil {
		if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
			if dnsErr.IsNotFound || strings.Contains(dnsErr.Error(), "no such host") || strings.Contains(dnsErr.Error(), "server misbehaving") {
				return nil, ErrZoneBroken
			}
		}
		return nil, fmt.Errorf("NS lookup failed: %w", err)
	}

	result := make([]string, 0, len(nsRecords))
	for _, ns := range nsRecords {
		result = append(result, ns.Host)
	}
	return result, nil
}

func resolveNSAddress(ctx context.Context, nsHost string) (string, error) {
	nsHost = stripTrailingDot(nsHost)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	ips, err := resolver.GetResolver().LookupHost(queryCtx, nsHost)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s: %w", nsHost, err)
	}

	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found for %s", nsHost)
}

func performDirectSOAQuery(_ context.Context, target, nsIP string) (uint8, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP(nsIP),
		Port: 53,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer func() {
		closeErr := conn.Close()
		if closeErr != nil {
			log.Printf("conn.Close() error: %v", closeErr)
		}
	}()

	if deadlineErr := conn.SetDeadline(time.Now().Add(dnsTimeout)); deadlineErr != nil {
		return 0, fmt.Errorf("failed to set deadline: %w", deadlineErr)
	}

	query := buildDNSQuery(target)

	if _, writeErr := conn.Write(query); writeErr != nil {
		return 0, fmt.Errorf("failed to send DNS query: %w", writeErr)
	}

	buffer := make([]byte, dnsMaxPacketLen)
	n, err := conn.Read(buffer)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return 0, errors.New("DNS query timeout")
		}
		return 0, fmt.Errorf("failed to read DNS response: %w", err)
	}

	if n < dnsHeaderSize {
		return 0, fmt.Errorf("DNS response too short: %d bytes", n)
	}

	rcode := buffer[3] & 0x0F
	log.Printf("performDirectSOAQuery IP=%s query=%x rcode=%d size=%d", nsIP, query, rcode, n)
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
