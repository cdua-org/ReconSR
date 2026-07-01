package preflightcheck

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

type mockDNSHandler func([]byte, net.Addr, *net.UDPConn)

func startMockDNSServer(t *testing.T, handler mockDNSHandler) (addr string, cleanup func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to start mock DNS server: %v", err)
	}

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("unexpected address type from ListenUDP")
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, dnsMaxPacketLen)
		for {
			n, remoteAddr, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			handler(buf[:n], remoteAddr, conn)
		}
	})

	cleanup = func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("mock DNS server close: %v", closeErr)
		}
		wg.Wait()
	}

	return fmt.Sprintf("127.0.0.1:%d", udpAddr.Port), cleanup
}

func mustWriteTo(t *testing.T, conn *net.UDPConn, data []byte, addr net.Addr) {
	t.Helper()
	if _, err := conn.WriteTo(data, addr); err != nil {
		t.Errorf("WriteTo failed: %v", err)
	}
}

func buildNSResponse(queryPacket []byte, nsHosts []string) []byte {
	var resp [dnsMaxPacketLen]byte
	copy(resp[:2], queryPacket[:2])

	flags := uint16(0x8180)
	binary.BigEndian.PutUint16(resp[2:], flags)

	binary.BigEndian.PutUint16(resp[4:], 1)
	binary.BigEndian.PutUint16(resp[6:], uint16(min(len(nsHosts), 0xFFFF)&0xFFFF))
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)

	offset := dnsHeaderSize
	qnameStart := dnsHeaderSize
	for qnameStart < len(queryPacket) && queryPacket[qnameStart] != 0 {
		labelLen := int(queryPacket[qnameStart])
		resp[offset] = queryPacket[qnameStart]
		offset++
		copy(resp[offset:], queryPacket[qnameStart+1:qnameStart+1+labelLen])
		offset += labelLen
		qnameStart += 1 + labelLen
	}
	resp[offset] = 0
	offset++

	binary.BigEndian.PutUint16(resp[offset:], 2)
	offset += 2
	binary.BigEndian.PutUint16(resp[offset:], dnsClassINET)
	offset += 2

	for _, ns := range nsHosts {
		resp[offset] = 0xC0
		resp[offset+1] = byte(dnsHeaderSize)
		offset += 2

		binary.BigEndian.PutUint16(resp[offset:], 2)
		offset += 2
		binary.BigEndian.PutUint16(resp[offset:], dnsClassINET)
		offset += 2

		binary.BigEndian.PutUint32(resp[offset:], 3600)
		offset += 4

		rdataStart := offset
		offset += 2

		for label := range strings.SplitSeq(ns, ".") {
			resp[offset] = byte(min(len(label), 255) & 0xFF)
			offset++
			copy(resp[offset:], label)
			offset += len(label)
		}
		resp[offset] = 0
		offset++

		rdLen := offset - rdataStart - 2
		binary.BigEndian.PutUint16(resp[rdataStart:], uint16(min(rdLen, 0xFFFF)&0xFFFF))
	}

	return resp[:offset]
}

func buildNXDOMAINResponse(queryPacket []byte) []byte {
	var resp [dnsMaxPacketLen]byte
	copy(resp[:2], queryPacket[:2])

	flags := uint16(0x8183)
	binary.BigEndian.PutUint16(resp[2:], flags)

	binary.BigEndian.PutUint16(resp[4:], 1)
	binary.BigEndian.PutUint16(resp[6:], 0)
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)

	offset := dnsHeaderSize
	qnameStart := dnsHeaderSize
	for qnameStart < len(queryPacket) && queryPacket[qnameStart] != 0 {
		labelLen := int(queryPacket[qnameStart])
		resp[offset] = queryPacket[qnameStart]
		offset++
		copy(resp[offset:], queryPacket[qnameStart+1:qnameStart+1+labelLen])
		offset += labelLen
		qnameStart += 1 + labelLen
	}
	resp[offset] = 0
	offset++
	qnameStart++

	if qnameStart+4 <= len(queryPacket) {
		copy(resp[offset:offset+4], queryPacket[qnameStart:qnameStart+4])
		offset += 4
	}

	return resp[:offset]
}

func buildAResponse(queryPacket []byte, ipv4 string) []byte {
	var resp [dnsMaxPacketLen]byte
	copy(resp[:2], queryPacket[:2])

	flags := uint16(0x8180)
	binary.BigEndian.PutUint16(resp[2:], flags)

	binary.BigEndian.PutUint16(resp[4:], 1)
	binary.BigEndian.PutUint16(resp[6:], 1)
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)

	offset := dnsHeaderSize
	qnameStart := dnsHeaderSize
	for qnameStart < len(queryPacket) && queryPacket[qnameStart] != 0 {
		labelLen := int(queryPacket[qnameStart])
		resp[offset] = queryPacket[qnameStart]
		offset++
		copy(resp[offset:], queryPacket[qnameStart+1:qnameStart+1+labelLen])
		offset += labelLen
		qnameStart += 1 + labelLen
	}
	resp[offset] = 0
	offset++

	binary.BigEndian.PutUint16(resp[offset:], 1)
	offset += 2
	binary.BigEndian.PutUint16(resp[offset:], dnsClassINET)
	offset += 2

	resp[offset] = 0xC0
	resp[offset+1] = byte(dnsHeaderSize)
	offset += 2

	binary.BigEndian.PutUint16(resp[offset:], 1)
	offset += 2
	binary.BigEndian.PutUint16(resp[offset:], dnsClassINET)
	offset += 2

	binary.BigEndian.PutUint32(resp[offset:], 300)
	offset += 4

	binary.BigEndian.PutUint16(resp[offset:], 4)
	offset += 2

	ip := net.ParseIP(ipv4).To4()
	copy(resp[offset:], ip)
	offset += 4

	return resp[:offset]
}

func buildSOAResponse(queryPacket []byte, rcode uint8) []byte {
	var resp [dnsMaxPacketLen]byte
	copy(resp[:2], queryPacket[:2])

	resp[2] = 0x81
	resp[3] = 0x80 | (rcode & 0x0F)

	binary.BigEndian.PutUint16(resp[4:], 1)
	binary.BigEndian.PutUint16(resp[6:], 0)
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)

	offset := dnsHeaderSize
	qnameStart := dnsHeaderSize
	for qnameStart < len(queryPacket) && queryPacket[qnameStart] != 0 {
		labelLen := int(queryPacket[qnameStart])
		resp[offset] = queryPacket[qnameStart]
		offset++
		copy(resp[offset:], queryPacket[qnameStart+1:qnameStart+1+labelLen])
		offset += labelLen
		qnameStart += 1 + labelLen
	}
	resp[offset] = 0
	offset++

	copy(resp[offset:], queryPacket[len(queryPacket)-4:])
	offset += 4

	return resp[:offset]
}

func TestPerformDirectSOAQuery_Success(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		resp := buildSOAResponse(query, 0)
		mustWriteTo(t, conn, resp, remote)
	})
	defer cleanup()

	rcode, err := performDirectSOAQuery(context.Background(), "example.com", "ns.example.com", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != 0 {
		t.Errorf("expected rcode 0, got %d", rcode)
	}
}

func TestPerformDirectSOAQuery_SERVFAIL(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		resp := buildSOAResponse(query, rcodeServfail)
		mustWriteTo(t, conn, resp, remote)
	})
	defer cleanup()

	rcode, err := performDirectSOAQuery(context.Background(), "example.com", "ns.example.com", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != rcodeServfail {
		t.Errorf("expected rcode %d, got %d", rcodeServfail, rcode)
	}
}

func TestPerformDirectSOAQuery_Timeout(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(_ []byte, _ net.Addr, _ *net.UDPConn) {
	})
	defer cleanup()

	origPreflightTimeout := resolver.PreflightTimeout
	resolver.PreflightTimeout = 10 * time.Millisecond
	defer func() { resolver.PreflightTimeout = origPreflightTimeout }()

	_, err := performDirectSOAQuery(context.Background(), "example.com", "ns.example.com", addr)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestPerformDirectSOAQuery_ConnectionRefused(t *testing.T) {
	_, err := performDirectSOAQuery(context.Background(), "example.com", "ns.example.com", "127.0.0.1:54321")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected non-timeout read error, got timeout: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to read") && !strings.Contains(err.Error(), "failed to send") {
		t.Errorf("expected read or send error, got: %v", err)
	}
}

func TestPerformDirectSOAQuery_ShortResponse(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(_ []byte, remote net.Addr, conn *net.UDPConn) {
		mustWriteTo(t, conn, []byte{0x00, 0x01}, remote)
	})
	defer cleanup()

	_, err := performDirectSOAQuery(context.Background(), "example.com", "ns.example.com", addr)
	if err == nil {
		t.Fatal("expected error for short response")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' error, got: %v", err)
	}
}

func TestPerformDirectSOAQuery_InvalidIP(t *testing.T) {
	_, err := performDirectSOAQuery(context.Background(), "example.com", "ns.example.com", "not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestPerformDirectSOAQuery_AllRCODEs(t *testing.T) {
	tests := []struct {
		name  string
		rcode uint8
	}{
		{strNoError, 0},
		{strServfail, rcodeServfail},
		{strNotimp, rcodeNotimp},
		{strRefused, rcodeRefused},
		{strNotauth, rcodeNotauth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
				resp := buildSOAResponse(query, tt.rcode)
				mustWriteTo(t, conn, resp, remote)
			})
			defer cleanup()

			rcode, err := performDirectSOAQuery(context.Background(), "example.com", "ns.example.com", addr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rcode != tt.rcode {
				t.Errorf("expected rcode %d, got %d", tt.rcode, rcode)
			}
		})
	}
}

func TestFetchNSRecords_RetryOnTimeout(t *testing.T) {
	var mu sync.Mutex
	callCount := 0

	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		mu.Lock()
		callCount++
		current := callCount
		mu.Unlock()

		if current <= 2 {
			return
		}

		resp := buildNSResponse(query, []string{"ns1.example.edu", "ns2.example.edu"})
		mustWriteTo(t, conn, resp, remote)
	})
	defer cleanup()

	overridePlainServers = []string{addr, addr, addr, addr, addr}
	defer func() { overridePlainServers = nil }()

	origMax := resolver.MaxRetriesPreflight
	origTimeout := resolver.PreflightTimeout

	resolver.MaxRetriesPreflight = 5
	resolver.PreflightTimeout = 10 * time.Millisecond
	defer func() {
		resolver.MaxRetriesPreflight = origMax
		resolver.PreflightTimeout = origTimeout
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := fetchNSRecords(ctx, "sub.example.com", "example.com")
	if err != nil {
		t.Fatalf("fetchNSRecords failed despite retry: %v", err)
	}
}

func TestResolveNSAddress_Success(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		resp := buildAResponse(query, "192.0.2.100")
		mustWriteTo(t, conn, resp, remote)
	})
	defer cleanup()

	overridePlainServers = []string{addr}
	defer func() { overridePlainServers = nil }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := resolveNSAddress(ctx, "sub.example.com", "ns1.example.com")
	if err != nil {
		t.Fatalf("resolveNSAddress failed: %v", err)
	}
	if ip != "192.0.2.100" {
		t.Errorf("expected IP 192.0.2.100, got %s", ip)
	}
}

func TestPerformDirectSOAQuery_REFUSED(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		resp := buildSOAResponse(query, rcodeRefused)
		mustWriteTo(t, conn, resp, remote)
	})
	defer cleanup()

	rcode, err := performDirectSOAQuery(context.Background(), "example.com", "ns.example.com", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != rcodeRefused {
		t.Errorf("expected rcode %d, got %d", rcodeRefused, rcode)
	}
	if !isBrokenZone(rcode) {
		t.Error("REFUSED should be detected as broken zone")
	}
}

func TestResolveNSAddress_AllFailed(t *testing.T) {
	overridePlainServers = []string{"127.0.0.2:0"}
	defer func() { overridePlainServers = nil }()

	ctx := context.Background()
	_, err := resolveNSAddress(ctx, "sub.example.com", "ns1.example.com")
	if err == nil {
		t.Fatal("expected error when all resolution attempts fail")
	}
}

func TestResolveNSAddress_NotFound(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		mustWriteTo(t, conn, buildNXDOMAINResponse(query), remote)
	})
	defer cleanup()

	overridePlainServers = []string{addr}
	defer func() { overridePlainServers = nil }()

	ctx := context.Background()
	_, err := resolveNSAddress(ctx, "sub.example.com", "ns1.notfound.example")
	if err == nil {
		t.Fatal("expected error when resolution returns NXDOMAIN")
	}
}

func TestFetchNSRecords_AllFailed(t *testing.T) {
	overridePlainServers = []string{"127.0.0.3:0"}
	defer func() { overridePlainServers = nil }()

	ctx := context.Background()
	_, err := fetchNSRecords(ctx, "sub.example.com", "example.com")
	if err == nil {
		t.Fatal("expected error when all NS fetches fail")
	}
}

func TestDoPreFlightCheck_FetchNSError(t *testing.T) {
	overridePlainServers = []string{"127.0.0.4:0"}
	defer func() { overridePlainServers = nil }()

	err := doPreFlightCheck(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error from doPreFlightCheck")
	}
}

func TestDoPreFlightCheck_NoNSRecords(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		resp := buildNSResponse(query, []string{})
		mustWriteTo(t, conn, resp, remote)
	})
	defer cleanup()

	overridePlainServers = []string{addr}
	defer func() { overridePlainServers = nil }()

	err := doPreFlightCheck(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "DNS zone is broken") {
		t.Fatalf("expected 'DNS zone is broken' error, got: %v", err)
	}
}

func TestDoPreFlightCheck_AllResolveFail(t *testing.T) {
	callCount := 0
	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		callCount++
		if callCount == 1 {
			mustWriteTo(t, conn, buildNSResponse(query, []string{"ns1.test.example"}), remote)
		}
	})
	defer cleanup()

	overridePlainServers = []string{addr}
	defer func() { overridePlainServers = nil }()

	origTimeout := resolver.PreflightTimeout
	resolver.PreflightTimeout = 100 * time.Millisecond
	defer func() { resolver.PreflightTimeout = origTimeout }()

	err := doPreFlightCheck(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("expected nil when all NS resolutions fail, got: %v", err)
	}
}

func TestDoPreFlightCheck_AllSOAFail(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		qStr := string(query)
		if strings.Contains(qStr, "example") && !strings.Contains(qStr, "ns2") {
			mustWriteTo(t, conn, buildNSResponse(query, []string{"ns2.test.example"}), remote)
		} else if strings.Contains(qStr, "ns2") {
			mustWriteTo(t, conn, buildAResponse(query, "255.255.255.255"), remote)
		}
	})
	defer cleanup()

	overridePlainServers = []string{addr}
	defer func() { overridePlainServers = nil }()

	origTimeout := resolver.PreflightTimeout
	resolver.PreflightTimeout = 100 * time.Millisecond
	defer func() { resolver.PreflightTimeout = origTimeout }()

	origDial := dialUDP
	defer func() { dialUDP = origDial }()
	dialUDP = func(network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
		if raddr != nil && raddr.Port == 53 {
			return nil, errors.New("mock SOA failure")
		}
		return origDial(network, laddr, raddr)
	}

	domainChecks = sync.Map{}
	dnsQueryCache = sync.Map{}

	err := doPreFlightCheck(context.Background(), "timeout.example.com")
	if err != nil {
		t.Fatalf("expected nil when all SOA checks fail, got: %v", err)
	}
}

func TestDoPreFlightCheck_InvalidDomain(t *testing.T) {
	domainChecks = sync.Map{}

	err := doPreFlightCheck(context.Background(), "invalid_domain")
	if err == nil {
		t.Error("expected error for invalid domain")
	}
}
func TestCacheExpiry(t *testing.T) {
	dnsQueryCache = sync.Map{}

	key := cacheKey{domain: "expiry.example.com", nsIP: "203.0.113.1"}

	dnsQueryCache.Store(key, cacheValue{
		rcode:     0,
		timestamp: time.Now().Add(-cacheValidity - time.Second),
	})

	_, ok := loadFromCache(key)
	if ok {
		t.Error("expected cache miss for expired entry")
	}
}

func TestCacheCorruptValue(t *testing.T) {
	dnsQueryCache = sync.Map{}

	key := cacheKey{domain: "corrupt.example.com", nsIP: "192.0.2.99"}
	dnsQueryCache.Store(key, "not-a-cacheValue")

	_, ok := loadFromCache(key)
	if ok {
		t.Error("expected cache miss for corrupt value type")
	}
}

func TestBuildDNSQuery_SingleLabel(t *testing.T) {
	query := buildDNSQuery("com")
	if len(query) < dnsHeaderSize {
		t.Fatalf("query too short: %d bytes", len(query))
	}

	offset := dnsHeaderSize
	labelLen := int(query[offset])
	if labelLen != 3 {
		t.Errorf("expected label length 3, got %d", labelLen)
	}
	actual := string(query[offset+1 : offset+1+labelLen])
	if actual != "com" {
		t.Errorf("expected label 'com', got %q", actual)
	}
}

func TestBuildDNSQuery_EmptyDomain(t *testing.T) {
	query := buildDNSQuery("")
	if len(query) < dnsHeaderSize {
		t.Fatalf("query too short: %d bytes", len(query))
	}
}

func TestBuildDNSQuery_TrailingDot(t *testing.T) {
	q1 := buildDNSQuery("example.com")
	q2 := buildDNSQuery("example.com.")
	if len(q1) != len(q2) {
		t.Errorf("trailing dot should produce same length query: %d vs %d", len(q1), len(q2))
	}
}

func TestPreFlightCheck_Singleflight(t *testing.T) {
	domainChecks = sync.Map{}

	var wg sync.WaitGroup
	errChan := make(chan error, 20)

	for range 20 {
		wg.Go(func() {
			err := PreFlightCheck(context.Background(), "singleflight.example.com")
			errChan <- err
		})
	}

	wg.Wait()
	close(errChan)

	var firstErr error
	first := true
	for err := range errChan {
		if first {
			firstErr = err
			first = false
			continue
		}
		if (firstErr == nil) != (err == nil) {
			t.Errorf("singleflight inconsistency: first=%v, got=%v", firstErr, err)
		}
	}
}

func TestPreFlightCheck_TypeAssertionFail(t *testing.T) {
	domainChecks = sync.Map{}

	domainChecks.Store("typefail.example.com", "not-a-domainCheck")

	err := PreFlightCheck(context.Background(), "typefail.example.com")
	if err == nil {
		t.Error("expected error for bad type assertion")
	}
	if !strings.Contains(err.Error(), "unexpected cache type") {
		t.Errorf("expected type assertion error, got: %v", err)
	}
}

func TestIsBrokenZone_CompleteCoverage(t *testing.T) {
	tests := []struct {
		rcode    uint8
		expected bool
	}{
		{0, false},
		{1, false},
		{rcodeServfail, true},
		{3, false},
		{rcodeNotimp, true},
		{rcodeRefused, true},
		{6, false},
		{7, false},
		{8, false},
		{rcodeNotauth, true},
		{10, false},
		{15, false},
	}

	for _, tt := range tests {
		result := isBrokenZone(tt.rcode)
		if result != tt.expected {
			t.Errorf("isBrokenZone(%d) = %v, want %v", tt.rcode, result, tt.expected)
		}
	}
}

func TestBuildSOAResponseHelper(t *testing.T) {
	query := buildDNSQuery("example.com")
	resp := buildSOAResponse(query, 0)

	if len(resp) < dnsHeaderSize {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	rcode := resp[3] & 0x0F
	if rcode != 0 {
		t.Errorf("expected rcode 0, got %d", rcode)
	}
}

func TestBuildNSResponseHelper(t *testing.T) {
	query := buildDNSQuery("example.com")
	resp := buildNSResponse(query, []string{"ns1.example.com"})

	if len(resp) < dnsHeaderSize {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 1 {
		t.Errorf("expected 1 answer, got %d", ancount)
	}
}

func TestBuildAResponseHelper(t *testing.T) {
	query := buildDNSQuery("ns1.example.com")
	resp := buildAResponse(query, "192.0.2.1")

	if len(resp) < dnsHeaderSize {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 1 {
		t.Errorf("expected 1 answer, got %d", ancount)
	}
}

func TestBuildNXDOMAINResponseHelper(t *testing.T) {
	query := buildDNSQuery("example.com")
	resp := buildNXDOMAINResponse(query)

	if len(resp) < dnsHeaderSize {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	rcode := resp[3] & 0x0F
	if rcode != 3 {
		t.Errorf("expected rcode 3 (NXDOMAIN), got %d", rcode)
	}
}

func TestDoPreFlightCheck_CacheHits(t *testing.T) {
	addr, cleanup := startMockDNSServer(t, func(query []byte, remote net.Addr, conn *net.UDPConn) {
		if len(query) >= 4 {
			mustWriteTo(t, conn, buildNSResponse(query, []string{"localhost"}), remote)
		}
	})
	defer cleanup()
	overridePlainServers = []string{addr}
	defer func() { overridePlainServers = nil }()

	tests := []struct {
		domain    string
		ip        string
		rcode     uint8
		expectErr bool
	}{
		{"example.com", "127.0.0.1", 0, false},
		{"example.org", "127.0.0.1", 2, true},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			key := cacheKey{domain: tt.domain, nsIP: tt.ip}
			storeInCache(key, tt.rcode)
			defer dnsQueryCache.Delete(key)

			err := doPreFlightCheck(context.Background(), tt.domain)
			if tt.expectErr {
				if err == nil || !strings.Contains(err.Error(), "DNS zone is broken") {
					t.Fatalf("expected 'DNS zone is broken' error, got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected nil, got: %v", err)
				}
			}
		})
	}
}
