package preflightcheck

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func TestStripTrailingDot(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com.", "example.com"},
		{"example.com", "example.com"},
		{"sub.example.com.", "sub.example.com"},
		{"", ""},
		{".", ""},
		{"a.", "a"},
	}

	for _, tt := range tests {
		result := stripTrailingDot(tt.input)
		if result != tt.expected {
			t.Errorf("stripTrailingDot(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSplitDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"example.com", []string{"example", "com"}},
		{"sub.example.com", []string{"sub", "example", "com"}},
		{"a.b.c.example.com", []string{"a", "b", "c", "example", "com"}},
		{"example.com.", []string{"example", "com"}},
		{"com", []string{"com"}},
		{"", nil},
	}

	for _, tt := range tests {
		result := splitDomain(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("splitDomain(%q) length mismatch: got %d, want %d", tt.input, len(result), len(tt.expected))
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("splitDomain(%q)[%d] = %q, want %q", tt.input, i, result[i], tt.expected[i])
			}
		}
	}
}

func TestBuildDNSQuery_Structure(t *testing.T) {
	domain := "example.com"
	query := buildDNSQuery(domain)

	if len(query) < dnsHeaderSize {
		t.Fatalf("DNS query too short: %d bytes", len(query))
	}

	flags := binary.BigEndian.Uint16(query[2:4])
	rdFlag := (flags >> 8) & 0x1
	if rdFlag != 1 {
		t.Errorf("expected RD=1, got RD=%d (flags=0x%04X)", rdFlag, flags)
	}

	qdCount := binary.BigEndian.Uint16(query[4:6])
	if qdCount != 1 {
		t.Errorf("expected QDCOUNT=1, got %d", qdCount)
	}

	ancount := binary.BigEndian.Uint16(query[6:8])
	if ancount != 0 {
		t.Errorf("expected ANCOUNT=0, got %d", ancount)
	}

	nscount := binary.BigEndian.Uint16(query[8:10])
	if nscount != 0 {
		t.Errorf("expected NSCOUNT=0, got %d", nscount)
	}

	arcount := binary.BigEndian.Uint16(query[10:12])
	if arcount != 0 {
		t.Errorf("expected ARCOUNT=0, got %d", arcount)
	}

	qtype := binary.BigEndian.Uint16(query[len(query)-4 : len(query)-2])
	if qtype != dnsTypeSOA {
		t.Errorf("expected QTYPE=SOA(%d), got %d", dnsTypeSOA, qtype)
	}

	qclass := binary.BigEndian.Uint16(query[len(query)-2:])
	if qclass != dnsClassINET {
		t.Errorf("expected QCLASS=INET(%d), got %d", dnsClassINET, qclass)
	}
}

func TestBuildDNSQuery_DomainEncoding(t *testing.T) {
	domain := "test.example.com"
	query := buildDNSQuery(domain)

	offset := dnsHeaderSize
	expectedLabels := []string{"test", "example", "com"}

	for _, expectedLabel := range expectedLabels {
		if offset >= len(query) {
			t.Fatalf("query ended prematurely at offset %d", offset)
		}

		labelLen := int(query[offset])
		offset++

		if offset+labelLen > len(query) {
			t.Fatalf("label extends beyond query boundary")
		}

		actualLabel := string(query[offset : offset+labelLen])
		if actualLabel != expectedLabel {
			t.Errorf("label mismatch: got %q, want %q", actualLabel, expectedLabel)
		}
		offset += labelLen
	}

	if offset >= len(query) || query[offset] != 0 {
		t.Error("expected null terminator after domain labels")
	}
}

func TestBuildDNSQuery_DifferentDomains(t *testing.T) {
	domains := []string{
		"a.com",
		"sub.example.com",
		"a.b.c.d.example.com",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			query := buildDNSQuery(domain)
			if len(query) < dnsHeaderSize {
				t.Errorf("query for %s too short", domain)
			}

			flags := binary.BigEndian.Uint16(query[2:4])
			if (flags>>8)&0x1 != 1 {
				t.Errorf("RD flag not one for %s", domain)
			}
		})
	}
}

func TestCache_Functionality(t *testing.T) {
	key := cacheKey{domain: "test.com", nsIP: "1.2.3.4"}

	_, ok := loadFromCache(key)
	if ok {
		t.Error("expected cache miss for new key")
	}

	storeInCache(key, rcodeServfail)

	val, ok := loadFromCache(key)
	if !ok {
		t.Error("expected cache hit after store")
	}
	if val.rcode != rcodeServfail {
		t.Errorf("expected rcode %d, got %d", rcodeServfail, val.rcode)
	}
}

func TestCache_WithinValidityPeriod(t *testing.T) {
	key := cacheKey{domain: "valid.com", nsIP: "5.6.7.8"}

	storeInCache(key, 0)

	_, ok := loadFromCache(key)
	if !ok {
		t.Error("expected cache hit immediately after store")
	}

	time.Sleep(100 * time.Millisecond)

	_, ok = loadFromCache(key)
	if !ok {
		t.Error("expected cache hit within validity period")
	}
}

func TestCache_DifferentKeys(t *testing.T) {
	key1 := cacheKey{domain: "a.com", nsIP: "1.1.1.1"}
	key2 := cacheKey{domain: "a.com", nsIP: "2.2.2.2"}
	key3 := cacheKey{domain: "b.com", nsIP: "1.1.1.1"}

	storeInCache(key1, rcodeServfail)

	val1, ok := loadFromCache(key1)
	if !ok {
		t.Error("expected cache hit for key1")
	}
	if val1.rcode != rcodeServfail {
		t.Errorf("expected rcode %d for key1, got %d", rcodeServfail, val1.rcode)
	}

	_, ok = loadFromCache(key2)
	if ok {
		t.Error("expected cache miss for different IP")
	}

	_, ok = loadFromCache(key3)
	if ok {
		t.Error("expected cache miss for different domain")
	}
}

func TestCache_KeyIsolation(t *testing.T) {
	dnsQueryCache = sync.Map{}

	tests := []struct {
		name       string
		storeKey   cacheKey
		lookupKey  cacheKey
		storeRcode uint8
		expectHit  bool
	}{
		{
			name:       "same domain same IP",
			storeKey:   cacheKey{domain: "test.com", nsIP: "1.1.1.1"},
			lookupKey:  cacheKey{domain: "test.com", nsIP: "1.1.1.1"},
			storeRcode: rcodeServfail,
			expectHit:  true,
		},
		{
			name:       "same domain different IP",
			storeKey:   cacheKey{domain: "test.com", nsIP: "1.1.1.1"},
			lookupKey:  cacheKey{domain: "test.com", nsIP: "2.2.2.2"},
			storeRcode: rcodeServfail,
			expectHit:  false,
		},
		{
			name:       "different domain same IP",
			storeKey:   cacheKey{domain: "a.com", nsIP: "8.8.8.8"},
			lookupKey:  cacheKey{domain: "b.com", nsIP: "8.8.8.8"},
			storeRcode: 0,
			expectHit:  false,
		},
		{
			name:       "different domain different IP",
			storeKey:   cacheKey{domain: "x.com", nsIP: "3.3.3.3"},
			lookupKey:  cacheKey{domain: "y.com", nsIP: "4.4.4.4"},
			storeRcode: 3,
			expectHit:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storeInCache(tt.storeKey, tt.storeRcode)

			val, ok := loadFromCache(tt.lookupKey)
			if ok != tt.expectHit {
				t.Errorf("expected hit=%v, got ok=%v", tt.expectHit, ok)
			}

			if tt.expectHit && val.rcode != tt.storeRcode {
				t.Errorf("expected rcode %d, got %d", tt.storeRcode, val.rcode)
			}
		})
	}
}

func TestPreFlightCheck_EmptyBaseDomain(t *testing.T) {
	target := "this-domain.doesnotexist123"

	err := PreFlightCheck(context.Background(), target)
	if err == nil {
		t.Error("expected error for non-existent domain")
	}
}

func TestParseDNSResponse_RCODEExtraction(t *testing.T) {
	testCases := []struct {
		name      string
		rcode     uint8
		expectErr bool
	}{
		{"NOERROR", 0, false},
		{"FORMERR", 1, false},
		{"SERVFAIL", 2, true},
		{"NXDOMAIN", 3, false},
		{"NOTIMP", 4, true},
		{"REFUSED", 5, true},
		{"NOTAUTH", 9, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response := make([]byte, dnsHeaderSize)
			response[3] = tc.rcode

			rcode := response[3] & 0x0F
			if rcode != tc.rcode {
				t.Errorf("RCODE extraction failed: got %d, want %d", rcode, tc.rcode)
			}

			broken := isBrokenZone(rcode)
			if broken != tc.expectErr {
				t.Errorf("isBrokenZone detection mismatch for %s: got %v, want %v", tc.name, broken, tc.expectErr)
			}
		})
	}
}

func TestDNSQueryPacketSize(t *testing.T) {
	longDomain := "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.example.com"
	query := buildDNSQuery(longDomain)

	if len(query) > dnsMaxPacketLen {
		t.Errorf("query exceeds max packet size: %d > %d", len(query), dnsMaxPacketLen)
	}
}

func TestConcurrentPreFlightCheck_SameTarget(_ *testing.T) {
	target := "concurrent.test.com"

	var wg sync.WaitGroup
	errorsChan := make(chan error, 10)

	for range 10 {
		wg.Go(func() {
			err := PreFlightCheck(context.Background(), target)
			errorsChan <- err
		})
	}

	wg.Wait()
	close(errorsChan)

	for err := range errorsChan {
		if err == nil {
			return
		}
	}
}

func TestCacheValidityDuration(t *testing.T) {
	if cacheValidity < 5*time.Minute {
		t.Errorf("cache validity too short: %v", cacheValidity)
	}
}

func TestDNSTimeout(t *testing.T) {
	if dnsTimeout != 2*time.Second {
		t.Errorf("DNS timeout not 2 seconds: %v", dnsTimeout)
	}
}
