package domainsbycerts

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	srcCrtsh   = "src_crtsh"
	srcCrtshPG = "src_crtsh_pg"
	srcSpotter = "src_spotter"
)

const optTrue = "true"

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{strings.ToUpper("example.com"), "example.com"},
		{"*.example.com", "*.example.com"},
		{"  A.example.com  ", "a.example.com"},
		{strings.ToUpper("*.sub.example.com"), "*.sub.example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		got := normalizeDomain(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMatchesTargetIdentity(t *testing.T) {
	const (
		targetDomain  = "example.org"
		subdomain     = "a.example.org"
		wildcard      = "*.example.org"
		scopedEmail   = "user@alum.example.org"
		offTargetHost = "sub.example.net"
		offTargetMail = "admin@certmail.example.net"
	)

	tests := []struct {
		value    string
		target   string
		expected bool
	}{
		{subdomain, targetDomain, true},
		{wildcard, targetDomain, true},
		{scopedEmail, targetDomain, true},
		{targetDomain, targetDomain, true},
		{offTargetHost, targetDomain, false},
		{offTargetMail, targetDomain, false},
		{"", targetDomain, false},
	}

	for _, tt := range tests {
		got := matchesTargetIdentity(tt.value, tt.target)
		if got != tt.expected {
			t.Errorf("matchesTargetIdentity(%q, %q) = %v, want %v", tt.value, tt.target, got, tt.expected)
		}
	}
}

func setPgOpenDBMock(t *testing.T, mock func(dsn string) (QueryExecuter, error)) {
	t.Helper()
	original := pgOpenDB
	pgOpenDB = mock
	t.Cleanup(func() {
		pgOpenDB = original
	})
}

func TestClassifyMatchedIdentity(t *testing.T) {
	const (
		targetDomain   = "example.net"
		wildcardDomain = "*.example.net"
		deepSubdomain  = "deep.sub.example.net"
		scopedEmail    = "user@alum.example.net"
		quotedEmail    = "\"quoted\"@alum.example.net"
		invalidDomain  = "bad host.example.net"
	)

	tests := []struct {
		name         string
		value        string
		target       string
		wantKind     string
		wantValue    string
		wantAccepted bool
	}{
		{
			name:         "target domain",
			value:        targetDomain,
			target:       targetDomain,
			wantKind:     identityKindTarget,
			wantValue:    targetDomain,
			wantAccepted: true,
		},
		{
			name:         "wildcard subdomain",
			value:        wildcardDomain,
			target:       targetDomain,
			wantKind:     constants.TypeSubdomain,
			wantValue:    wildcardDomain,
			wantAccepted: true,
		},
		{
			name:         "regular subdomain",
			value:        strings.ToUpper(deepSubdomain),
			target:       targetDomain,
			wantKind:     constants.TypeSubdomain,
			wantValue:    deepSubdomain,
			wantAccepted: true,
		},
		{
			name:         "valid email",
			value:        scopedEmail,
			target:       targetDomain,
			wantKind:     constants.TypeEmail,
			wantValue:    scopedEmail,
			wantAccepted: true,
		},
		{
			name:         "invalid email extra is rejected",
			value:        quotedEmail,
			target:       targetDomain,
			wantAccepted: false,
		},
		{
			name:         "invalid domain is rejected",
			value:        invalidDomain,
			target:       targetDomain,
			wantAccepted: false,
		},
		{
			name:         "valid email but wrong target",
			value:        "admin@example.org",
			target:       targetDomain,
			wantAccepted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := classifyMatchedIdentity(tt.value, tt.target)
			if ok != tt.wantAccepted {
				t.Fatalf("classifyMatchedIdentity(%q, %q) accepted = %v, want %v", tt.value, tt.target, ok, tt.wantAccepted)
			}
			if !tt.wantAccepted {
				return
			}
			if got.kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", got.kind, tt.wantKind)
			}
			if got.value != tt.wantValue {
				t.Fatalf("value = %q, want %q", got.value, tt.wantValue)
			}
		})
	}
}

func TestParseCertTimestamp(t *testing.T) {
	tests := []struct {
		input  string
		isZero bool
	}{
		{"2026-05-06T12:07:45", false},
		{"2026-05-06T12:07:45Z", false},
		{"2026-05-06T12:07:45+03:00", false},
		{"2026-05-06 12:07:45", false},
		{"", true},
		{"invalid", true},
	}

	for _, tt := range tests {
		got := parseCertTimestamp(tt.input)
		if got.IsZero() != tt.isZero {
			t.Errorf("parseCertTimestamp(%q).IsZero() = %v, want %v", tt.input, got.IsZero(), tt.isZero)
		}
	}
}

func TestClassifyIdentities(t *testing.T) {
	const (
		targetDomain    = "example.com"
		wildcardDomain  = "*.example.com"
		subdomainA      = "a.example.com"
		subdomainB      = "b.example.com"
		deepSubdomain   = "deep.sub.example.com"
		offTargetDomain = "example.net"
		offTargetHost   = "sub.example.net"
		scopedEmail     = "user@alum.example.com"
		quotedEmail     = "\"quoted\"@alum.example.com"
		offTargetEmail  = "admin@certmail.example.org"
	)

	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	identities := []certificateIdentitySource{
		{value: targetDomain, source: srcCrtsh, NotAfter: future},
		{value: targetDomain, source: srcCrtsh, NotAfter: past},
		{value: wildcardDomain, source: srcCrtsh, NotAfter: future},
		{value: subdomainA, source: srcCrtsh, NotAfter: future},
		{value: strings.ToUpper(subdomainB), source: srcSpotter, NotAfter: past},
		{value: subdomainA, source: srcSpotter, NotAfter: past},
		{value: offTargetDomain, source: srcCrtsh, NotAfter: future},
		{value: offTargetHost, source: srcCrtsh, NotAfter: future},
		{value: deepSubdomain, source: srcCrtsh, NotAfter: future},
		{value: scopedEmail, source: srcCrtshPG, NotAfter: future},
		{value: quotedEmail, source: srcCrtshPG, NotAfter: future},
		{value: offTargetEmail, source: srcCrtshPG, NotAfter: future},
	}

	classified := classifyIdentities(identities, targetDomain)

	if classified.targetMaxExpiry.Before(now) {
		t.Error("targetMaxExpiry should be in the future")
	}

	if len(classified.subdomains) != 4 {
		t.Errorf("expected 4 unique subdomains, got %d", len(classified.subdomains))
	}

	if got, ok := classified.subdomains[wildcardDomain]; !ok || !got.notAfter.Equal(future) {
		t.Errorf("%s: expected future timestamp, got %+v", wildcardDomain, got)
	}

	if got, ok := classified.subdomains[subdomainA]; !ok || !got.notAfter.Equal(future) {
		t.Errorf("%s: expected future timestamp, got %+v", subdomainA, got)
	}

	if got, ok := classified.subdomains[subdomainB]; !ok || !got.notAfter.Equal(past) {
		t.Errorf("%s: expected past timestamp, got %+v", subdomainB, got)
	}

	if _, ok := classified.subdomains[offTargetDomain]; ok {
		t.Error("off-target domain should not be classified as a subdomain")
	}

	if len(classified.emails) != 1 {
		t.Errorf("expected 1 valid email, got %d", len(classified.emails))
	}

	if got, ok := classified.emails[scopedEmail]; !ok || !got.notAfter.Equal(future) {
		t.Errorf("%s: expected future timestamp, got %+v", scopedEmail, got)
	}
}

func TestFormatResults_CertExpiredFiltering(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	classified := classifiedIdentities{
		subdomains: map[string]classifiedIdentity{
			"active.example.com":  {notAfter: future, source: srcCrtsh},
			"expired.example.com": {notAfter: past, source: srcCrtsh},
			"unknown.example.com": {source: srcCrtsh},
		},
		emails: map[string]classifiedIdentity{
			"active@alum.example.com":  {notAfter: future, source: srcCrtshPG},
			"expired@alum.example.com": {notAfter: past, source: srcCrtshPG},
		},
		targetMaxExpiry: future,
		targetSource:    srcCrtsh,
	}

	results := formatResults(classified, false, modutil.NewLocalIDGenerator())

	var subdomains, emails, certExpired, certNotAfter, emailNotAfter, statuses int
	for _, r := range results {
		switch r.Type {
		case constants.TypeSubdomain:
			subdomains++
		case constants.TypeEmail:
			emails++
		case constants.TypeCertExpiredSubdomains:
			certExpired++
		case constants.TypeCertNotAfter:
			certNotAfter++
		case constants.TypeDomainCertNotAfter:
			emailNotAfter++
		case constants.TypeStatus:
			statuses++
		}
	}

	if subdomains != 2 {
		t.Errorf("with ghost filtering: expected 2 subdomain results, got %d", subdomains)
	}
	if emails != 2 {
		t.Errorf("with ghost filtering: expected 2 email results, got %d", emails)
	}
	if certExpired != 1 {
		t.Errorf("with ghost filtering: expected 1 cert_expired_subdomains result, got %d", certExpired)
	}
	if certNotAfter != 2 {
		t.Errorf("with ghost filtering: expected 2 cert_not_after results, got %d", certNotAfter)
	}
	if emailNotAfter != 2 {
		t.Errorf("with ghost filtering: expected 2 domain_cert_not_after results, got %d", emailNotAfter)
	}
	if statuses != 1 {
		t.Errorf("with ghost filtering: expected 1 status result, got %d", statuses)
	}
}

func TestFormatResults_DisableCertExpiredSubdomains(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	classified := classifiedIdentities{
		subdomains: map[string]classifiedIdentity{
			"active.example.com":  {notAfter: future, source: srcCrtsh},
			"expired.example.com": {notAfter: past, source: srcCrtsh},
		},
		emails: map[string]classifiedIdentity{
			"expired@alum.example.com": {notAfter: past, source: srcCrtshPG},
		},
		targetMaxExpiry: future,
		targetSource:    srcCrtsh,
	}

	results := formatResults(classified, true, modutil.NewLocalIDGenerator())

	var subdomains, emails, certExpired, certNotAfter, emailNotAfter, statuses int
	for _, r := range results {
		switch r.Type {
		case constants.TypeSubdomain:
			subdomains++
		case constants.TypeEmail:
			emails++
		case constants.TypeCertExpiredSubdomains:
			certExpired++
		case constants.TypeCertNotAfter:
			certNotAfter++
		case constants.TypeDomainCertNotAfter:
			emailNotAfter++
		case constants.TypeStatus:
			statuses++
		}
	}

	if subdomains != 2 {
		t.Errorf("with ghost disabled: expected 2 subdomain results, got %d", subdomains)
	}
	if emails != 1 {
		t.Errorf("with ghost disabled: expected 1 email result, got %d", emails)
	}
	if certExpired != 0 {
		t.Errorf("with ghost disabled: expected 0 cert_expired_subdomains results, got %d", certExpired)
	}
	if certNotAfter != 3 {
		t.Errorf("with ghost disabled: expected 3 cert_not_after results, got %d", certNotAfter)
	}
	if emailNotAfter != 1 {
		t.Errorf("with ghost disabled: expected 1 domain_cert_not_after result, got %d", emailNotAfter)
	}
	if statuses != 2 {
		t.Errorf("with ghost disabled: expected 2 status results, got %d", statuses)
	}
}

func TestFormatResults_WildcardSubdomain(t *testing.T) {
	future := time.Now().Add(30 * 24 * time.Hour)
	classified := classifiedIdentities{
		subdomains: map[string]classifiedIdentity{
			"*.wild.example.com": {notAfter: future, source: srcCrtsh},
		},
		emails: make(map[string]classifiedIdentity),
	}

	results := formatResults(classified, false, modutil.NewLocalIDGenerator())
	wildcard := findDomainCertResult(results, constants.TypeSubdomain, "wild.example.com")
	if wildcard == nil {
		t.Fatalf("expected normalized wildcard subdomain result, got %+v", results)
	}
	if !slices.Contains(wildcard.Tags, constants.TagWildcard) {
		t.Fatalf("expected wildcard tag, got %+v", wildcard.Tags)
	}
	if wildcard.Context != "*.wild.example.com" {
		t.Fatalf("expected full wildcard context, got %q", wildcard.Context)
	}

	certDate := findDomainCertResult(results, constants.TypeCertNotAfter, future.Format(time.DateTime))
	if certDate == nil || certDate.Source == nil {
		t.Fatalf("expected certificate date sourced from wildcard, got %+v", certDate)
	}
	if certDate.Source.Type != constants.TypeSubdomain || certDate.Source.Value != "wild.example.com" {
		t.Fatalf("expected certificate date source to use normalized wildcard, got %+v", certDate.Source)
	}
}

func findDomainCertResult(results []schema.ModuleResult, resultType, value string) *schema.ModuleResult {
	for i := range results {
		if results[i].Type == resultType && results[i].Value == value {
			return &results[i]
		}
	}

	return nil
}

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(caps.Functions) != 1 || caps.Functions[0] != constants.FuncGetDomains {
		t.Fatalf("expected 1 function %s, got %v", constants.FuncGetDomains, caps.Functions)
	}
}

func TestModule_Name(t *testing.T) {
	mod := New()
	if name := mod.Name(); name != "domainsbycerts" {
		t.Errorf("expected name %q, got %q", "domainsbycerts", name)
	}
}

func TestModule_Exec(t *testing.T) {
	mod := New()

	inputUnsupported := schema.ModuleInput{
		Functions: []string{"unsupported_func"},
		Target: schema.Entity{
			Type:  constants.TypeDomain,
			Value: "unsupported.example",
		},
	}
	out, err := mod.Exec(inputUnsupported)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}
	if out.Executions[0].Error == nil || !strings.Contains(*out.Executions[0].Error, "unsupported function") {
		t.Errorf("expected unsupported function error, got %v", out.Executions[0].Error)
	}

	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte(`[]`)); writeErr != nil {
			panic(writeErr)
		}
	})

	originalCertspotterBaseURL := certspotterBaseURL
	certspotterBaseURL = mockServer.URL
	t.Cleanup(func() { certspotterBaseURL = originalCertspotterBaseURL })

	originalCrtshBaseURL := crtshBaseURL
	crtshBaseURL = mockServer.URL
	t.Cleanup(func() { crtshBaseURL = originalCrtshBaseURL })
	setPgOpenDBMock(t, func(_ string) (QueryExecuter, error) {
		return nil, errors.New("mock pg err")
	})

	inputSupported := schema.ModuleInput{
		Functions: []string{constants.FuncGetDomains},
		Target: schema.Entity{
			Type:  constants.TypeDomain,
			Value: "supported.example",
		},
	}
	out, err = mod.Exec(inputSupported)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}
}

func TestFormatResults_ExpiredTarget(t *testing.T) {
	past := time.Now().Add(-30 * 24 * time.Hour)

	classified := classifiedIdentities{
		subdomains:      make(map[string]classifiedIdentity),
		emails:          make(map[string]classifiedIdentity),
		targetMaxExpiry: past,
		targetSource:    srcCrtsh,
	}

	results := formatResults(classified, false, modutil.NewLocalIDGenerator())

	if len(results) > 0 {
		t.Errorf("expected 0 results for expired target, got %d", len(results))
	}
}

func TestFormatResults_EmailWithoutDate(t *testing.T) {
	classified := classifiedIdentities{
		subdomains: make(map[string]classifiedIdentity),
		emails: map[string]classifiedIdentity{
			"admin@example.com": {
				source: newCrtshFetcher().Name(),
			},
		},
		targetSource: srcSpotter,
	}

	results := formatResults(classified, false, modutil.NewLocalIDGenerator())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Type != constants.TypeEmail || results[0].Value != "admin@example.com" {
		t.Errorf("expected email result, got: %+v", results[0])
	}
}

func TestCollectAllIdentities_DisabledFetchers(t *testing.T) {
	resolver.Options["DisableCertspotter"] = optTrue
	resolver.Options["DisableCrtshPG"] = optTrue
	defer delete(resolver.Options, "DisableCertspotter")
	defer delete(resolver.Options, "DisableCrtshPG")

	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte(`[{"name_value":"disabled.example.com"}]`)); writeErr != nil {
			panic(writeErr)
		}
	})

	originalCrtshBaseURL := crtshBaseURL
	crtshBaseURL = mockServer.URL
	t.Cleanup(func() { crtshBaseURL = originalCrtshBaseURL })

	identities := collectAllIdentities(context.Background(), "example.com")

	if len(identities.identities) == 0 {
		t.Errorf("expected identities, got 0")
	}

	found := false
	for _, id := range identities.identities {
		if id.value == "disabled.example.com" && id.source == newCrtshFetcher().Name() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find disabled.example.com from crtsh, got: %+v", identities.identities)
	}
}

func TestModule_LocalIDChaining(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte(`[{"name_value":"a.example.com\nb.example.com","dns_names":["a.example.com", "b.example.com"], "not_after": "2099-01-01T00:00:00"}]`)); writeErr != nil {
			panic(writeErr)
		}
	})

	originalCertspotterBaseURL := certspotterBaseURL
	certspotterBaseURL = mockServer.URL
	t.Cleanup(func() { certspotterBaseURL = originalCertspotterBaseURL })

	originalCrtshBaseURL := crtshBaseURL
	crtshBaseURL = mockServer.URL
	t.Cleanup(func() { crtshBaseURL = originalCrtshBaseURL })
	setPgOpenDBMock(t, func(_ string) (QueryExecuter, error) {
		return nil, errors.New("mock pg err")
	})
	resolver.Options["DisableCertExpiredSubdomains"] = optTrue
	defer delete(resolver.Options, "DisableCertExpiredSubdomains")

	exec := getDomains("example.com")

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %s", *exec.Error)
	}

	if len(exec.Results) < 2 {
		t.Fatalf("Expected multiple results, got %d: %+v", len(exec.Results), exec.Results)
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func requireUniqueLocalIDs(t *testing.T, results []schema.ModuleResult) {
	seen := make(map[int]bool)
	for _, res := range results {
		if res.LocalID <= 0 {
			t.Errorf("expected positive LocalID, got %d for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		if seen[res.LocalID] {
			t.Errorf("duplicate LocalID %d found for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		seen[res.LocalID] = true

		if res.Source != nil {
			if res.Source.LocalID <= 0 {
				t.Errorf("expected positive LocalID in source, got %d", res.Source.LocalID)
			}
			if res.Source.LocalID >= res.LocalID {
				t.Errorf("expected source LocalID %d to be strictly less than result LocalID %d (Type: %s, Value: %s)", res.Source.LocalID, res.LocalID, res.Type, res.Value)
			}
		}
	}
}
