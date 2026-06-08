package hunterio

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const testAPIKey = "test_key"

func setupMockServer(t *testing.T, domainFixture string, domainStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/account", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(validAccountJSON)); err != nil {
			t.Logf("write failed: %v", err)
		}
	})
	if domainFixture != "" {
		mux.HandleFunc("/domain-search", func(w http.ResponseWriter, _ *http.Request) {
			data := loadHunterioFixture(t, domainFixture)
			w.WriteHeader(domainStatus)
			if _, err := w.Write(data); err != nil {
				t.Logf("write failed: %v", err)
			}
		})
	}
	return httptest.NewServer(mux)
}

const validAccountJSON = `{"data": {"requests": {"searches": {"used": 10, "available": 1000}}}}`

func loadHunterioFixture(t *testing.T, filename string) []byte {
	t.Helper()
	var data []byte
	var err error
	switch filename {
	case "domain_search_pagination_page1.json":
		data, err = os.ReadFile("testdata/domain_search_pagination_page1.json")
	case "domain_search_pagination_page2.json":
		data, err = os.ReadFile("testdata/domain_search_pagination_page2.json")
	case "domain_search_b2b.json":
		data, err = os.ReadFile("testdata/domain_search_b2b.json")
	case "domain_search_b2b_single_profile.json":
		data, err = os.ReadFile("testdata/domain_search_b2b_single_profile.json")
	case "domain_search_empty_ghost.json":
		data, err = os.ReadFile("testdata/domain_search_empty_ghost.json")
	case "domain_search_tempmail.json":
		data, err = os.ReadFile("testdata/domain_search_tempmail.json")
	case "domain_search_publicmail.json":
		data, err = os.ReadFile("testdata/domain_search_publicmail.json")
	case "domain_search_accept_all.json":
		data, err = os.ReadFile("testdata/domain_search_accept_all.json")
	case "domain_search_restricted_account.json":
		data, err = os.ReadFile("testdata/domain_search_restricted_account.json")
	default:
		t.Fatalf("unsupported fixture %s", filename)
	}
	if err != nil {
		t.Fatalf("failed to read testdata %s: %v", filename, err)
	}
	return data
}

func overrideBaseURL(t *testing.T, serverURL string) {
	t.Helper()
	original := hunterioAPIBaseURL
	hunterioAPIBaseURL = serverURL
	t.Cleanup(func() { hunterioAPIBaseURL = original })
}

func overrideLimits(t *testing.T, limit, maxPages int) {
	t.Helper()
	origLimit := resolver.HunterioLimit
	origPages := resolver.HunterioMaxPages
	resolver.HunterioLimit = limit
	resolver.HunterioMaxPages = maxPages
	t.Cleanup(func() {
		resolver.HunterioLimit = origLimit
		resolver.HunterioMaxPages = origPages
	})
}

func overrideRetries(t *testing.T, retries int) {
	t.Helper()
	orig := resolver.HunterioMaxRetries
	resolver.HunterioMaxRetries = retries
	t.Cleanup(func() { resolver.HunterioMaxRetries = orig })
}

func findResultsByType(results []schema.ModuleResult, entityType string) []schema.ModuleResult {
	var found []schema.ModuleResult
	for _, r := range results {
		if r.Type == entityType {
			found = append(found, r)
		}
	}
	return found
}

func findResultByTypeValue(results []schema.ModuleResult, entityType, value string) *schema.ModuleResult {
	for i := range results {
		if results[i].Type == entityType && results[i].Value == value {
			return &results[i]
		}
	}
	return nil
}

func TestGetDomainSearch_Pagination(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/account", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(validAccountJSON)); err != nil {
			t.Logf("write failed: %v", err)
		}
	})

	mux.HandleFunc("/domain-search", func(w http.ResponseWriter, r *http.Request) {
		offset := r.URL.Query().Get("offset")
		var data []byte
		if offset == "0" {
			data = loadHunterioFixture(t, "domain_search_pagination_page1.json")
		} else {
			data = loadHunterioFixture(t, "domain_search_pagination_page2.json")
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(data); err != nil {
			t.Logf("write failed: %v", err)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	overrideBaseURL(t, server.URL)
	overrideLimits(t, 10, 2)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "example.com")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
	}

	emails := findResultsByType(exec.Results, constants.TypeEmail)
	if len(emails) != 14 {
		t.Errorf("expected 14 emails from pagination, got %d", len(emails))
	}
}

func TestGetDomainSearch_B2BFullProfile(t *testing.T) {
	server := setupMockServer(t, "domain_search_b2b.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "enterprise-b2b.example.net")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
	}

	if findResultByTypeValue(exec.Results, constants.TypeOrganization, "Enterprise B2B Corporation") == nil {
		t.Errorf("missing organization")
	}

	pattern := findResultsByType(exec.Results, constants.TypeEmailPattern)
	if len(pattern) == 0 || pattern[0].Value != "{first}.{last}" {
		t.Errorf("missing or wrong email pattern")
	}

	validateB2BEmails(t, exec.Results)
	validateB2BPersons(t, exec.Results)
	validateB2BProperties(t, exec.Results)
	validateB2BSources(t, exec.Results)

	if exec.RawData == "" {
		t.Errorf("expected non-empty RawData")
	}
}

func validateB2BEmails(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	emails := findResultsByType(results, constants.TypeEmail)
	if len(emails) != 3 {
		t.Errorf("expected 3 emails, got %d", len(emails))
	}

	aliceEmail := findResultByTypeValue(results, constants.TypeEmail, "alice.director@enterprise-b2b.example.net")
	if aliceEmail == nil {
		t.Errorf("missing alice email")
	}

	supportEmail := findResultByTypeValue(results, constants.TypeEmail, "support-team@enterprise-b2b.example.net")
	if supportEmail == nil {
		t.Errorf("missing support email")
	}
}

func validateB2BPersons(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	if findResultByTypeValue(results, constants.TypePerson, "Alice Director") == nil {
		t.Errorf("missing person Alice Director")
	}

	if findResultByTypeValue(results, constants.TypePerson, "Bob Intern") == nil {
		t.Errorf("missing person Bob Intern")
	}

	persons := findResultsByType(results, constants.TypePerson)
	if len(persons) != 2 {
		t.Errorf("expected 2 persons (alice, bob), got %d", len(persons))
	}
}

func requireCountByType(t *testing.T, results []schema.ModuleResult, resultType string, count int) {
	t.Helper()
	actual := 0
	for _, r := range results {
		if r.Type == resultType {
			actual++
		}
	}
	if actual != count {
		t.Errorf("expected %d info properties with type %q, got %d", count, resultType, actual)
	}
}

func validateB2BProperties(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	requireCountByType(t, results, constants.TypePosition, 2)
	requireCountByType(t, results, constants.TypeDepartment, 3)
	requireCountByType(t, results, constants.TypeSeniority, 2)
	requireCountByType(t, results, constants.TypeConfidenceScore, 3)
	requireCountByType(t, results, constants.TypeVerificationStatus, 3)
}

func validateB2BSources(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	phones := findResultsByType(results, constants.TypePhone)
	if len(phones) != 1 || phones[0].Value != "+1 800 555 0199" {
		t.Errorf("expected 1 phone +1 800 555 0199, got %v", phones)
	}
	validateB2BSocial(t, results)
	validateB2BLinkedDomains(t, results)
	validateB2BSourceRefs(t, results)
}

func validateB2BSocial(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	urls := findResultsByType(results, constants.TypeURL)
	const ctxLinkedIn = "LinkedIn"
	hasLinkedin, hasTwitter := false, false
	for _, u := range urls {
		if u.Context == ctxLinkedIn && u.Value == "https://www.linkedin.com/in/alicedirector-example" {
			hasLinkedin = true
			if !slices.Contains(u.Tags, constants.TagSocial) {
				t.Errorf("LinkedIn URL missing TagSocial")
			}
		}
		if u.Context == "Twitter" && u.Value == "https://twitter.com/alice_tech_example" {
			hasTwitter = true
			if !slices.Contains(u.Tags, constants.TagSocial) {
				t.Errorf("Twitter URL missing TagSocial")
			}
		}
	}
	if !hasLinkedin {
		t.Errorf("missing LinkedIn URL")
	}
	if !hasTwitter {
		t.Errorf("missing Twitter URL")
	}
}

func validateB2BLinkedDomains(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	linked := []schema.ModuleResult{}
	for _, r := range results {
		if r.Type == constants.TypeDomain && slices.Contains(r.Tags, constants.TagLinked) {
			linked = append(linked, r)
		}
	}
	if len(linked) != 2 {
		t.Errorf("expected 2 linked domains, got %d", len(linked))
	}
	for _, ld := range linked {
		if !ld.Applied || !slices.Contains(ld.Tags, constants.TagLinked) {
			t.Errorf("linked domain %q should be applied and tagged linked", ld.Value)
		}
	}
}

func validateB2BSourceRefs(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	sourceURLs := []schema.ModuleResult{}
	for _, r := range results {
		if r.Type == constants.TypeURL && r.Source != nil && r.Source.Type == constants.TypeSource {
			sourceURLs = append(sourceURLs, r)
		}
	}
	if len(sourceURLs) != 3 {
		t.Errorf("expected 3 source URLs, got %d", len(sourceURLs))
	}

	validateB2BSourceDomains(t, results)

	extractedDates := []schema.ModuleResult{}
	for _, r := range results {
		if r.Type == constants.TypeDate && strings.HasPrefix(r.Value, "Extracted on: ") {
			extractedDates = append(extractedDates, r)
		}
	}
	if len(extractedDates) != 3 {
		t.Errorf("expected 3 extracted on dates, got %d", len(extractedDates))
	}
}

func validateB2BSourceDomains(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	sourceDomains := []schema.ModuleResult{}
	for _, r := range results {
		if r.Type == constants.TypeDomain && r.Source != nil && (r.Source.Type == constants.TypeURL || r.Source.Type == constants.TypeSource) {
			sourceDomains = append(sourceDomains, r)
		}
	}
	if len(sourceDomains) != 3 {
		t.Errorf("expected 3 source domains, got %d", len(sourceDomains))
	}
	for _, sd := range sourceDomains {
		if sd.Value == "enterprise-b2b.example.net" {
			if sd.OutOfScope {
				t.Errorf("source domain %q should have OutOfScope=false", sd.Value)
			}
		} else {
			if !sd.OutOfScope {
				t.Errorf("source domain %q should have OutOfScope=true", sd.Value)
			}
		}
	}
}

func TestGetDomainSearch_StrictCorp(t *testing.T) {
	server := setupMockServer(t, "domain_search_b2b_single_profile.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "strict-corp.example.com")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
	}

	if findResultByTypeValue(exec.Results, constants.TypeOrganization, "Strict Corporation") == nil {
		t.Errorf("missing organization Strict Corporation")
	}

	pattern := findResultsByType(exec.Results, constants.TypeEmailPattern)
	if len(pattern) == 0 || pattern[0].Value != "{first}" {
		t.Errorf("missing or wrong email pattern")
	}

	if findResultByTypeValue(exec.Results, constants.TypeEmail, "alice@strict-corp.example.com") == nil {
		t.Errorf("missing email alice@strict-corp.example.com")
	}

	if findResultByTypeValue(exec.Results, constants.TypePerson, "Alice Smith") == nil {
		t.Errorf("missing person Alice Smith")
	}

	urls := findResultsByType(exec.Results, constants.TypeURL)
	hasLinkedin := false
	for _, u := range urls {
		if u.Context == "LinkedIn" {
			hasLinkedin = true
		}
	}
	if !hasLinkedin {
		t.Errorf("missing LinkedIn URL")
	}

	phones := findResultsByType(exec.Results, constants.TypePhone)
	if len(phones) != 1 {
		t.Errorf("expected 1 phone, got %d", len(phones))
	}
}

func TestGetDomainSearch_GenericEmailNoPerson(t *testing.T) {
	server := setupMockServer(t, "domain_search_empty_ghost.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "stealth-startup.example.io")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
	}

	emails := findResultsByType(exec.Results, constants.TypeEmail)
	if len(emails) != 0 {
		t.Errorf("expected 0 emails, got %d", len(emails))
	}

	persons := findResultsByType(exec.Results, constants.TypePerson)
	if len(persons) != 0 {
		t.Errorf("expected 0 persons for empty ghost, got %d", len(persons))
	}
}

func TestGetDomainSearch_Tempmail(t *testing.T) {
	server := setupMockServer(t, "domain_search_tempmail.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "example.com")

	if findResultByTypeValue(exec.Results, constants.TypeInfo, "Disposable Email Domain") == nil {
		t.Errorf("expected info %q not found", "Disposable Email Domain")
	}
}

func TestGetDomainSearch_PublicMail(t *testing.T) {
	server := setupMockServer(t, "domain_search_publicmail.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "example.com")

	if findResultByTypeValue(exec.Results, constants.TypeInfo, "Webmail Provider") == nil {
		t.Errorf("expected info %q not found", "Webmail Provider")
	}
}

func TestGetDomainSearch_AcceptAll(t *testing.T) {
	server := setupMockServer(t, "domain_search_b2b.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "example.com")

	if findResultByTypeValue(exec.Results, constants.TypeInfo, "Accept-All Domain") == nil {
		t.Errorf("expected info %q not found", "Accept-All Domain")
	}
}

func TestGetDomainSearch_RateLimitAsProperty(t *testing.T) {
	server := setupMockServer(t, "domain_search_restricted_account.json", http.StatusTooManyRequests)
	defer server.Close()

	overrideBaseURL(t, server.URL)
	overrideRetries(t, 1)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "example.com")

	if exec.Error != nil {
		t.Errorf("rate limit should not set exec.Error, got: %s", *exec.Error)
	}

	if findResultByTypeValue(exec.Results, constants.TypeInfo, "Your account was restricted. Please log in to Hunter for more information.") == nil {
		t.Errorf("expected parsed error details as info property")
	}

	if exec.RawData == "" {
		t.Errorf("expected RawData even on rate limit")
	}
}

func TestGetDomainSearch_PreflightFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/account", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(`{"errors": [{"details": "Invalid API key"}]}`)); err != nil {
			t.Logf("write failed: %v", err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "example.com")

	if exec.Error != nil {
		t.Errorf("preflight failure should not set exec.Error, got: %s", *exec.Error)
	}

	r := findResultByTypeValue(exec.Results, constants.TypeInfo, "Hunter.io API key is invalid")
	if r == nil {
		t.Errorf("expected info property for invalid key")
	} else if r.Category != constants.CategoryProperty {
		t.Errorf("expected category=%q, got %q", constants.CategoryProperty, r.Category)
	}
}

func TestGetDomainSearch_QuotaExceeded(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/account", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"data": {"requests": {"searches": {"used": 1000, "available": 1000}}}}`)); err != nil {
			t.Logf("write failed: %v", err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "example.com")

	if exec.Error != nil {
		t.Errorf("quota exceeded should not set exec.Error, got: %s", *exec.Error)
	}

	r := findResultByTypeValue(exec.Results, constants.TypeInfo, "Hunter.io API quota exceeded or credits exhausted")
	if r == nil {
		t.Errorf("expected info property for quota exceeded")
	} else if r.Category != constants.CategoryProperty {
		t.Errorf("expected category=%q, got %q", constants.CategoryProperty, r.Category)
	}
}

func TestModule_LocalIDChaining(t *testing.T) {
	server := setupMockServer(t, "domain_search_b2b.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "enterprise-b2b.example.net")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
	}

	if len(exec.Results) < 2 {
		t.Skip("Expected multiple results to verify chaining, skipping test")
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
