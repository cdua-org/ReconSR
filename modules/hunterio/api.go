package hunterio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dateutil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var hunterioAPIBaseURL = "https://api.hunter.io/v2"

// apiAccountResponse maps to the /v2/account endpoint response.
type apiAccountResponse struct {
	Data struct {
		Requests struct {
			Searches struct {
				Used      int `json:"used"`
				Available int `json:"available"`
			} `json:"searches"`
		} `json:"requests"`
	} `json:"data"`
}

type apiEmailSource struct {
	Domain      string `json:"domain"`
	URI         string `json:"uri"`
	ExtractedOn string `json:"extracted_on"`
	LastSeenOn  string `json:"last_seen_on"`
	StillOnPage bool   `json:"still_on_page"`
}

type apiEmailEntry struct {
	Verification struct {
		Date   string `json:"date"`
		Status string `json:"status"`
	} `json:"verification"`
	Department  string           `json:"department"`
	Type        string           `json:"type"`
	FirstName   string           `json:"first_name"`
	LastName    string           `json:"last_name"`
	Position    string           `json:"position"`
	Seniority   string           `json:"seniority"`
	Linkedin    string           `json:"linkedin"`
	Twitter     string           `json:"twitter"`
	PhoneNumber string           `json:"phone_number"`
	Value       string           `json:"value"`
	Sources     []apiEmailSource `json:"sources"`
	Confidence  int              `json:"confidence"`
}

// apiDomainSearchResponse maps to the /v2/domain-search endpoint response.
type apiDomainSearchResponse struct {
	Errors []struct {
		Details string `json:"details"`
	} `json:"errors"`
	Data struct {
		Domain        string          `json:"domain"`
		Pattern       string          `json:"pattern"`
		Organization  string          `json:"organization"`
		LinkedDomains []string        `json:"linked_domains"`
		Emails        []apiEmailEntry `json:"emails"`
		Disposable    bool            `json:"disposable"`
		Webmail       bool            `json:"webmail"`
		AcceptAll     bool            `json:"accept_all"`
	} `json:"data"`
	Meta struct {
		Results int `json:"results"`
	} `json:"meta"`
}

func (m *module) handlePreflightAPI(ctx context.Context) {
	if m.apiKey == "test-api-key" {
		dlog.Printf("%s skip stage=preflight reason=test_key", constants.FuncGetHunterioDomainSearch)
		m.queryCredits = 999999
		return
	}

	m.waitRateLimit()
	u := hunterioAPIBaseURL + "/account"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		dlog.Printf("%s error stage=preflight_create_request err=%v", constants.FuncGetHunterioDomainSearch, err)
		m.keyInvalid = true
		return
	}
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())
	req.Header.Set("X-API-Key", m.apiKey)

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		dlog.Printf("%s error stage=preflight_do_request err=%v", constants.FuncGetHunterioDomainSearch, err)
		m.keyInvalid = true
		return
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			dlog.Printf("%s body_close_failed err=%v", constants.FuncGetHunterioDomainSearch, cerr)
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		dlog.Printf("%s error stage=preflight_invalid_key status=%d", constants.FuncGetHunterioDomainSearch, resp.StatusCode)
		m.keyInvalid = true
		return
	default:
		dlog.Printf("%s error stage=preflight_status status=%d", constants.FuncGetHunterioDomainSearch, resp.StatusCode)
		m.keyInvalid = true
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		dlog.Printf("%s error stage=preflight_read_body err=%v", constants.FuncGetHunterioDomainSearch, err)
		m.keyInvalid = true
		return
	}

	var info apiAccountResponse
	if err := json.Unmarshal(body, &info); err == nil {
		m.queryCredits = info.Data.Requests.Searches.Available - info.Data.Requests.Searches.Used
		if m.queryCredits <= 0 {
			dlog.Printf("%s error stage=preflight_quota_exceeded", constants.FuncGetHunterioDomainSearch)
			m.quotaExceeded = true
		} else {
			dlog.Printf("%s success stage=preflight credits=%d", constants.FuncGetHunterioDomainSearch, m.queryCredits)
		}
	} else {
		dlog.Printf("%s error stage=preflight_parse err=%v", constants.FuncGetHunterioDomainSearch, err)
		m.keyInvalid = true
	}
}

func (m *module) getDomainSearch(ctx context.Context, targetType, targetValue string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetHunterioDomainSearch)
	gen := modutil.NewLocalIDGenerator()

	if m.apiKey == "demo-api-key" {
		return m.getDomainSearchDemo(&exec, targetType, targetValue, gen)
	}

	m.preflightOnce.Do(func() { m.handlePreflightAPI(ctx) })

	m.mu.Lock()
	credits := m.queryCredits
	m.mu.Unlock()

	if m.keyInvalid {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    "Hunter.io API key is invalid",
			LocalID:  gen.NextID(),
		})
		return exec
	}
	if m.quotaExceeded || credits <= 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    "Hunter.io API quota exceeded or credits exhausted",
			LocalID:  gen.NextID(),
		})
		return exec
	}

	limit, maxPages := getLimits()
	offset := 0
	var rawResponses []byte
	var allEmails []schema.ModuleResult
	var linkedDomains []string
	var domainForScope string

	for page := range maxPages {
		if page > 0 {
			time.Sleep(120 * time.Millisecond)
		} else {
			m.waitRateLimit()
		}

		respBody, statusCode, shouldBreak := m.fetchDomainPage(ctx, &exec, targetType, targetValue, limit, offset)
		if shouldBreak {
			rawResponses = appendRaw(rawResponses, respBody)
			break
		}

		rawResponses = appendRaw(rawResponses, respBody)

		if m.handlePageResponse(&exec, statusCode, respBody, gen) {
			break
		}

		var parsedResp apiDomainSearchResponse
		if err := json.Unmarshal(respBody, &parsedResp); err != nil {
			modutil.SetError(&exec, "json parse error: %v", err)
			break
		}

		if page == 0 {
			domainForScope = targetValue
			if targetType == constants.TypeOrganization && parsedResp.Data.Domain != "" {
				domainForScope = parsedResp.Data.Domain
			}
			appendDomainProperties(&exec, &parsedResp, gen)
			linkedDomains = append(linkedDomains, parsedResp.Data.LinkedDomains...)
		}

		allEmails = append(allEmails, extractEmails(&parsedResp, domainForScope, gen)...)

		dlog.Printf("%s success target=%q page=%d results=%d", constants.FuncGetHunterioDomainSearch, targetValue, page+1, parsedResp.Meta.Results)

		offset += limit
		if offset >= parsedResp.Meta.Results {
			break
		}
	}

	exec.Results = append(exec.Results, allEmails...)
	for _, ld := range linkedDomains {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       constants.TypeDomain,
			Value:      ld,
			Tags:       []string{constants.TagLinked},
			OutOfScope: orgdomain.IsOutOfScope(ld, domainForScope),
			Applied:    true,
			LocalID:    gen.NextID(),
		})
	}

	modutil.SetRawFromBytes(&exec, rawResponses)

	return exec
}

func (m *module) handlePageResponse(exec *schema.ModuleExecution, statusCode int, respBody []byte, gen *modutil.LocalIDGenerator) bool {
	if statusCode == http.StatusOK {
		m.mu.Lock()
		m.queryCredits--
		m.mu.Unlock()
	}

	if statusCode >= http.StatusInternalServerError {
		modutil.SetError(exec, "hunterio server error (retryable)", fmt.Errorf("%d", statusCode))
		return true
	} else if statusCode >= 400 {
		appendAPIErrorResult(exec, statusCode, respBody, gen)

		if statusCode == http.StatusTooManyRequests || statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			m.mu.Lock()
			m.queryCredits = 0
			m.quotaExceeded = true
			m.mu.Unlock()
		}
		return true
	}
	return false
}

func (m *module) fetchDomainPage(ctx context.Context, exec *schema.ModuleExecution, targetType, targetValue string, limit, offset int) (respBody []byte, statusCode int, shouldBreak bool) {
	parsedURL, err := buildURL(targetType, targetValue, limit, offset)
	if err != nil {
		modutil.SetError(exec, "parse url: %v", err)
		return nil, 0, true
	}

	respBody, statusCode, attemptErr := m.doPageRequest(ctx, parsedURL.String())
	if attemptErr != nil {
		modutil.SetError(exec, "request failed: %v", attemptErr)
		return respBody, 0, true
	}
	if respBody == nil {
		modutil.SetError(exec, "request failed after retries: %v", errors.New("no response"))
		return nil, 0, true
	}

	return respBody, statusCode, false
}

func appendRaw(dst, src []byte) []byte {
	if len(src) == 0 {
		return dst
	}
	dst = append(dst, src...)
	dst = append(dst, '\n')
	return dst
}

func appendAPIErrorResult(exec *schema.ModuleExecution, statusCode int, respBody []byte, gen *modutil.LocalIDGenerator) {
	userMsg := fmt.Sprintf("Hunter.io API error (HTTP %d)", statusCode)

	var searchErr apiDomainSearchResponse
	if err := json.Unmarshal(respBody, &searchErr); err == nil && len(searchErr.Errors) > 0 {
		userMsg = searchErr.Errors[0].Details
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    userMsg,
		LocalID:  gen.NextID(),
	})
}

func appendDomainProperties(exec *schema.ModuleExecution, parsedResp *apiDomainSearchResponse, gen *modutil.LocalIDGenerator) {
	if parsedResp.Data.Organization != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeOrganization,
			Category: constants.CategoryProperty,
			Value:    parsedResp.Data.Organization,
			LocalID:  gen.NextID(),
		})
	}
	if parsedResp.Data.Pattern != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeEmailPattern,
			Category: constants.CategoryProperty,
			Value:    parsedResp.Data.Pattern,
			LocalID:  gen.NextID(),
		})
	}
	if parsedResp.Data.Disposable {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    "Disposable Email Domain",
			LocalID:  gen.NextID(),
		})
	}
	if parsedResp.Data.Webmail {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    "Webmail Provider",
			LocalID:  gen.NextID(),
		})
	}
	if parsedResp.Data.AcceptAll {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    "Accept-All Domain",
			LocalID:  gen.NextID(),
		})
	}
}

func getLimits() (limit, maxPages int) {
	limit = resolver.HunterioLimit
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	maxPages = resolver.HunterioMaxPages
	if maxPages <= 0 {
		maxPages = 1
	}
	return limit, maxPages
}

func buildURL(targetType, targetValue string, limit, offset int) (*url.URL, error) {
	u := hunterioAPIBaseURL + "/domain-search"
	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("url parse error: %w", err)
	}
	q := parsedURL.Query()
	if targetType == constants.TypeOrganization {
		q.Set("company", targetValue)
	} else {
		q.Set("domain", targetValue)
	}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))

	if resolver.HunterioType != "" {
		q.Set("type", resolver.HunterioType)
	}
	if resolver.HunterioSeniority != "" {
		q.Set("seniority", resolver.HunterioSeniority)
	}
	if resolver.HunterioDepartment != "" {
		q.Set("department", resolver.HunterioDepartment)
	}

	parsedURL.RawQuery = q.Encode()
	return parsedURL, nil
}

func (m *module) doPageRequest(ctx context.Context, u string) (respBody []byte, statusCode int, attemptErr error) {
	for attempt := range resolver.HunterioMaxRetries {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		if err != nil {
			return nil, 0, fmt.Errorf("new request error: %w", err)
		}
		req.Header.Set("User-Agent", resolver.GetRandomUserAgent())
		req.Header.Set("X-API-Key", m.apiKey)

		client := &http.Client{Timeout: resolver.HTTPTimeout}
		resp, err := client.Do(req)
		if err != nil {
			dlog.Printf("%s error stage=do_request attempt=%d err=%v", constants.FuncGetHunterioDomainSearch, attempt+1, err)
			attemptErr = err
			time.Sleep(resolver.RetryBaseDelay * time.Duration(attempt+1))
			continue
		}

		respBody, err = io.ReadAll(resp.Body)

		if cerr := resp.Body.Close(); cerr != nil {
			dlog.Printf("%s body_close_failed err=%v", constants.FuncGetHunterioDomainSearch, cerr)
		}

		if err != nil {
			dlog.Printf("%s error stage=read_body attempt=%d err=%v", constants.FuncGetHunterioDomainSearch, attempt+1, err)
			attemptErr = err
			time.Sleep(resolver.RetryBaseDelay * time.Duration(attempt+1))
			continue
		}

		statusCode = resp.StatusCode
		if (statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError) && attempt < resolver.HunterioMaxRetries-1 {
			dlog.Printf("%s error stage=server_error_or_rate_limit attempt=%d status=%d", constants.FuncGetHunterioDomainSearch, attempt+1, statusCode)
			time.Sleep(resolver.RetryBaseDelay * time.Duration(attempt+1))
			continue
		}
		break
	}
	return respBody, statusCode, attemptErr
}

func extractEmails(parsedResp *apiDomainSearchResponse, targetDomain string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	var results []schema.ModuleResult
	for i := range parsedResp.Data.Emails {
		results = extractEmailEntry(&parsedResp.Data.Emails[i], results, targetDomain, gen)
	}
	return results
}

func extractEmailEntry(e *apiEmailEntry, results []schema.ModuleResult, targetDomain string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	emailID := gen.NextID()
	emailRes := schema.ModuleResult{
		Type:     constants.TypeEmail,
		Category: constants.CategoryNode,
		Value:    e.Value,
		LocalID:  emailID,
	}
	if e.Type != "" {
		emailRes.Context = strings.ToUpper(e.Type[:1]) + e.Type[1:] + " email"
	}
	results = append(results, emailRes)

	emailRef := &schema.EntityRef{Type: constants.TypeEmail, Value: e.Value, LocalID: emailID}

	results = appendEmailProperties(e, results, emailRef, gen)
	targetRef := appendPersonData(e, &results, emailRef, gen)
	results = appendProfileData(e, results, targetRef, gen)
	results = appendSources(e, results, emailRef, targetDomain, gen)

	return results
}

func appendEmailProperties(e *apiEmailEntry, results []schema.ModuleResult, emailRef *schema.EntityRef, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	if e.Confidence > 0 {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeConfidenceScore,
			Category: constants.CategoryProperty,
			Value:    strconv.Itoa(e.Confidence),
			Source:   emailRef,
			LocalID:  gen.NextID(),
		})
	}
	if e.Verification.Status != "" {
		val := e.Verification.Status
		if e.Verification.Date != "" {
			val = fmt.Sprintf("%s (%s)", val, e.Verification.Date)
		}
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeVerificationStatus,
			Category: constants.CategoryProperty,
			Value:    val,
			Source:   emailRef,
			LocalID:  gen.NextID(),
		})
	}
	return results
}

func appendPersonData(e *apiEmailEntry, results *[]schema.ModuleResult, emailRef *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	personName := strings.TrimSpace(e.FirstName + " " + e.LastName)
	if personName == "" {
		return emailRef
	}

	personID := gen.NextID()
	*results = append(*results, schema.ModuleResult{
		Type:     constants.TypePerson,
		Category: constants.CategoryNode,
		Value:    personName,
		Source:   emailRef,
		LocalID:  personID,
	})
	return &schema.EntityRef{Type: constants.TypePerson, Value: personName, LocalID: personID}
}

func appendProfileData(e *apiEmailEntry, results []schema.ModuleResult, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	if e.Position != "" {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypePosition,
			Category: constants.CategoryProperty,
			Value:    e.Position,
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}
	if e.Department != "" {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeDepartment,
			Category: constants.CategoryProperty,
			Value:    e.Department,
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}
	if e.Seniority != "" {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeSeniority,
			Category: constants.CategoryProperty,
			Value:    e.Seniority,
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}
	const ctxLinkedIn = "LinkedIn"
	if e.Linkedin != "" {
		results = append(results, schema.ModuleResult{
			Type:    constants.TypeURL,
			Value:   e.Linkedin,
			Context: ctxLinkedIn,
			Tags:    []string{constants.TagSocial},
			Source:  targetRef,
			LocalID: gen.NextID(),
		})
	}
	if e.Twitter != "" {
		twitterURL := e.Twitter
		if !strings.HasPrefix(twitterURL, "http") {
			twitterURL = "https://twitter.com/" + twitterURL
		}
		results = append(results, schema.ModuleResult{
			Type:    constants.TypeURL,
			Value:   twitterURL,
			Context: "Twitter",
			Tags:    []string{constants.TagSocial},
			Source:  targetRef,
			LocalID: gen.NextID(),
		})
	}
	if e.PhoneNumber != "" {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypePhone,
			Category: constants.CategoryNode,
			Value:    e.PhoneNumber,
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}
	return results
}

func appendSources(e *apiEmailEntry, results []schema.ModuleResult, emailRef *schema.EntityRef, targetDomain string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	if len(e.Sources) == 0 {
		return results
	}

	sourceGroupVal := "Sources for " + e.Value
	sourceGroupID := gen.NextID()
	sourceGroupRef := &schema.EntityRef{Type: constants.TypeSource, Value: sourceGroupVal, LocalID: sourceGroupID}
	results = append(results, schema.ModuleResult{
		Type:     constants.TypeSource,
		Category: constants.CategoryNode,
		Value:    sourceGroupVal,
		Source:   emailRef,
		LocalID:  sourceGroupID,
	})

	for _, s := range e.Sources {
		if s.URI != "" {
			results = appendSourceWithURI(s, results, sourceGroupRef, targetDomain, gen)
		} else if s.Domain != "" {
			results = append(results, schema.ModuleResult{
				Type:       constants.TypeDomain,
				Value:      s.Domain,
				Tags:       []string{constants.TagScrape},
				Source:     sourceGroupRef,
				OutOfScope: orgdomain.IsOutOfScope(s.Domain, targetDomain),
				LocalID:    gen.NextID(),
			})
		}
	}
	return results
}

func appendSourceWithURI(s apiEmailSource, results []schema.ModuleResult, sourceGroupRef *schema.EntityRef, targetDomain string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	sourceID := gen.NextID()
	results = append(results, schema.ModuleResult{
		Type:    constants.TypeURL,
		Value:   s.URI,
		Source:  sourceGroupRef,
		LocalID: sourceID,
	})
	sourceRef := &schema.EntityRef{Type: constants.TypeURL, Value: s.URI, LocalID: sourceID}

	if s.Domain != "" {
		results = append(results, schema.ModuleResult{
			Type:       constants.TypeDomain,
			Value:      s.Domain,
			Tags:       []string{constants.TagScrape},
			Source:     sourceRef,
			OutOfScope: orgdomain.IsOutOfScope(s.Domain, targetDomain),
			LocalID:    gen.NextID(),
		})
	}
	if s.ExtractedOn != "" {
		extractedOn := s.ExtractedOn
		if day, ok := dateutil.NormalizeDay(extractedOn); ok {
			extractedOn = day
		}
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Extracted on: " + extractedOn,
			Source:   sourceRef,
			LocalID:  gen.NextID(),
		})
	}
	if s.LastSeenOn != "" {
		lastSeenOn := s.LastSeenOn
		if day, ok := dateutil.NormalizeDay(lastSeenOn); ok {
			lastSeenOn = day
		}
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Last seen: " + lastSeenOn,
			Source:   sourceRef,
			LocalID:  gen.NextID(),
		})
	}
	if s.StillOnPage {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeStatus,
			Category: constants.CategoryProperty,
			Value:    "Still on page",
			Source:   sourceRef,
			LocalID:  gen.NextID(),
		})
	}
	return results
}
