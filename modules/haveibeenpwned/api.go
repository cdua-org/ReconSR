package haveibeenpwned

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
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var (
	hibpAPIBaseURL                        = "https://haveibeenpwned.com/api/v3"
	httpClientTransport http.RoundTripper = http.DefaultTransport
)

type apiBreachEntry struct {
	Name               string   `json:"Name"`
	Title              string   `json:"Title"`
	Domain             string   `json:"Domain"`
	BreachDate         string   `json:"BreachDate"`
	AddedDate          string   `json:"AddedDate"`
	ModifiedDate       string   `json:"ModifiedDate"`
	Description        string   `json:"Description"`
	LogoPath           string   `json:"LogoPath"`
	Attribution        string   `json:"Attribution"`
	DisclosureURL      string   `json:"DisclosureUrl"`
	DataClasses        []string `json:"DataClasses"`
	PwnCount           int      `json:"PwnCount"`
	IsVerified         bool     `json:"IsVerified"`
	IsFabricated       bool     `json:"IsFabricated"`
	IsSensitive        bool     `json:"IsSensitive"`
	IsRetired          bool     `json:"IsRetired"`
	IsSpamList         bool     `json:"IsSpamList"`
	IsMalware          bool     `json:"IsMalware"`
	IsSubscriptionFree bool     `json:"IsSubscriptionFree"`
	IsStealerLog       bool     `json:"IsStealerLog"`
}

type apiErrorResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"statusCode"`
}

func (m *module) getEmailBreaches(ctx context.Context, email string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetEmailBreaches)
	gen := modutil.NewLocalIDGenerator()

	if m.apiKey == "demo-api-key" {
		return m.getEmailBreachesDemo(&exec, email, gen)
	}

	u := fmt.Sprintf("%s/breachedaccount/%s?truncateResponse=false", hibpAPIBaseURL, url.PathEscape(email))

	for attempt := range resolver.HaveIBeenPwnedMaxRetries {
		m.waitRateLimit()

		respBody, statusCode, retryAfter, shouldBreak := m.fetchPage(ctx, &exec, u, attempt)
		if shouldBreak {
			modutil.SetRawFromBytes(&exec, respBody)
			break
		}

		if statusCode == http.StatusOK {
			var breaches []apiBreachEntry
			if err := json.Unmarshal(respBody, &breaches); err != nil {
				dlog.Printf("%s error stage=parse err=%v", constants.FuncGetEmailBreaches, err)
				modutil.SetError(&exec, "json parse error: %v", err)
				break
			}
			dlog.Printf("%s success target=%q results=%d", constants.FuncGetEmailBreaches, email, len(breaches))
			processBreaches(&exec, email, breaches, gen)
			modutil.SetRawFromBytes(&exec, respBody)
			break
		}

		if m.handleErrorResponse(&exec, statusCode, retryAfter, respBody, attempt) {
			modutil.SetRawFromBytes(&exec, respBody)
			break
		}
	}

	return exec
}

func (m *module) fetchPage(ctx context.Context, exec *schema.ModuleExecution, u string, attempt int) (respBody []byte, statusCode int, retryAfter string, shouldBreak bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		modutil.SetError(exec, "create request: %v", err)
		return nil, 0, "", true
	}

	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())
	req.Header.Set("hibp-api-key", m.apiKey)

	client := &http.Client{
		Timeout:   resolver.HTTPTimeout,
		Transport: httpClientTransport,
	}
	resp, err := client.Do(req)
	if err != nil {
		dlog.Printf("%s error stage=do_request attempt=%d err=%v", constants.FuncGetEmailBreaches, attempt+1, err)
		time.Sleep(resolver.RetryBaseDelay * time.Duration(attempt+1))
		return nil, 0, "", false
	}

	retryAfter = resp.Header.Get("retry-after")

	respBody, err = io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil {
		dlog.Printf("%s body_close_failed err=%v", constants.FuncGetEmailBreaches, cerr)
	}

	if err != nil {
		dlog.Printf("%s error stage=read_body attempt=%d err=%v", constants.FuncGetEmailBreaches, attempt+1, err)
		time.Sleep(resolver.RetryBaseDelay * time.Duration(attempt+1))
		return nil, 0, retryAfter, false
	}

	return respBody, resp.StatusCode, retryAfter, false
}

func (m *module) handleErrorResponse(exec *schema.ModuleExecution, statusCode int, retryAfter string, respBody []byte, attempt int) bool {
	if statusCode == http.StatusNotFound {
		dlog.Printf("%s success target=not_found", constants.FuncGetEmailBreaches)
		return true
	}

	if statusCode == http.StatusTooManyRequests {
		sec, err := strconv.Atoi(retryAfter)
		if retryAfter != "" && err == nil && sec > 0 {
			time.Sleep(time.Duration(sec) * time.Second)
		} else {
			time.Sleep(resolver.RetryBaseDelay * time.Duration(attempt+1))
		}

		if attempt == resolver.HaveIBeenPwnedMaxRetries-1 {
			dlog.Printf("%s error stage=rate_limit_exceeded", constants.FuncGetEmailBreaches)
			modutil.SetError(exec, "haveibeenpwned rate limit exceeded: %v", errors.New("HTTP 429"))
		} else {
			dlog.Printf("%s warning stage=rate_limit attempt=%d retry_after=%s", constants.FuncGetEmailBreaches, attempt+1, retryAfter)
		}
		return false
	}

	if statusCode == http.StatusUnauthorized {
		dlog.Printf("%s error stage=unauthorized", constants.FuncGetEmailBreaches)
		modutil.SetError(exec, "haveibeenpwned api key is unauthorized: %v", errors.New("HTTP 401"))
		return true
	}

	if statusCode >= 500 && attempt < resolver.HaveIBeenPwnedMaxRetries-1 {
		dlog.Printf("%s error stage=server_error_or_unexpected attempt=%d status=%d", constants.FuncGetEmailBreaches, attempt+1, statusCode)
		time.Sleep(resolver.RetryBaseDelay * time.Duration(attempt+1))
		return false
	}

	var apiErr apiErrorResponse
	errMsg := fmt.Sprintf("HTTP %d", statusCode)
	if err := json.Unmarshal(respBody, &apiErr); err == nil && apiErr.Message != "" {
		errMsg = fmt.Sprintf("HTTP %d: %s", statusCode, apiErr.Message)
	}
	modutil.SetError(exec, "haveibeenpwned api error: %v", errors.New(errMsg))
	return true
}

func processBreaches(exec *schema.ModuleExecution, email string, breaches []apiBreachEntry, gen *modutil.LocalIDGenerator) {
	if len(breaches) > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:    constants.TypeEmail,
			Value:   email,
			Tags:    []string{constants.TagCompromised},
			LocalID: gen.NextID(),
		})
	}

	for i := range breaches {
		b := &breaches[i]
		breachID := gen.NextID()

		breachRes := schema.ModuleResult{
			Type:     constants.TypeBreach,
			Category: constants.CategoryProperty,
			Value:    b.Name,
			Context:  b.Title,
			LocalID:  breachID,
		}
		exec.Results = append(exec.Results, breachRes)

		breachRef := &schema.EntityRef{Type: constants.TypeBreach, Value: b.Name, LocalID: breachID}

		if b.Domain != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       constants.TypeDomain,
				Value:      b.Domain,
				Source:     breachRef,
				LocalID:    gen.NextID(),
				OutOfScope: true,
			})
		}

		addBreachTags(exec, b, breachRef, gen)
		addBreachProperties(exec, b, breachRef, gen)
	}
}

func addBreachTags(exec *schema.ModuleExecution, b *apiBreachEntry, breachRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	var tags []string
	if b.IsVerified {
		tags = append(tags, "verified")
	}
	if b.IsFabricated {
		tags = append(tags, "fabricated")
	}
	if b.IsSensitive {
		tags = append(tags, "sensitive")
	}
	if b.IsRetired {
		tags = append(tags, "retired")
	}
	if b.IsSpamList {
		tags = append(tags, "spam_list")
	}
	if b.IsMalware {
		tags = append(tags, "malware")
	}
	if b.IsSubscriptionFree {
		tags = append(tags, "subscription_free")
	}
	if b.IsStealerLog {
		tags = append(tags, "stealer_log")
	}

	for _, t := range tags {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    t,
			Source:   breachRef,
			LocalID:  gen.NextID(),
		})
	}
}

func addBreachProperties(exec *schema.ModuleExecution, b *apiBreachEntry, breachRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if b.BreachDate != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Breach Date: " + b.BreachDate,
			Source:   breachRef,
			LocalID:  gen.NextID(),
		})
	}

	if b.AddedDate != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Added Date: " + b.AddedDate,
			Source:   breachRef,
			LocalID:  gen.NextID(),
		})
	}

	if b.ModifiedDate != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Modified Date: " + b.ModifiedDate,
			Source:   breachRef,
			LocalID:  gen.NextID(),
		})
	}

	if b.PwnCount > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypePwnedRecords,
			Category: constants.CategoryProperty,
			Value:    strconv.Itoa(b.PwnCount),
			Source:   breachRef,
			LocalID:  gen.NextID(),
		})
	}

	if b.Description != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDescription,
			Category: constants.CategoryProperty,
			Value:    b.Description,
			Source:   breachRef,
			LocalID:  gen.NextID(),
		})
	}

	if b.Attribution != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeAttribution,
			Category: constants.CategoryProperty,
			Value:    b.Attribution,
			Source:   breachRef,
			LocalID:  gen.NextID(),
		})
	}

	if b.DisclosureURL != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeURL,
			Category: constants.CategoryProperty,
			Value:    b.DisclosureURL,
			Context:  "Disclosure Publication",
			Source:   breachRef,
			LocalID:  gen.NextID(),
		})
	}

	if len(b.DataClasses) > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeLeakedData,
			Category: constants.CategoryProperty,
			Value:    strings.Join(b.DataClasses, ", "),
			Source:   breachRef,
			LocalID:  gen.NextID(),
		})
	}
}
