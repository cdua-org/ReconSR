// Package abuseipdb implements a module for checking IP reputation against the AbuseIPDB service.
package abuseipdb

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
	"sync/atomic"

	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var categoriesMap = map[int]string{
	1:  "DNS Compromise",
	2:  "DNS Poisoning",
	3:  "Fraud Orders",
	4:  "DDoS Attack",
	5:  "FTP Brute-Force",
	6:  "Ping of Death",
	7:  "Phishing",
	8:  "Fraud VoIP",
	9:  "Open Proxy",
	10: "Web Spam",
	11: "Email Spam",
	12: "Blog Spam",
	13: "VPN IP",
	14: "Port Scan",
	15: "Hacking",
	16: "SQL Injection",
	17: "Spoofing",
	18: "Brute-Force",
	19: "Bad Web Bot",
	20: "Exploited Host",
	21: "Web App Attack",
	22: "SSH",
	23: "IoT Targeted",
}

var defaultAPIURL = "https://api.abuseipdb.com/api/v2/check"
var dbg = debuglog.New("abuseipdb")

type module struct {
	apiKey    string
	demoFired atomic.Bool
}

// New creates a new abuseipdb module instance.
func New() schema.Module {
	return &module{
		apiKey: apiconfig.GetKey("AbuseIPDB"),
	}
}

func (m *module) Name() string { return "abuseipdb" }

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	if m.apiKey == "" {
		return schema.ModuleCapabilities{}, nil
	}

	return schema.ModuleCapabilities{
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:      5,
			DelayMs:    1000,
			InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
		},
		Functions: []string{constants.FuncCheckAbuseIPDB},
	}, nil
}

type abuseIPDBResponse struct {
	Data struct {
		IsWhitelisted *bool  `json:"isWhitelisted"`
		IPAddress     string `json:"ipAddress"`
		CountryCode   string `json:"countryCode"`
		UsageType     string `json:"usageType"`
		ISP           string `json:"isp"`
		Domain        string `json:"domain"`
		Reports       []struct {
			ReportedAt string `json:"reportedAt"`
			Comment    string `json:"comment"`
			Categories []int  `json:"categories"`
		} `json:"reports"`
		Hostnames            []string `json:"hostnames"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		TotalReports         int      `json:"totalReports"`
		IsPublic             bool     `json:"isPublic"`
		IsTor                bool     `json:"isTor"`
	} `json:"data"`
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		exec := modutil.NewExecution(f)

		if f == constants.FuncCheckAbuseIPDB {
			if m.apiKey == "demo-api-key" {
				m.processCheckDemo(&exec, data.Target.Value)
			} else {
				processCheck(&exec, data.Target.Value, m.apiKey)
			}
		} else {
			modutil.SetError(&exec, "unsupported function: %v", errors.New(f))
		}

		executions = append(executions, exec)
	}

	return schema.ModuleOutput{Executions: executions}, nil
}

func processCheck(exec *schema.ModuleExecution, target, apiKey string) {
	dbg.Printf("%s target=%q", constants.FuncCheckAbuseIPDB, target)

	maxAge := resolver.AbuseIPDBmaxAgeInDays
	if maxAge < 1 {
		maxAge = 1
	} else if maxAge > 365 {
		maxAge = 365
	}

	u, err := url.Parse(defaultAPIURL)
	if err != nil {
		dbg.Printf("%s error target=%q stage=url_parse err=%v", constants.FuncCheckAbuseIPDB, target, err)
		modutil.SetError(exec, "invalid default API URL: %v", err)
		return
	}
	q := u.Query()
	q.Set("ipAddress", target)
	q.Set("maxAgeInDays", strconv.Itoa(maxAge))
	q.Set("verbose", "true")
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	var lastErr error
	var rawData []byte
	var parsed abuseIPDBResponse

	for attempt := range resolver.MaxRetriesIPMeta {
		body, statusCode, headers, err := doRequest(ctx, u.String(), apiKey)
		if err != nil {
			lastErr = err
			dbg.Printf("%s error target=%q stage=request attempt=%d err=%v", constants.FuncCheckAbuseIPDB, target, attempt, lastErr)
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				break
			}
			httputil.SleepContext(ctx, httputil.RetryDelay(httputil.Retry, attempt, resolver.RetryBaseDelay))
			continue
		}

		rawData = body
		action := httputil.ClassifyStatus(statusCode)
		dbg.Printf("%s target=%q attempt=%d status=%d action=%d", constants.FuncCheckAbuseIPDB, target, attempt, statusCode, action)

		if action == httputil.RateLimit {
			if isDailyQuotaExceeded(headers) {
				lastErr = fmt.Errorf("daily API quota exceeded (HTTP 429), Retry-After: %s", headers.Get("Retry-After"))
				dbg.Printf("%s error target=%q stage=rate_limit attempt=%d retry_after=%q quota=daily_exhausted", constants.FuncCheckAbuseIPDB, target, attempt, headers.Get("Retry-After"))
				break
			}

			lastErr = errors.New("rate limited (HTTP 429)")
			dbg.Printf("%s error target=%q stage=rate_limit attempt=%d", constants.FuncCheckAbuseIPDB, target, attempt)
			httputil.SleepContext(ctx, httputil.RetryDelay(httputil.RateLimit, attempt, resolver.RetryBaseDelay))
			continue
		}

		if statusCode != http.StatusOK {
			lastErr = fmt.Errorf("unexpected status %d", statusCode)
			dbg.Printf("%s error target=%q stage=response_status attempt=%d status=%d", constants.FuncCheckAbuseIPDB, target, attempt, statusCode)
			break
		}

		if err := json.Unmarshal(body, &parsed); err != nil {
			lastErr = fmt.Errorf("parse json: %w", err)
			dbg.Printf("%s error target=%q stage=unmarshal attempt=%d err=%v", constants.FuncCheckAbuseIPDB, target, attempt, lastErr)
		} else {
			dbg.Printf("%s success target=%q attempt=%d reports=%d score=%d", constants.FuncCheckAbuseIPDB, target, attempt, parsed.Data.TotalReports, parsed.Data.AbuseConfidenceScore)
			lastErr = nil
		}
		break
	}

	modutil.SetRawFromBytes(exec, rawData)

	if lastErr != nil {
		modutil.SetError(exec, "%v", lastErr)
		return
	}

	populateResults(exec, &parsed)
}

func doRequest(ctx context.Context, urlStr, apiKey string) (body []byte, statusCode int, headers http.Header, err error) {
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if reqErr != nil {
		return nil, 0, nil, fmt.Errorf("create request: %w", reqErr)
	}

	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, doErr := client.Do(req)
	if doErr != nil {
		return nil, 0, nil, fmt.Errorf("do request: %w", doErr)
	}

	respBody, readErr := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil && readErr == nil {
		readErr = cerr
	}
	if readErr != nil {
		return nil, 0, nil, fmt.Errorf("read body: %w", readErr)
	}

	return respBody, resp.StatusCode, resp.Header, nil
}

func isDailyQuotaExceeded(header http.Header) bool {
	if header.Get("X-RateLimit-Remaining") == "0" {
		return true
	}
	retryAfterSec, err := strconv.Atoi(header.Get("Retry-After"))
	if err == nil && retryAfterSec > 60 {
		return true
	}
	return false
}

func populateResults(exec *schema.ModuleExecution, resp *abuseIPDBResponse) {
	d := resp.Data

	if d.AbuseConfidenceScore > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeAbuseScore,
			Category: constants.CategoryProperty,
			Value:    strconv.Itoa(d.AbuseConfidenceScore),
		})

		if d.AbuseConfidenceScore < 50 {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeTag,
				Category: constants.CategoryProperty,
				Value:    constants.TagSuspicious,
			})
		} else {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeTag,
				Category: constants.CategoryProperty,
				Value:    constants.TagMalicious,
			})
		}
	}

	if d.IsWhitelisted != nil && *d.IsWhitelisted {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    constants.TagWhitelisted,
		})
	}

	if d.IsPublic {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    constants.TagPublicIP,
		})
	}

	if d.IsTor {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    constants.TagTorExit,
		})
	}

	if d.UsageType != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeUsageType,
			Category: constants.CategoryProperty,
			Value:    d.UsageType,
		})
	}

	if d.ISP != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeISP,
			Category: constants.CategoryProperty,
			Value:    d.ISP,
		})
	}

	populateMoreResults(exec, resp)
}

func populateMoreResults(exec *schema.ModuleExecution, resp *abuseIPDBResponse) {
	d := resp.Data

	if d.Domain != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:  constants.TypeDomain,
			Value: d.Domain,
			Tags:  []string{constants.TagReverseIP},
		})
	}

	if d.CountryCode != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeGeo,
			Category: constants.CategoryProperty,
			Value:    d.CountryCode,
		})
	}

	for _, host := range d.Hostnames {
		if host != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:  constants.TypeDomain,
				Value: host,
				Tags:  []string{constants.TagReverseIP},
			})
		}
	}

	parseReports(exec, resp)
}

func parseReports(exec *schema.ModuleExecution, resp *abuseIPDBResponse) {
	d := resp.Data
	if d.TotalReports <= 0 {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeTotalReports,
		Category: constants.CategoryProperty,
		Value:    strconv.Itoa(d.TotalReports),
	})

	var hasSpam, hasDDoS, hasBruteforce, hasScanner bool

	for _, rep := range d.Reports {
		var catNames []string
		for _, c := range rep.Categories {
			if name, ok := categoriesMap[c]; ok {
				catNames = append(catNames, name)
			} else {
				catNames = append(catNames, fmt.Sprintf("Unknown Category %d", c))
			}

			switch c {
			case 10, 11, 12:
				hasSpam = true
			case 4:
				hasDDoS = true
			case 18, 22:
				hasBruteforce = true
			case 14:
				hasScanner = true
			}
		}

		catStr := strings.Join(catNames, ", ")
		safeComment := strings.ReplaceAll(rep.Comment, "\n", " ")
		if len(safeComment) > 100 {
			safeComment = safeComment[:97] + "..."
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeAbuseReport,
			Category: constants.CategoryProperty,
			Value:    fmt.Sprintf("[%s] %s: %s", rep.ReportedAt, catStr, safeComment),
		})
	}

	if hasSpam {
		exec.Results = append(exec.Results, schema.ModuleResult{Type: constants.TypeTag, Category: constants.CategoryProperty, Value: constants.TagSpam})
	}
	if hasDDoS {
		exec.Results = append(exec.Results, schema.ModuleResult{Type: constants.TypeTag, Category: constants.CategoryProperty, Value: constants.TagDDoS})
	}
	if hasBruteforce {
		exec.Results = append(exec.Results, schema.ModuleResult{Type: constants.TypeTag, Category: constants.CategoryProperty, Value: constants.TagBruteforce})
	}
	if hasScanner {
		exec.Results = append(exec.Results, schema.ModuleResult{Type: constants.TypeTag, Category: constants.CategoryProperty, Value: constants.TagScanner})
	}
}
