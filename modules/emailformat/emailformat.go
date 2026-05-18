// Package emailformat provides integration with email-format.com API.
package emailformat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const moduleName = "emailformat"

var dbg = debuglog.New(moduleName)

var baseURL = "https://www.email-format.com"

var cfEmailRegex = regexp.MustCompile(`data-cfemail="([0-9a-fA-F]+)"`)

type emailformatModule struct{}

// New creates a new module instance.
func New() schema.Module {
	return &emailformatModule{}
}

func (m *emailformatModule) Name() string {
	return moduleName
}

func (m *emailformatModule) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		CustomFunctions: map[string]schema.FunctionCapabilities{
			constants.FuncGetEmails: {
				Limit:      1,
				DelayMs:    3000,
				InputTypes: []string{constants.TypeDomain, constants.TypeSubdomain},
			},
		},
	}, nil
}

func (m *emailformatModule) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	var execs []schema.ModuleExecution

	for _, fn := range data.Functions {
		if fn == constants.FuncGetEmails {
			execs = append(execs, getEmails(data.Target))
		}
	}

	return schema.ModuleOutput{Executions: execs}, nil
}

func getEmails(target schema.Entity) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetEmails)

	reqURL := fmt.Sprintf("%s/d/%s/", baseURL, url.PathEscape(target.Value))

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	rawBody, statusCode, lastErr := fetchHTML(ctx, reqURL, target.Value)
	modutil.SetRawFromBytes(&exec, rawBody)

	if statusCode == 0 && lastErr != nil {
		dbg.Printf("%s error target=%q stage=request err=%v", constants.FuncGetEmails, target.Value, lastErr)
		modutil.SetError(&exec, "request failed: %v", lastErr)
		return exec
	}

	if statusCode == http.StatusNotFound {
		dbg.Printf("%s not_found target=%q status=%d", constants.FuncGetEmails, target.Value, statusCode)
		return exec
	}

	if statusCode != http.StatusOK {
		if lastErr != nil {
			dbg.Printf("%s error target=%q stage=response status=%d err=%v", constants.FuncGetEmails, target.Value, statusCode, lastErr)
			modutil.SetError(&exec, "request failed: %v", lastErr)
		} else {
			dbg.Printf("%s error target=%q stage=response status=%d", constants.FuncGetEmails, target.Value, statusCode)
			modutil.SetError(&exec, "request failed with status: %d", fmt.Errorf("%d", statusCode))
		}
		return exec
	}

	parseEmails(&exec, rawBody, target.Value)
	dbg.Printf("%s success target=%q records=%d", constants.FuncGetEmails, target.Value, len(exec.Results))
	return exec
}

func fetchHTML(ctx context.Context, reqURL, target string) (rawBody []byte, statusCode int, err error) {
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesHT; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
		if err != nil {
			dbg.Printf("%s error target=%q stage=create_request attempt=%d err=%v", constants.FuncGetEmails, target, attempt, err)
			return nil, 0, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("User-Agent", resolver.GetRandomUserAgent())
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		client := &http.Client{Timeout: resolver.HTTPTimeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			dbg.Printf("%s request_retry target=%q stage=do_request attempt=%d err=%v", constants.FuncGetEmails, target, attempt, err)
			if attempt < resolver.MaxRetriesHT {
				httputil.SleepContext(ctx, resolver.RetryBaseDelay)
			}
			continue
		}

		statusCode = resp.StatusCode
		body, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("%s body_close_failed target=%q attempt=%d err=%v", constants.FuncGetEmails, target, attempt, cerr)
		}

		if err != nil {
			lastErr = err
			dbg.Printf("%s request_retry target=%q stage=read_body attempt=%d err=%v", constants.FuncGetEmails, target, attempt, err)
			if attempt < resolver.MaxRetriesHT {
				httputil.SleepContext(ctx, resolver.RetryBaseDelay)
			}
			continue
		}

		rawBody = body

		if statusCode == http.StatusOK || statusCode == http.StatusNotFound {
			dbg.Printf("%s response_received target=%q attempt=%d status=%d", constants.FuncGetEmails, target, attempt, statusCode)
			break
		}

		action := httputil.ClassifyStatus(statusCode)
		if action == httputil.Abort {
			dbg.Printf("%s error target=%q stage=response_status attempt=%d status=%d action=%d", constants.FuncGetEmails, target, attempt, statusCode, action)
			lastErr = fmt.Errorf("http status %d: %s", statusCode, string(body))
			break
		}
		dbg.Printf("%s retry_status target=%q attempt=%d status=%d action=%d", constants.FuncGetEmails, target, attempt, statusCode, action)

		lastErr = fmt.Errorf("http status %d", statusCode)
		if attempt < resolver.MaxRetriesHT {
			if action == httputil.RateLimit {
				httputil.SleepContext(ctx, httputil.RetryDelay(action, attempt-1, resolver.RetryBaseDelay))
			} else {
				httputil.SleepContext(ctx, resolver.RetryBaseDelay)
			}
		}
	}
	return rawBody, statusCode, lastErr
}

func parseEmails(exec *schema.ModuleExecution, rawBody []byte, target string) {
	matches := cfEmailRegex.FindAllSubmatch(rawBody, -1)

	uniqueEmails := make(map[string]bool)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		email, ok := decodeCFEmail(string(match[1]))
		if !ok {
			continue
		}

		validRes, err := validator.Validate(constants.TypeEmail, email)
		if err != nil {
			continue
		}

		if !strings.HasSuffix(validRes.Value, "@"+target) && !strings.HasSuffix(validRes.Value, "."+target) {
			continue
		}

		if !uniqueEmails[validRes.Value] {
			uniqueEmails[validRes.Value] = true
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     validRes.Type,
				Category: constants.CategoryNode,
				Value:    validRes.Value,
				Context:  "email-format.com",
			})
		}
	}
}

func decodeCFEmail(enc string) (string, bool) {
	if len(enc) < 2 || len(enc)%2 != 0 {
		return "", false
	}

	key, err := strconv.ParseUint(enc[:2], 16, 8)
	if err != nil {
		return "", false
	}

	decoded := make([]byte, 0, (len(enc)-2)/2)
	for i := 2; i < len(enc); i += 2 {
		b, err := strconv.ParseUint(enc[i:i+2], 16, 8)
		if err != nil {
			return "", false
		}
		decoded = append(decoded, byte((b^key)&0xFF))
	}

	return strings.ToLower(string(decoded)), true
}
