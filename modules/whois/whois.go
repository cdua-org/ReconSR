// Package whois provides a fallback-oriented architecture (RDAP primary, TCP WHOIS secondary)
// to guarantee metadata extraction regardless of domain registrar API compliance.
package whois

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

// Name provides the unique identifier used by the dispatcher for routing.
func (m *module) Name() string {
	return "whois"
}

// Capabilities declares the module's contract (inputs and functions) to the system core.
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_whois"},
		InputTypes: []string{"domain"},
	}, nil
}

// Exec acts as the stateless execution pipeline for incoming requests,
// isolating the core routing from the underlying network extraction logic.
func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_whois" {
			execution = m.getWhoisData(data.Target.Value)
		} else {
			errMsg := "unsupported function: " + f
			execution = schema.ModuleExecution{
				Function: f,
				Error:    &errMsg,
			}
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

func (m *module) getWhoisData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_whois",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var metadata Metadata
	var rawData string

	disableRDAP := false
	if val, ok := resolver.GetOption("DisableRDAP"); ok && strings.EqualFold(val, "true") {
		disableRDAP = true
	}

	methodUsed := ""

	rErr := func() error {
		if disableRDAP {
			return errors.New("RDAP disabled via configuration")
		}
		rdapData, err := queryRDAP(ctx, target)
		if err != nil {
			return fmt.Errorf("rdap failed: %w", err)
		}
		metadata = parseRDAP(rdapData)
		if rawBytes, mErr := json.Marshal(rdapData); mErr == nil {
			methodUsed = "RDAP"
			rawData = string(rawBytes)
		}
		return nil
	}()

	if rawData == "" {
		whoisRaw, wErr := queryWHOIS(ctx, target)
		if wErr != nil {
			errStr := ""
			if rErr != nil {
				errStr = rErr.Error() + "; "
			}
			errMsg := errStr + "whois fallback failed: " + wErr.Error()
			execution.Error = &errMsg
			execution.Results = nil
			return execution
		}
		metadata = parseWHOIS(whoisRaw)
		methodUsed = "TCP 43 WHOIS"
		rawData = whoisRaw
	}

	debugVal, debugOk := resolver.GetOption("Debug")
	if debugOk && strings.EqualFold(debugVal, "true") {
		fmt.Fprintf(os.Stderr, "[whois-debug] method=%q usedDNS=%q rawLen=%d\n", methodUsed, resolver.GetLastUsedPlain(), len(rawData))
		if rawData != "" {
			sample := rawData
			if len(sample) > 300 {
				sample = sample[:300] + "..."
			}
			fmt.Fprintf(os.Stderr, "[whois-debug] rawSample: %s\n", sample)
		}
	}

	execution.RawData = rawData
	execution.Results = m.buildResults(&metadata, target, methodUsed)

	return execution
}

func (m *module) buildResults(metadata *Metadata, target, methodUsed string) []schema.ModuleResult {
	var results []schema.ModuleResult

	sourceCtx := "RDAP"
	if methodUsed == "TCP 43 WHOIS" {
		sourceCtx = "WHOIS"
	}

	appendSlice := func(arr []string, typ, prefix string, isOOS bool) {
		for _, v := range arr {
			v = strings.TrimSpace(v)
			if v != "" {
				results = append(results, m.result(typ, v, prefix+" ("+sourceCtx+")", isOOS))
			}
		}
	}

	appendContact := func(c Contact, prefix string, forceOOS bool) {
		isOOS := forceOOS
		if slices.ContainsFunc(c.Organization, isPrivacyService) {
			isOOS = true
		}

		appendSlice(c.Name, "person", prefix+" Name", isOOS)
		appendSlice(c.Organization, "company", prefix+" Organization", isOOS)
		appendSlice(c.Email, "email", prefix+" Email", isOOS)
		appendSlice(c.Address, "address", prefix+" Address", isOOS)

		for _, p := range c.Phone {
			cleanPhone := normalizePhone(p)
			if cleanPhone != "" {
				results = append(results, m.result("tel", cleanPhone, prefix+" Phone ("+sourceCtx+")", isOOS))
			}
		}
	}

	// Registrar and Abuse data is always Out Of Scope by architectural definition
	appendContact(metadata.Registrar, "Registrar", true)
	appendContact(metadata.Abuse, "Abuse", true)

	// Registrant/Admin/Tech might be the target or a privacy service
	appendContact(metadata.Registrant, "Registrant", false)
	appendContact(metadata.Admin, "Admin", false)
	appendContact(metadata.Tech, "Tech", false)
	appendContact(metadata.Billing, "Billing", false)

	results = append(results, m.buildMetadataResults(metadata, target, sourceCtx)...)
	return results
}

func (m *module) result(typ, value, ctx string, oos bool) schema.ModuleResult {
	return schema.ModuleResult{
		Type:       typ,
		Value:      value,
		Context:    ctx,
		Applied:    true,
		OutOfScope: oos,
	}
}

func (m *module) buildMetadataResults(metadata *Metadata, target, sourceCtx string) []schema.ModuleResult {
	var results []schema.ModuleResult

	if metadata.RegistrarURL != "" {
		results = append(results, m.result("url", metadata.RegistrarURL, "Registrar URL ("+sourceCtx+")", true))
	}
	if metadata.WhoisServer != "" {
		results = append(results, m.result("domain", metadata.WhoisServer, "Whois Server ("+sourceCtx+")", true))
	}
	if metadata.DNSSEC != "" {
		results = append(results, m.result("string", metadata.DNSSEC, "DNSSEC Status ("+sourceCtx+")", false))
	}
	if metadata.IANAID != "" {
		results = append(results, m.result("string", metadata.IANAID, "IANA ID ("+sourceCtx+")", true))
	}
	if metadata.CreationDate != "" {
		results = append(results, m.result("date", metadata.CreationDate, "Creation Date ("+sourceCtx+")", false))
	}
	if metadata.UpdatedDate != "" {
		results = append(results, m.result("date", metadata.UpdatedDate, "Updated Date ("+sourceCtx+")", false))
	}
	if metadata.ExpirationDate != "" {
		results = append(results, m.result("date", metadata.ExpirationDate, "Expiration Date ("+sourceCtx+")", false))
	}
	for _, ns := range metadata.NameServers {
		oos := !strings.HasSuffix(strings.ToLower(ns), "."+strings.ToLower(target))
		typ := "domain"
		if !strings.Contains(ns, ".") {
			typ = "string"
		}
		results = append(results, m.result(typ, ns, "Name Server ("+sourceCtx+")", oos))
	}
	for _, st := range metadata.DomainStatus {
		results = append(results, m.result("status", st, "Domain Status ("+sourceCtx+")", false))
	}
	return results
}

// --- Network functions ---

func queryRDAP(ctx context.Context, domain string) (map[string]any, error) {
	url := buildRDAPURL(domain)
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesWhois; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("create rdap request: %w", err)
		}
		req.Header.Set("Accept", "application/rdap+json")

		transport := &http.Transport{
			DialContext:         resolver.GetDialer().DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   7 * time.Second,
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("rdap do request: %w", err)
			if attempt < resolver.MaxRetriesWhois && sleepContext(ctx) {
				continue
			}
			break
		}

		bodyOk := true
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("rdap status %d", resp.StatusCode)
			bodyOk = false
		}

		// read and close body
		var data map[string]any
		err = json.NewDecoder(resp.Body).Decode(&data)
		if cerr := resp.Body.Close(); cerr != nil && isDebug() {
			fmt.Fprintf(os.Stderr, "[whois-debug] warning: failed to close rdap body: %v\n", cerr)
		}

		if !bodyOk {
			if attempt < resolver.MaxRetriesWhois && sleepContext(ctx) {
				continue
			}
			break
		}

		if err != nil {
			lastErr = fmt.Errorf("rdap decode error: %w", err)
			if attempt < resolver.MaxRetriesWhois && sleepContext(ctx) {
				continue
			}
			break
		}

		return data, nil
	}

	return nil, lastErr
}

func queryWHOIS(ctx context.Context, domain string) (string, error) {
	ianaRes, err := dialWHOIS(ctx, "whois.iana.org", domain)
	if err != nil {
		return "", fmt.Errorf("failed to query IANA: %w", err)
	}

	referServer := ""
	scanner := bufio.NewScanner(strings.NewReader(ianaRes))
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if strings.HasPrefix(line, "refer:") || strings.HasPrefix(line, "whois:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				referServer = parts[1]
				break
			}
		}
	}

	if referServer == "" {
		if strings.Contains(strings.ToLower(ianaRes), "identity digital") {
			referServer = "whois.identitydigital.services"
		}
	}

	if referServer == "" || referServer == "whois.iana.org" {
		return ianaRes, nil
	}

	res, err := dialWHOIS(ctx, referServer, domain)
	if err != nil {
		return "", fmt.Errorf("failed to query refer server: %w", err)
	}
	return res, nil
}

func dialWHOIS(ctx context.Context, server, query string) (string, error) {
	// Format queries based on specific WHOIS server requirements
	query = formatWHOISQuery(server, query)
	d := resolver.GetDialer()
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesWhois; attempt++ {
		res, err := func() (string, error) {
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
			if err != nil {
				return "", fmt.Errorf("dial error: %w", err)
			}
			defer func() {
				if cerr := conn.Close(); cerr != nil && isDebug() {
					fmt.Fprintf(os.Stderr, "[whois-debug] warning: failed to close whois connection: %v\n", cerr)
				}
			}()

			if deadline, ok := ctx.Deadline(); ok {
				if sErr := conn.SetDeadline(deadline); sErr != nil {
					return "", fmt.Errorf("set deadline error: %w", sErr)
				}
			}

			if _, wErr := fmt.Fprintf(conn, "%s\r\n", query); wErr != nil {
				return "", fmt.Errorf("write error: %w", wErr)
			}

			b, rErr := io.ReadAll(conn)
			if rErr != nil {
				return "", fmt.Errorf("read error: %w", rErr)
			}
			return string(b), nil
		}()

		if err == nil {
			return res, nil
		}

		lastErr = err
		if attempt < resolver.MaxRetriesWhois && sleepContext(ctx) {
			continue
		}
	}

	return "", lastErr
}

// formatWHOISQuery adjusts the query string for specific WHOIS servers
// that require special formatting to return parseable results.
func formatWHOISQuery(server, query string) string {
	switch {
	case strings.HasSuffix(server, "jprs.jp") && !strings.HasSuffix(query, "/e"):
		return query + "/e"
	case strings.HasSuffix(server, "verisign-grs.com") && !strings.HasPrefix(query, "="):
		return "=" + query
	case strings.HasSuffix(server, "denic.de") && !strings.HasPrefix(query, "-T dn "):
		return "-T dn " + query
	case strings.HasSuffix(server, "nic.name") && !strings.HasPrefix(query, "domain="):
		return "domain=" + query
	}
	return query
}

func sleepContext(ctx context.Context) bool {
	select {
	case <-time.After(2 * time.Second):
		return true
	case <-ctx.Done():
		return false
	}
}
func isDebug() bool {
	val, ok := resolver.GetOption("Debug")
	return ok && val == "true"
}
