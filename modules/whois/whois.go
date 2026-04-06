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
		fmt.Fprintf(os.Stderr, "[whois-debug] method=%q usedDNS=%q rawLen=%d\n", methodUsed, resolver.LastUsedPlain, len(rawData))
	}

	execution.RawData = rawData
	execution.Results = m.buildResults(&metadata, target)

	return execution
}

func (m *module) buildResults(metadata *Metadata, target string) []schema.ModuleResult {
	var results []schema.ModuleResult

	appendSlice := func(arr []string, typ, prefix string, isOOS bool) {
		for _, v := range arr {
			v = strings.TrimSpace(v)
			if v != "" {
				results = append(results, m.result(typ, v, prefix, isOOS))
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
				results = append(results, m.result("tel", cleanPhone, prefix+" Phone", isOOS))
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

	results = append(results, m.buildMetadataResults(metadata, target)...)

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

func (m *module) buildMetadataResults(metadata *Metadata, target string) []schema.ModuleResult {
	var results []schema.ModuleResult

	if metadata.RegistrarURL != "" {
		results = append(results, m.result("url", metadata.RegistrarURL, "Registrar URL", true))
	}
	if metadata.WhoisServer != "" {
		results = append(results, m.result("domain", metadata.WhoisServer, "Whois Server", true))
	}
	if metadata.DNSSEC != "" {
		results = append(results, m.result("string", metadata.DNSSEC, "DNSSEC Status", false))
	}
	if metadata.IANAID != "" {
		results = append(results, m.result("string", metadata.IANAID, "IANA ID", true))
	}
	if metadata.CreationDate != "" {
		results = append(results, m.result("date", metadata.CreationDate, "Creation Date", false))
	}
	if metadata.UpdatedDate != "" {
		results = append(results, m.result("date", metadata.UpdatedDate, "Updated Date", false))
	}
	if metadata.ExpirationDate != "" {
		results = append(results, m.result("date", metadata.ExpirationDate, "Expiration Date", false))
	}
	for _, ns := range metadata.NameServers {
		oos := !strings.HasSuffix(strings.ToLower(ns), "."+strings.ToLower(target))
		results = append(results, m.result("domain", ns, "Name Server", oos))
	}
	for _, st := range metadata.DomainStatus {
		results = append(results, m.result("status", st, "Domain Status", false))
	}
	return results
}

// --- Network functions ---

func queryRDAP(ctx context.Context, domain string) (map[string]any, error) {
	url := "https://rdap.org/domain/" + domain
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
		return nil, fmt.Errorf("rdap do request: %w", err)
	}
	defer func() {
		//nolint:errcheck // defer body close error is not critical
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap status %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("rdap decode error: %w", err)
	}
	return data, nil
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
	d := resolver.GetDialer()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", fmt.Errorf("dial error: %w", err)
	}
	defer func() {
		//nolint:errcheck // defer connection close error is not critical
		_ = conn.Close()
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if sErr := conn.SetDeadline(deadline); sErr != nil {
			return "", fmt.Errorf("set deadline error: %w", sErr)
		}
	}

	if _, wErr := fmt.Fprintf(conn, "%s\r\n", query); wErr != nil {
		return "", fmt.Errorf("write error: %w", wErr)
	}

	res, rErr := io.ReadAll(conn)
	if rErr != nil {
		return "", fmt.Errorf("read error: %w", rErr)
	}
	return string(res), nil
}
