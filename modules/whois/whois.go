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
	"slices"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var dbg = debuglog.New("whois")

type module struct{}

// New instantiates the WHOIS metadata module for the Dispatcher.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "whois"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{constants.FuncGetWhois},
		InputTypes: []string{constants.TypeDomain},
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   5,
			DelayMs: 2000,
		},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == constants.FuncGetWhois {
			execution = m.getWhoisData(data.Target.Value)
		} else {
			execution = modutil.NewExecution(f)
			errMsg := "unsupported function: " + f
			execution.Error = &errMsg
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

func (m *module) getWhoisData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: constants.FuncGetWhois,
		Results:  make([]schema.ModuleResult, 0, 35),
	}

	dbg.Printf("getWhoisData target=%q", target)

	ctx := context.Background()

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
		if whoisRaw != "" {
			rawData = whoisRaw
			metadata = parseWHOIS(whoisRaw)
			methodUsed = "TCP 43 WHOIS"
		}
		if wErr != nil {
			errStr := ""
			if rErr != nil {
				errStr = rErr.Error() + "; "
			}
			errMsg := errStr + "whois fallback failed: " + wErr.Error()
			execution.Error = &errMsg
			execution.RawData = rawData
			return execution
		}
	}

	dbg.Printf("method=%q usedDNS=%q rawLen=%d", methodUsed, resolver.GetLastUsedPlain(), len(rawData))
	if rawData != "" {
		sample := rawData
		if len(sample) > 300 {
			sample = sample[:300] + "..."
		}
		dbg.Printf("rawSample: %s", sample)
	}

	execution.RawData = rawData
	execution.Results = m.buildResults(&metadata, target, methodUsed)

	return execution
}

func (m *module) buildResults(metadata *Metadata, target, methodUsed string) []schema.ModuleResult {
	results := make([]schema.ModuleResult, 0, 35)

	sourceCtx := "RDAP"
	if methodUsed == "TCP 43 WHOIS" {
		sourceCtx = "WHOIS"
	}

	registrantAnchor, regResults := m.getRegistrantAnchor(metadata, target, sourceCtx)
	results = append(results, regResults...)

	registrarAnchor, regrResults := m.getRegistrarAnchor(metadata, target, sourceCtx)
	results = append(results, regrResults...)

	m.appendContact(&results, &metadata.Registrar, "Registrar", "", true, registrarAnchor, sourceCtx, target)
	m.appendContact(&results, &metadata.Abuse, "Abuse", constants.TypeWhoisAbuse, true, registrarAnchor, sourceCtx, target)

	m.appendContact(&results, &metadata.Registrant, "Registrant", "", false, registrantAnchor, sourceCtx, target)
	m.appendContact(&results, &metadata.Admin, "Admin", constants.TypeWhoisAdmin, false, registrantAnchor, sourceCtx, target)
	m.appendContact(&results, &metadata.Tech, "Tech", constants.TypeWhoisTech, false, registrantAnchor, sourceCtx, target)
	m.appendContact(&results, &metadata.Billing, "Billing", constants.TypeWhoisBilling, false, registrantAnchor, sourceCtx, target)

	results = append(results, m.buildMetadataResults(metadata, target, sourceCtx, registrarAnchor)...)
	return results
}

func (m *module) appendSlice(results *[]schema.ModuleResult, arr []string, typ, prefix string, isOOS bool, anchor *schema.EntityRef, sourceCtx string) {
	for _, v := range arr {
		v = strings.TrimSpace(v)
		if v != "" {
			category := constants.CategoryProperty
			resolvedType := typ
			if typ == "person" || typ == constants.TypeOrganization || typ == constants.TypeEmail {
				category = constants.CategoryNode
			}
			if typ == constants.TypeEmail {
				res, err := validator.Validate(constants.TypeEmail, v)
				if err != nil {
					continue
				}
				v = res.Value
				resolvedType = res.Type
			}
			*results = append(*results, m.result(resolvedType, category, v, prefix+" ("+sourceCtx+")", isOOS, anchor))
		}
	}
}

func (m *module) appendAddress(results *[]schema.ModuleResult, arr []string, typ, prefix string, isOOS bool, anchor *schema.EntityRef, sourceCtx string) {
	if len(arr) == 0 {
		return
	}

	var uniqueParts []string
	seen := make(map[string]bool)

	for _, v := range arr {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		lowerVal := strings.ToLower(v)
		if !seen[lowerVal] {
			seen[lowerVal] = true
			uniqueParts = append(uniqueParts, v)
		}
	}

	if len(uniqueParts) > 0 {
		slices.SortStableFunc(uniqueParts, func(a, b string) int {
			return strings.Compare(strings.ToLower(a), strings.ToLower(b))
		})
		mergedAddress := strings.Join(uniqueParts, ", ")
		*results = append(*results, m.result(typ, constants.CategoryNode, mergedAddress, prefix+" Address ("+sourceCtx+")", isOOS, anchor))
	}
}

func (m *module) appendContact(results *[]schema.ModuleResult, c *Contact, roleName, roleType string, forceOOS bool, anchor *schema.EntityRef, sourceCtx, target string) {
	if !hasContactData(c) {
		return
	}

	isOOS := forceOOS
	if slices.ContainsFunc(c.Organization, isPrivacyService) {
		isOOS = true
	}

	currentAnchor := anchor
	if roleType != "" {
		roleValue := roleName + " Contact of " + target
		*results = append(*results, m.result(roleType, constants.CategoryNode, roleValue, roleName+" Contact ("+sourceCtx+")", isOOS, anchor))
		currentAnchor = &schema.EntityRef{Type: roleType, Value: roleValue}
	}

	m.appendSlice(results, c.Name, "person", roleName+" Name", isOOS, currentAnchor, sourceCtx)
	m.appendSlice(results, c.Organization, constants.TypeOrganization, roleName+" Organization", isOOS, currentAnchor, sourceCtx)
	m.appendSlice(results, c.Email, constants.TypeEmail, roleName+" Email", isOOS, currentAnchor, sourceCtx)
	m.appendAddress(results, c.Address, "address", roleName, isOOS, currentAnchor, sourceCtx)

	for _, p := range c.Phone {
		cleanPhone := normalizePhone(p)
		if cleanPhone != "" {
			*results = append(*results, m.result(constants.TypePhone, constants.CategoryNode, cleanPhone, roleName+" Phone ("+sourceCtx+")", isOOS, currentAnchor))
		}
	}
}

func (m *module) getRegistrantAnchor(metadata *Metadata, target, sourceCtx string) (*schema.EntityRef, []schema.ModuleResult) {
	if hasContactData(&metadata.Registrant) || hasContactData(&metadata.Admin) || hasContactData(&metadata.Tech) || hasContactData(&metadata.Billing) {
		regValue := "Registrant of " + target
		res := []schema.ModuleResult{{
			Type:     constants.TypeWhoisRegistrant,
			Category: constants.CategoryNode,
			Value:    regValue,
			Context:  "Domain Registrant (" + sourceCtx + ")",
			Applied:  true,
		}}
		return &schema.EntityRef{Type: constants.TypeWhoisRegistrant, Value: regValue}, res
	}
	return nil, nil
}

func (m *module) getRegistrarAnchor(metadata *Metadata, target, sourceCtx string) (*schema.EntityRef, []schema.ModuleResult) {
	if hasContactData(&metadata.Registrar) || hasContactData(&metadata.Abuse) || metadata.RegistrarURL != "" || metadata.WhoisServer != "" || metadata.IANAID != "" {
		regValue := "Registrar of " + target
		res := []schema.ModuleResult{{
			Type:     constants.TypeWhoisRegistrar,
			Category: constants.CategoryNode,
			Value:    regValue,
			Context:  "Domain Registrar (" + sourceCtx + ")",
			Applied:  true,
		}}
		return &schema.EntityRef{Type: constants.TypeWhoisRegistrar, Value: regValue}, res
	}
	return nil, nil
}

func hasContactData(c *Contact) bool {
	return len(c.Name) > 0 || len(c.Organization) > 0 || len(c.Email) > 0 || len(c.Address) > 0 || len(c.Phone) > 0 || len(c.Fax) > 0
}

func (m *module) result(typ, category, value, ctx string, oos bool, anchor *schema.EntityRef) schema.ModuleResult {
	res := schema.ModuleResult{
		Type:       typ,
		Category:   category,
		Value:      value,
		Context:    ctx,
		Applied:    true,
		OutOfScope: oos,
	}
	if anchor != nil {
		res.Source = anchor
	}
	return res
}

func buildWhoisServerResult(host, target string) (schema.ModuleResult, bool) {
	res, err := validator.Validate(constants.TypeDomain, host)
	if err != nil {
		dbg.Printf("buildWhoisServerResult skipping invalid whois server target=%q entity=%q err=%v", target, host, err)
		return schema.ModuleResult{}, false
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	dbg.Printf("buildWhoisServerResult target=%q entity=%q oos=%v", target, res.Value, isOOS)

	return schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagWhoisServer},
		OutOfScope: isOOS,
	}, true
}

func (m *module) buildMetadataResults(metadata *Metadata, target, sourceCtx string, registrarAnchor *schema.EntityRef) []schema.ModuleResult {
	results := make([]schema.ModuleResult, 0, 15)

	if metadata.RegistrarURL != "" {
		results = append(results, m.result(constants.TypeURL, constants.CategoryProperty, metadata.RegistrarURL, "Registrar URL ("+sourceCtx+")", true, registrarAnchor))
	}
	if metadata.WhoisServer != "" {
		if result, ok := buildWhoisServerResult(metadata.WhoisServer, target); ok {
			result.Context = "Whois Server (" + sourceCtx + ")"
			result.Applied = true
			result.Source = registrarAnchor
			results = append(results, result)
		}
	}
	if metadata.IANAID != "" {
		results = append(results, m.result(constants.TypeIANAID, constants.CategoryProperty, metadata.IANAID, "IANA ID ("+sourceCtx+")", true, registrarAnchor))
	}

	if metadata.DNSSEC != "" {
		results = append(results, m.result(constants.TypeDNSSEC, constants.CategoryProperty, metadata.DNSSEC, "DNSSEC Status ("+sourceCtx+")", false, nil))
	}
	if metadata.CreationDate != "" {
		results = append(results, m.result(constants.TypeDate, constants.CategoryProperty, metadata.CreationDate, "Creation Date ("+sourceCtx+")", false, nil))
	}
	if metadata.UpdatedDate != "" {
		results = append(results, m.result(constants.TypeDate, constants.CategoryProperty, metadata.UpdatedDate, "Updated Date ("+sourceCtx+")", false, nil))
	}
	if metadata.ExpirationDate != "" {
		results = append(results, m.result(constants.TypeDate, constants.CategoryProperty, metadata.ExpirationDate, "Expiration Date ("+sourceCtx+")", false, nil))
	}
	for _, ns := range metadata.NameServers {
		if !strings.Contains(ns, ".") {
			oos := !strings.HasSuffix(strings.ToLower(ns), "."+strings.ToLower(target))
			results = append(results, m.result(constants.TypeHandle, constants.CategoryProperty, ns, "Name Server ("+sourceCtx+")", oos, nil))
			continue
		}

		res, err := validator.Validate(constants.TypeDomain, ns)
		if err != nil {
			continue
		}

		result := m.result(res.Type, constants.CategoryNode, res.Value, "Name Server ("+sourceCtx+")", orgdomain.IsOutOfScope(res.Value, target), nil)
		result.Tags = []string{constants.TagNS}
		results = append(results, result)
	}
	for _, st := range metadata.DomainStatus {
		results = append(results, m.result(constants.TypeStatus, constants.CategoryProperty, st, "Domain Status ("+sourceCtx+")", false, nil))
	}
	return results
}

func queryRDAP(ctx context.Context, domain string) (map[string]any, error) {
	url := buildRDAPURL(domain)
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesWhois; attempt++ {
		data, retriable, err := attemptRDAP(ctx, url)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !retriable {
			break
		}
		if attempt < resolver.MaxRetriesWhois {
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				break
			}
			continue
		}
	}

	return nil, lastErr
}

func attemptRDAP(ctx context.Context, url string) (data map[string]any, retriable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, false, fmt.Errorf("create rdap request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")

	transport := &http.Transport{
		DialContext:         resolver.GetDialer().DialContext,
		TLSHandshakeTimeout: resolver.Timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   resolver.HTTPTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("rdap do request: %w", err)
	}

	bodyOk := true
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("rdap status %d", resp.StatusCode)
		bodyOk = false
	}

	decodeErr := json.NewDecoder(resp.Body).Decode(&data)
	if cerr := resp.Body.Close(); cerr != nil {
		dbg.Printf("warning: failed to close rdap body: %v", cerr)
	}

	if !bodyOk {
		action := httputil.ClassifyStatus(resp.StatusCode)
		retriable := action == httputil.Retry || action == httputil.RateLimit
		return nil, retriable, err
	}

	if decodeErr != nil {
		return nil, true, fmt.Errorf("rdap decode error: %w", decodeErr)
	}

	return data, false, nil
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
		return ianaRes, fmt.Errorf("failed to query refer server: %w", err)
	}
	return res, nil
}

func dialWHOIS(ctx context.Context, server, query string) (string, error) {
	query = formatWHOISQuery(server, query)
	d := resolver.GetDialer()
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesWhois; attempt++ {
		res, err := func() (string, error) {
			attemptCtx, cancel := context.WithTimeout(ctx, resolver.Timeout)
			defer cancel()

			conn, err := d.DialContext(attemptCtx, "tcp", net.JoinHostPort(server, "43"))
			if err != nil {
				return "", fmt.Errorf("dial error: %w", err)
			}
			defer func() {
				if cerr := conn.Close(); cerr != nil {
					dbg.Printf("warning: failed to close whois connection: %v", cerr)
				}
			}()

			if deadline, ok := attemptCtx.Deadline(); ok {
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
		if attempt < resolver.MaxRetriesWhois {
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				break
			}
			continue
		}
	}

	return "", lastErr
}

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
