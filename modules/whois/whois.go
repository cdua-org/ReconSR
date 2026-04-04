// Package whois provides a fallback-oriented architecture (RDAP primary, TCP WHOIS secondary)
// to guarantee metadata extraction regardless of domain registrar API compliance.
package whois

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"cdua-org/ReconSR/schema"
)

const (
	roleRegistrar      = "registrar"
	roleRegistrant     = "registrant"
	roleAdministrative = "administrative"
	roleTechnical      = "technical"
	roleBilling        = "billing"
	roleAbuse          = "abuse"
)

// Contact consolidates fragmented vCard and text-based contact fields into a unified schema
// for consistent mapping across both RDAP and legacy WHOIS responses.
type Contact struct {
	Name         string
	Organization string
	Email        string
	Address      string
	Phone        string
}

// Metadata defines the normalized intersection of RDAP and WHOIS fields.
// It acts as the canonical data source before final conversion into graph Entities.
//
//nolint:govet // field alignment optimization is negligible here
type Metadata struct {
	NameServers    []string
	DomainStatus   []string
	CreationDate   string
	ExpirationDate string
	UpdatedDate    string
	RegistrarURL   string
	WhoisServer    string
	DNSSEC         string
	IANAID         string
	Registrar      Contact
	Registrant     Contact
	Admin          Contact
	Tech           Contact
	Billing        Contact
	Abuse          Contact
}

var dnsServers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
	"84.200.69.80:53",
	"84.200.70.40:53",
	"193.183.98.154:53",
	"185.121.177.177:53",
	"4.2.2.1:53",
	"4.2.2.2:53",
}

var dnsIndex atomic.Uint32

func getNextDNSServer() string {
	idx := dnsIndex.Add(1)
	//nolint:gosec // slice length is small and known
	pos := int(idx % uint32(len(dnsServers)))
	return dnsServers[pos]
}

func getCustomResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", getNextDNSServer())
		},
	}
}

func getDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  getCustomResolver(),
	}
}

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

	rdapData, rErr := queryRDAP(ctx, target)
	if rErr == nil {
		metadata = parseRDAP(rdapData)
		if rawBytes, mErr := json.Marshal(rdapData); mErr == nil {
			rawData = string(rawBytes)
		}
	} else {
		whoisRaw, wErr := queryWHOIS(ctx, target)
		if wErr != nil {
			errMsg := "rdap failed: " + rErr.Error() + "; whois fallback failed: " + wErr.Error()
			execution.Error = &errMsg
			execution.Results = nil
			return execution
		}
		metadata = parseWHOIS(whoisRaw)
		rawData = whoisRaw
	}

	execution.RawData = rawData
	execution.Results = m.buildResults(&metadata, target)

	return execution
}

func (m *module) buildResults(metadata *Metadata, target string) []schema.ModuleResult {
	var results []schema.ModuleResult

	appendContact := func(c Contact, prefix string, forceOOS bool) {
		// Mark as OOS if it's a known registrar role OR a privacy protection service
		isOOS := forceOOS || isPrivacyService(c.Organization)

		if c.Name != "" {
			results = append(results, schema.ModuleResult{Type: "person", Value: c.Name, Context: prefix + " Name", OutOfScope: isOOS})
		}
		if c.Organization != "" {
			results = append(results, schema.ModuleResult{Type: "company", Value: c.Organization, Context: prefix + " Organization", OutOfScope: isOOS})
		}
		if c.Email != "" {
			results = append(results, schema.ModuleResult{Type: "email", Value: c.Email, Context: prefix + " Email", OutOfScope: isOOS})
		}
		if c.Address != "" {
			results = append(results, schema.ModuleResult{Type: "address", Value: c.Address, Context: prefix + " Address", OutOfScope: isOOS})
		}
		if c.Phone != "" {
			cleanPhone := normalizePhone(c.Phone)
			if cleanPhone != "" {
				results = append(results, schema.ModuleResult{Type: "tel", Value: cleanPhone, Context: prefix + " Phone", OutOfScope: isOOS})
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

func (m *module) buildMetadataResults(metadata *Metadata, target string) []schema.ModuleResult {
	var results []schema.ModuleResult

	if metadata.RegistrarURL != "" {
		results = append(results, schema.ModuleResult{Type: "url", Value: metadata.RegistrarURL, Context: "Registrar URL", OutOfScope: true})
	}
	if metadata.WhoisServer != "" {
		results = append(results, schema.ModuleResult{Type: "domain", Value: metadata.WhoisServer, Context: "Whois Server", OutOfScope: true})
	}
	if metadata.DNSSEC != "" {
		results = append(results, schema.ModuleResult{Type: "string", Value: metadata.DNSSEC, Context: "DNSSEC Status"})
	}
	if metadata.IANAID != "" {
		results = append(results, schema.ModuleResult{Type: "string", Value: metadata.IANAID, Context: "IANA ID", OutOfScope: true})
	}
	if metadata.CreationDate != "" {
		results = append(results, schema.ModuleResult{Type: "date", Value: metadata.CreationDate, Context: "Creation Date"})
	}
	if metadata.UpdatedDate != "" {
		results = append(results, schema.ModuleResult{Type: "date", Value: metadata.UpdatedDate, Context: "Updated Date"})
	}
	if metadata.ExpirationDate != "" {
		results = append(results, schema.ModuleResult{Type: "date", Value: metadata.ExpirationDate, Context: "Expiration Date"})
	}
	for _, ns := range metadata.NameServers {
		// Only mark as OOS if it's NOT a subdomain of our target.
		// System's global scope check will catch external infra (Cloudflare, etc.) automatically.
		oos := !strings.HasSuffix(strings.ToLower(ns), "."+strings.ToLower(target))
		results = append(results, schema.ModuleResult{
			Type:       "domain",
			Value:      ns,
			Context:    "Name Server",
			OutOfScope: oos,
		})
	}
	for _, st := range metadata.DomainStatus {
		results = append(results, schema.ModuleResult{Type: "status", Value: st, Context: "Domain Status"})
	}
	return results
}

func isPrivacyService(org string) bool {
	low := strings.ToLower(org)
	keywords := []string{
		"privacy", "redacted", "proxy", "whoisguard", "whoisprivacy",
		"protection", "masked", "not disclosed", "customer care",
	}
	for _, kw := range keywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func normalizePhone(phone string) string {
	phone = strings.ToLower(strings.TrimSpace(phone))
	phone = strings.TrimPrefix(phone, "tel:")
	phone = strings.TrimPrefix(phone, "phone:")

	hasPlus := strings.HasPrefix(phone, "+")

	var digits []rune
	for _, r := range phone {
		if (r >= '0' && r <= '9') || r == '+' {
			digits = append(digits, r)
		}
	}

	result := strings.TrimSpace(string(digits))
	if hasPlus && !strings.HasPrefix(result, "+") {
		result = "+" + result
	}

	result = strings.ReplaceAll(result, "+", "")

	var cleaned []rune
	for _, r := range result {
		if r >= '0' && r <= '9' {
			cleaned = append(cleaned, r)
		}
	}

	if len(cleaned) >= 10 {
		return "+" + string(cleaned)
	}
	return ""
}

func queryRDAP(ctx context.Context, domain string) (map[string]any, error) {
	url := "https://rdap.org/domain/" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create rdap request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")

	transport := &http.Transport{
		DialContext:         getDialer().DialContext,
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
	d := getDialer()
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

func safeString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if list, ok := v.([]any); ok {
		var parts []string
		for _, item := range list {
			if s, ok := item.(string); ok {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		var nonEmpty []string
		for _, p := range parts {
			if p != "" {
				nonEmpty = append(nonEmpty, p)
			}
		}
		return strings.Join(nonEmpty, ", ")
	}
	return ""
}

func parseRDAP(data map[string]any) Metadata {
	m := Metadata{}
	if entities, ok := data["entities"].([]any); ok {
		parseRDAPEntities(&m, entities)
	}
	if events, ok := data["events"].([]any); ok {
		parseRDAPEvents(&m, events)
	}
	if ns, ok := data["nameservers"].([]any); ok {
		parseRDAPNameservers(&m, ns)
	}
	if status, ok := data["status"].([]any); ok {
		parseRDAPStatus(&m, status)
	}
	return m
}

func parseRDAPEntities(m *Metadata, entities []any) {
	for _, e := range entities {
		entity, ok := e.(map[string]any)
		if !ok {
			continue
		}

		// Some RDAP responses put entities recursively inside other entities
		if subEntities, subOk := entity["entities"].([]any); subOk {
			parseRDAPEntities(m, subEntities)
		}

		roles, ok := entity["roles"].([]any)
		if !ok {
			continue
		}
		for _, r := range roles {
			role, ok := r.(string)
			if !ok || (role != roleRegistrar && role != roleRegistrant) {
				continue
			}
			vcards, ok := entity["vcardArray"].([]any)
			if !ok || len(vcards) <= 1 {
				continue
			}
			props, ok := vcards[1].([]any)
			if !ok {
				continue
			}
			extractVCardProps(m, role, props)
		}
	}
}

func extractVCardProps(m *Metadata, role string, props []any) {
	var targetContact *Contact
	switch role {
	case roleRegistrar:
		targetContact = &m.Registrar
	case roleRegistrant:
		targetContact = &m.Registrant
	case roleAdministrative:
		targetContact = &m.Admin
	case roleTechnical:
		targetContact = &m.Tech
	case roleBilling:
		targetContact = &m.Billing
	case roleAbuse:
		targetContact = &m.Abuse
	default:
		return
	}

	for _, p := range props {
		applyVCardProp(m, targetContact, role, p)
	}
}

func applyVCardProp(m *Metadata, c *Contact, role string, p any) {
	prop, ok := p.([]any)
	if !ok || len(prop) < 4 {
		return
	}
	name := safeString(prop[0])
	value := safeString(prop[3])

	switch name {
	case "fn":
		c.Name = value
	case "org":
		c.Organization = value
	case "email":
		c.Email = value
	case "adr":
		c.Address = value
	case "tel":
		c.Phone = value
	case "url":
		if role == roleRegistrar {
			m.RegistrarURL = value
		}
	}
}

func parseRDAPEvents(m *Metadata, events []any) {
	for _, e := range events {
		event, ok := e.(map[string]any)
		if !ok {
			continue
		}
		action := safeString(event["eventAction"])
		date := safeString(event["eventDate"])

		switch action {
		case "registration":
			m.CreationDate = date
		case "expiration":
			m.ExpirationDate = date
		case "last changed":
			m.UpdatedDate = date
		}
	}
}

func parseRDAPNameservers(m *Metadata, ns []any) {
	for _, n := range ns {
		entry, ok := n.(map[string]any)
		if !ok {
			continue
		}
		if host := safeString(entry["ldhName"]); host != "" {
			m.NameServers = append(m.NameServers, strings.ToLower(host))
		}
	}
}

func parseRDAPStatus(m *Metadata, status []any) {
	for _, s := range status {
		if str := safeString(s); str != "" {
			m.DomainStatus = append(m.DomainStatus, str)
		}
	}
}

var whoisPatterns = map[string]*regexp.Regexp{
	"registrar":   regexp.MustCompile(`(?i)Registrar:\s+(.*)`),
	"url":         regexp.MustCompile(`(?i)Registrar\s+URL:\s+(.*)`),
	"whoisserver": regexp.MustCompile(`(?i)Registrar\s+WHOIS\s+Server:\s+(.*)`),
	"ianaid":      regexp.MustCompile(`(?i)Registrar\s+IANA\s+ID:\s+(.*)`),
	"dnssec":      regexp.MustCompile(`(?i)DNSSEC:\s+(.*)`),

	"creation":   regexp.MustCompile(`(?i)(Creation|Created|Registered)\s+Date:\s+(.*)`),
	"updated":    regexp.MustCompile(`(?i)(Updated|Last\s+Updated)\s+Date:\s+(.*)`),
	"expiration": regexp.MustCompile(`(?i)(Registry\s+Expiry|Expiration|Expires)\s+Date:\s+(.*)`),
	"ns":         regexp.MustCompile(`(?i)Name\s+Server:\s+(.*)`),
	"status":     regexp.MustCompile(`(?i)Domain\s+Status:\s+(.*)`),

	"reg_name":  regexp.MustCompile(`(?i)Registrant\s+Name:\s+(.*)`),
	"reg_org":   regexp.MustCompile(`(?i)Registrant\s+Organization:\s+(.*)`),
	"reg_email": regexp.MustCompile(`(?i)Registrant\s+Email:\s+(.*)`),
	"reg_addr":  regexp.MustCompile(`(?i)Registrant\s+(?:Street|Address|City|State/Province|Postal Code|Country):\s+(.*)`),
	"reg_phone": regexp.MustCompile(`(?i)Registrant\s+Phone:\s+(.*)`),

	"admin_name":  regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Name:\s+(.*)`),
	"admin_org":   regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Organization:\s+(.*)`),
	"admin_email": regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Email:\s+(.*)`),
	"admin_addr":  regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+(?:Street|Address|City|State/Province|Postal Code|Country):\s+(.*)`),
	"admin_phone": regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Phone:\s+(.*)`),

	"tech_name":  regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Name:\s+(.*)`),
	"tech_org":   regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Organization:\s+(.*)`),
	"tech_email": regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Email:\s+(.*)`),
	"tech_addr":  regexp.MustCompile(`(?i)(?:Tech|Technical)\s+(?:Street|Address|City|State/Province|Postal Code|Country):\s+(.*)`),
	"tech_phone": regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Phone:\s+(.*)`),

	"billing_name":  regexp.MustCompile(`(?i)Billing\s+Name:\s+(.*)`),
	"billing_org":   regexp.MustCompile(`(?i)Billing\s+Organization:\s+(.*)`),
	"billing_email": regexp.MustCompile(`(?i)Billing\s+Email:\s+(.*)`),
	"billing_addr":  regexp.MustCompile(`(?i)Billing\s+(?:Street|Address|City|State/Province|Postal Code|Country):\s+(.*)`),
	"billing_phone": regexp.MustCompile(`(?i)Billing\s+Phone:\s+(.*)`),

	"abuse_email": regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Email:\s+(.*)`),
	"abuse_phone": regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Phone:\s+(.*)`),
}

func parseWHOIS(raw string) Metadata {
	m := Metadata{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		for key, re := range whoisPatterns {
			match := re.FindStringSubmatch(line)
			if len(match) <= 1 {
				continue
			}
			val := strings.TrimSpace(match[len(match)-1])
			applyWHOISMatch(&m, key, val)
		}
	}
	return m
}

func applyWHOISMatch(m *Metadata, key, val string) {
	if applyRegistrarMatch(m, key, val) {
		return
	}
	if applyContactMatch(&m.Registrant, key, "reg_", val) {
		return
	}
	if applyContactMatch(&m.Admin, key, "admin_", val) {
		return
	}
	if applyContactMatch(&m.Tech, key, "tech_", val) {
		return
	}
	if applyContactMatch(&m.Billing, key, "billing_", val) {
		return
	}
	if applyContactMatch(&m.Abuse, key, "abuse_", val) {
		return
	}
	applyDomainMatch(m, key, val)
}

func applyRegistrarMatch(m *Metadata, key, val string) bool {
	switch key {
	case "registrar":
		if m.Registrar.Name == "" {
			m.Registrar.Name = val
		}
		return true
	case "url":
		if m.RegistrarURL == "" {
			m.RegistrarURL = val
		}
		return true
	case "whoisserver":
		if m.WhoisServer == "" {
			m.WhoisServer = val
		}
		return true
	case "ianaid":
		if m.IANAID == "" {
			m.IANAID = val
		}
		return true
	case "dnssec":
		if m.DNSSEC == "" {
			m.DNSSEC = val
		}
		return true
	}
	return false
}

func applyContactMatch(c *Contact, key, prefix, val string) bool {
	if !strings.HasPrefix(key, prefix) {
		return false
	}
	field := strings.TrimPrefix(key, prefix)
	switch field {
	case "org":
		if c.Organization == "" {
			c.Organization = val
		}
		return true
	case "name":
		if c.Name == "" {
			c.Name = val
		}
		return true
	case "email":
		if c.Email == "" {
			c.Email = val
		}
		return true
	case "addr":
		if c.Address == "" {
			c.Address = val
		} else {
			c.Address += ", " + val
		}
		return true
	case "phone":
		if c.Phone == "" {
			c.Phone = val
		}
		return true
	}
	return false
}

func applyDomainMatch(m *Metadata, key, val string) {
	switch key {
	case "creation":
		if m.CreationDate == "" {
			m.CreationDate = val
		}
	case "updated":
		if m.UpdatedDate == "" {
			m.UpdatedDate = val
		}
	case "expiration":
		if m.ExpirationDate == "" {
			m.ExpirationDate = val
		}
	case "ns":
		m.NameServers = append(m.NameServers, strings.ToLower(val))
	case "status":
		m.DomainStatus = append(m.DomainStatus, val)
	}
}
