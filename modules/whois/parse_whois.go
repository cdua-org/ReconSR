package whois

import (
	"bufio"
	"regexp"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
)

var dotPaddingRe = regexp.MustCompile(`\.{2,}:\s*`)

type roleMarker struct {
	pattern  string
	role     string
	isPrefix bool
}

var roleMarkers = []roleMarker{
	// Contains: generic ICANN / RPSL / EDUCAUSE
	{"registrar:", whoisRoleRegistrar, false},
	{"registrant:", whoisRoleRegistrant, false},
	{"administrative contact:", whoisRoleAdministrative, false},
	{"billing contact:", whoisRoleBilling, false},
	{"admin:", whoisRoleAdministrative, false},
	{"administrative:", whoisRoleAdministrative, false},
	{"technical contact:", whoisRoleTechnical, false},
	{"tech:", whoisRoleTechnical, false},
	{"technical:", whoisRoleTechnical, false},
	{"abuse:", whoisRoleAbuse, false},
	{"abuse contact:", whoisRoleAbuse, false},
	{"name servers:", whoisRoleNameServers, false},
	{"domain nameservers:", whoisRoleNameServers, false},
	{"domain servers in listed order:", whoisRoleNameServers, false},

	// Prefix: Italian/generic bare-word sections
	{"holder", whoisRoleRegistrant, true},
	{"admin contact", whoisRoleAdministrative, true},
	{"technical", whoisRoleTechnical, true},
	{"registrant", whoisRoleRegistrant, true},
	{whoisRoleRegistrar, whoisRoleRegistrar, true},
	{"nameservers", whoisRoleNameServers, true},

	// Prefix: Korean name server sections
	{"primary name server", whoisRoleNameServers, true},
	{"secondary name server", whoisRoleNameServers, true},

	// Prefix: Austrian RPSL-style sections
	{"tech-c:", whoisRoleTechnical, true},
	{"admin-c:", whoisRoleAdministrative, true},
}

func updateRoleContext(lineLower, currentRole string) string {
	if strings.HasPrefix(lineLower, "contact:") {
		if strings.Contains(lineLower, "administrative") {
			return whoisRoleAdministrative
		}
		if strings.Contains(lineLower, "technical") {
			return whoisRoleTechnical
		}
		if strings.Contains(lineLower, "billing") {
			return whoisRoleBilling
		}
	}

	for _, m := range roleMarkers {
		if m.isPrefix {
			if strings.HasPrefix(lineLower, m.pattern) {
				rest := strings.TrimSpace(lineLower[len(m.pattern):])
				if !strings.Contains(rest, ":") || rest == ":" || strings.HasPrefix(rest, ": ") {
					return m.role
				}
			}
		} else if strings.Contains(lineLower, m.pattern) {
			return m.role
		}
	}

	if strings.HasSuffix(lineLower, ":") {
		return ""
	}

	return currentRole
}

var whoisPatterns = map[string]*regexp.Regexp{
	// Generic ICANN
	whoisRoleRegistrar:    regexp.MustCompile(`(?i)Registrar(?:\s+Name)?\s*:\s+(.*)`),
	constants.TypeURL:     regexp.MustCompile(`(?i)(?:Registrar\s+)?(?:URL|Web)\s*:\s+(.*)`),
	"url_bare":            regexp.MustCompile(`(?i)^\s*(https?://[^\s<>]+)\s*$`),
	whoisFieldWhoisServer: regexp.MustCompile(`(?i)Registrar\s+WHOIS\s+Server\s*:\s+(.*)`),
	whoisFieldIANAID:      regexp.MustCompile(`(?i)Registrar\s+IANA\s+ID\s*:\s+(.*)`),
	whoisFieldDNSSEC:      regexp.MustCompile(`(?i)DNSSEC\s*:\s*(.*)`),
	whoisFieldCreation:    regexp.MustCompile(`(?i)(Creation|Created(?:\s+On)?|Registered(?:\s+on)?|Activated|Registration\s+Time|Registered\s+Time)(?:\s+Date)?\s*:\s+(.*)`),
	whoisFieldUpdated:     regexp.MustCompile(`(?i)(Updated|Last[\s-]+Updated|Last[\s-]+Update|Last\s+Modified|Modified|Changed)(?:\s+(?:Date|On))?(?:\s*:\s*|\s+)(.*)`),
	whoisFieldExpiration:  regexp.MustCompile(`(?i)(Registry\s+Expiry|Expiration|Expiry|Expire|Expires|Expiration\s+Time|paid-till|Renewal\s+Date)(?:\s+Date)?\s*:\s+(.*)`),
	whoisFieldNameServer:  regexp.MustCompile(`(?i)(Name\s+Server|nserver|nameservers?|DNS)\s*:\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),
	whoisFieldStatus:      regexp.MustCompile(`(?i)(Domain\s+)?(Status|State)\s*:\s+(.*)`),

	// Registrant contact (ICANN standard)
	"reg_name":  regexp.MustCompile(`(?i)Registrant\s+(?:Contact\s+)?Name\s*:\s+(.*)`),
	"reg_org":   regexp.MustCompile(`(?i)Registrant\s+Organization\s*:\s+(.*)`),
	"reg_email": regexp.MustCompile(`(?i)Registrant\s+Email\s*:\s+(.*)`),
	"reg_addr":  regexp.MustCompile(`(?i)Registrant\s+(?:Street|Address|City|State/Province|Postal Code|Country|Zip\s+Code)\s*:\s+(.*)`),
	"reg_phone": regexp.MustCompile(`(?i)Registrant\s+Phone\s*:\s+(.*)`),
	"reg_fax":   regexp.MustCompile(`(?i)Registrant\s+Fax\s*:\s+(.*)`),

	// Admin contact (ICANN standard)
	"admin_name":  regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+(?:Contact\s+)?Name\s*:\s+(.*)`),
	"admin_org":   regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Organization\s*:\s+(.*)`),
	"admin_email": regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Email\s*:\s+(.*)`),
	"admin_addr":  regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+(?:Street|Address|City|State/Province|Postal Code|Country)\s*:\s+(.*)`),
	"admin_phone": regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Phone\s*:\s+(.*)`),
	"admin_fax":   regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Fax\s*:\s+(.*)`),

	// Tech contact (ICANN standard)
	"tech_name":  regexp.MustCompile(`(?i)(?:Tech|Technical)\s+(?:Contact\s+)?Name\s*:\s+(.*)`),
	"tech_org":   regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Organization\s*:\s+(.*)`),
	"tech_email": regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Email\s*:\s+(.*)`),
	"tech_addr":  regexp.MustCompile(`(?i)(?:Tech|Technical)\s+(?:Street|Address|City|State/Province|Postal Code|Country)\s*:\s+(.*)`),
	"tech_phone": regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Phone\s*:\s+(.*)`),
	"tech_fax":   regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Fax\s*:\s+(.*)`),

	// Billing contact (ICANN standard)
	"billing_name":  regexp.MustCompile(`(?i)Billing\s+(?:Contact\s+)?Name\s*:\s+(.*)`),
	"billing_org":   regexp.MustCompile(`(?i)Billing\s+Organization\s*:\s+(.*)`),
	"billing_email": regexp.MustCompile(`(?i)Billing\s+Email\s*:\s+(.*)`),
	"billing_addr":  regexp.MustCompile(`(?i)Billing\s+(?:Street|Address|City|State/Province|Postal Code|Country)\s*:\s+(.*)`),
	"billing_phone": regexp.MustCompile(`(?i)Billing\s+Phone\s*:\s+(.*)`),
	"billing_fax":   regexp.MustCompile(`(?i)Billing\s+Fax\s*:\s+(.*)`),

	// Abuse contact
	"abuse_email": regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Email\s*:\s+(.*)`),
	"abuse_phone": regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Phone\s*:\s+(.*)`),
	"abuse_fax":   regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Fax\s*:\s+(.*)`),

	// Taiwanese .tw WHOIS
	"tw_created":   regexp.MustCompile(`(?i)Record\s+created\s+on\s+(.*)`),
	"tw_expires":   regexp.MustCompile(`(?i)Record\s+expires\s+on\s+(.*)`),
	"tw_registrar": regexp.MustCompile(`(?i)Registration\s+Service\s+Provider\s*:\s+(.*)`),
	"tw_url":       regexp.MustCompile(`(?i)Registration\s+Service\s+URL\s*:\s+(.*)`),

	// Norwegian .no WHOIS (Handles)
	"no_registrar": regexp.MustCompile(`(?i)Registrar\s+Handle\s*:\s+(.*)`),
	"no_nserver":   regexp.MustCompile(`(?i)Name\s+Server\s+Handle\s*:\s+(.*)`),
	"no_tech":      regexp.MustCompile(`(?i)Tech-c\s+Handle\s*:\s+(.*)`),

	// RPSL / generic unstructured
	"rpsl_name":        regexp.MustCompile(`(?i)^\s*(?:person(?:name)?|name)(?:-loc)?\s*:\s+(.*)`),
	"rpsl_org":         regexp.MustCompile(`(?i)^\s*(?:organi[zs]ation|org)(?:-loc)?\s*:\s+(.*)`),
	"rpsl_email":       regexp.MustCompile(`(?i)^\s*(?:e-mail|email|abuse-email|holder\s+email)\s*:\s+(.*)`),
	whoisFieldRPSLAddr: regexp.MustCompile(`(?i)^\s*(?:address|street(?:\s+address)?|city|state|postal(?:\s*-?code)?|country|abuse-postal)(?:-loc)?\s*:\s+(.*)`),
	"rpsl_phone":       regexp.MustCompile(`(?i)^\s*(?:phone|tel|abuse-phone)(?:-loc)?\s*:\s+(.*)`),
	"rpsl_fax":         regexp.MustCompile(`(?i)^\s*(?:fax(?:-no)?)(?:-loc)?\s*:\s+(.*)`),

	// Chinese WHOIS
	whoisFieldCNRegistrant:      regexp.MustCompile(`(?i)Registrant\s*:\s+(.+)`),
	whoisFieldCNRegistrantEmail: regexp.MustCompile(`(?i)Registrant\s+Contact\s+Email\s*:\s+(.+)`),

	// Japanese WHOIS (JPRS format 1)
	"jp_domain":      regexp.MustCompile(`(?i)a\.\s*\[Domain\s+Name\]\s+(.+)`),
	"jp_org":         regexp.MustCompile(`(?i)g\.\s*\[Organization\]\s+(.+)`),
	"jp_org_type":    regexp.MustCompile(`(?i)l\.\s*\[Organization\s+Type\]\s+(.+)`),
	"jp_admin":       regexp.MustCompile(`(?i)m\.\s*\[Administrative\s+Contact\]\s+(.+)`),
	"jp_tech":        regexp.MustCompile(`(?i)n\.\s*\[Technical\s+Contact\]\s+(.+)`),
	"jp_registered":  regexp.MustCompile(`(?i)\[Registered\s+Date\]\s+(.+)`),
	"jp_connected":   regexp.MustCompile(`(?i)\[Connected\s+Date\]\s+(.+)`),
	"jp_last_update": regexp.MustCompile(`(?i)\[Last\s+Update\]\s+(.+)`),
	"jp_state":       regexp.MustCompile(`(?i)\[State\]\s+(.+)`),
	"jp_lock":        regexp.MustCompile(`(?i)\[Lock\s+Status\]\s+(.+)`),
	"ns_jp":          regexp.MustCompile(`(?i)p\.\s*\[Name\s+Server\]\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),

	// Japanese WHOIS (JPRS format 2 — bracket style)
	"jp2_ns":                regexp.MustCompile(`(?i)\[Name\s+Server\]\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),
	"jp2_created":           regexp.MustCompile(`(?i)\[Created\s+on\]\s+(.+)`),
	"jp2_expires":           regexp.MustCompile(`(?i)\[Expires\s+on\]\s+(.+)`),
	"jp2_status":            regexp.MustCompile(`(?i)\[Status\]\s+(.+)`),
	"jp2_registrant":        regexp.MustCompile(`(?i)\[Registrant\]\s+(.+)`),
	"jp2_lock":              regexp.MustCompile(`(?i)\[Lock\s+Status\]\s+(.+)`),
	"jp2_updated":           regexp.MustCompile(`(?i)\[Last\s+Updated\]\s+(.+)`),
	"jp2_contact_name":      regexp.MustCompile(`(?i)\[Name\]\s+(.+)`),
	"jp2_contact_email":     regexp.MustCompile(`(?i)\[Email\]\s+(.+)`),
	whoisFieldJP2PostalCode: regexp.MustCompile(`(?i)\[Postal\s+code\]\s+(.+)`),
	whoisFieldJP2Address:    regexp.MustCompile(`(?i)\[Postal\s+Address\]\s+(.+)`),
	"jp2_phone":             regexp.MustCompile(`(?i)\[Phone\]\s+(.+)`),
	"jp2_fax":               regexp.MustCompile(`(?i)\[Fax\]\s+(.+)`),

	// Austrian .at WHOIS
	"at_changed": regexp.MustCompile(`(?i)^\s*changed\s*:\s+(.*)`),
	"at_tech_c":  regexp.MustCompile(`(?i)^\s*tech-c\s*:\s+(.*)`),
	"at_admin_c": regexp.MustCompile(`(?i)^\s*admin-c\s*:\s+(.*)`),
	"at_nserver": regexp.MustCompile(`(?i)^\s*nserver\s*:\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),

	// Korean .kr WHOIS
	"kr_hostname":      regexp.MustCompile(`(?i)Host\s+Name\s*:\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),
	"kr_agency":        regexp.MustCompile(`(?i)Authorized\s+Agency\s*:\s+(.*)`),
	"kr_ac_name":       regexp.MustCompile(`(?i)Administrative\s+Contact\(AC\)\s*:\s+(.*)`),
	"kr_ac_email":      regexp.MustCompile(`(?i)AC\s+E-Mail\s*:\s+(.*)`),
	"kr_ac_phone":      regexp.MustCompile(`(?i)AC\s+Phone\s+Number\s*:\s+(.*)`),
	whoisFieldKRRegZip: regexp.MustCompile(`(?i)Registrant\s+Zip\s+Code\s*:\s+(.*)`),

	// Brazilian .br WHOIS
	"br_owner":   regexp.MustCompile(`(?i)^owner\s*:\s+(.*)`),
	"br_ownerid": regexp.MustCompile(`(?i)^ownerid\s*:\s+(.*)`),
}

func parseWHOIS(raw string) Metadata {
	m := Metadata{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	currentRole := ""
	indentedIndex := 0
	lastKey := ""
	handleRoles := make(map[string]string)

	rawLower := strings.ToLower(raw)
	registryType := detectRegistry(rawLower)

	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)

		line = dotPaddingRe.ReplaceAllString(line, ": ")

		if skipLine(line) {
			if line == "" {
				currentRole = ""
			}
			continue
		}
		if isFooterMarker(line) {
			break
		}
		lineLower := strings.ToLower(line)

		newRole := updateRoleContext(lineLower, currentRole)
		roleChanged := newRole != currentRole
		if roleChanged {
			currentRole = newRole
			indentedIndex = 0
		}

		parts := strings.SplitN(lineLower, ":", 2)
		if len(parts) == 2 && processHandles(parts, handleRoles, &currentRole, registryType) {
			continue
		}

		matched, key := matchPatterns(&m, currentRole, line, lineLower, registryType)
		if matched {
			lastKey = key
			if isDomainLevelKey(key) {
				currentRole = ""
			}
		}

		if matched || roleChanged {
			continue
		}

		if isContinuation(rawLine, line, lastKey) {
			applyContinuation(&m, lastKey, currentRole, line)
			continue
		}

		if currentRole == whoisRoleNameServers {
			addNameServer(&m, strings.Fields(line)[0])
		} else if isFreeformLine(rawLine, line, currentRole) {
			classifyIndentedLine(&m, currentRole, line, indentedIndex)
			indentedIndex++
		}
	}
	return m
}

func matchPatterns(m *Metadata, currentRole, line, lineLower, registryType string) (matched bool, matchedKey string) {
	for key, re := range whoisPatterns {
		if strings.HasPrefix(lineLower, "state:") {
			if key == whoisFieldStatus && currentRole != "" {
				continue
			}
			if key == whoisFieldRPSLAddr && currentRole == "" {
				continue
			}
		}

		match := re.FindStringSubmatch(line)
		if len(match) <= 1 {
			continue
		}
		val := strings.TrimSpace(match[len(match)-1])
		if isPlaceholder(val) {
			return true, key
		}

		if field, found := strings.CutPrefix(key, "rpsl_"); found {
			applyRPSLMatch(m, currentRole, lineLower, field, val, registryType)
		} else {
			applyWHOISMatch(m, key, val)
		}
		return true, key
	}
	return false, ""
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
	if strings.HasPrefix(key, "tw_") {
		applyTWMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "no_") {
		applyNOMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "jp") || strings.HasPrefix(key, "ns_jp") {
		applyJPMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "at_") {
		applyAustrianMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "br_") {
		applyBRMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "kr_") {
		applyKRMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "cn_") {
		applyCNMatch(m, key, val)
		return
	}
	applyDomainMatch(m, key, val)
}
