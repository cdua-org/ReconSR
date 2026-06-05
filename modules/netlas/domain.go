package netlas

import (
	"encoding/json"
	"fmt"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

func (m *netlasModule) getNetlasDomain(target schema.Entity, fn string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(fn)
	targetValue := target.Value
	dbg.Printf("%s target=%q", fn, targetValue)

	u := fmt.Sprintf("%s/%s/?source_type=include&fields=*", netlasAPIBaseURL, targetValue)

	if m.apiKey == demoIndicator {
		if !m.demoDomainFired.CompareAndSwap(false, true) {
			dbg.Printf("%s skipped stage=demo_already_fired target=%q", fn, targetValue)
			return exec
		}
		dbg.Printf("%s start stage=demo_mode", fn)
		return m.runDemoDomain(exec, target, gen)
	}

	rawBody, ok := m.doAPIRequest(&exec, u, targetValue, gen)
	if !ok {
		return exec
	}

	exec.RawData = string(rawBody)

	var resp netlasResponse
	if err := json.Unmarshal(rawBody, &resp); err != nil {
		dbg.Printf("%s error stage=parse_json err=%v", fn, err)
		modutil.SetError(&exec, "parse json: %v", err)
		return exec
	}

	if resp.Domain == "" {
		dbg.Printf("%s empty_response target=%q", fn, targetValue)
		return exec
	}

	parseDomainResponse(&exec, &resp, target, gen)
	dbg.Printf("%s success target=%q results=%d", fn, targetValue, len(exec.Results))

	return exec
}

func parseDomainResponse(exec *schema.ModuleExecution, resp *netlasResponse, target schema.Entity, gen *modutil.LocalIDGenerator) {
	targetRef := &schema.EntityRef{Type: target.Type, Value: target.Value}
	targetValue := target.Value

	if resp.Domain != "" {
		if res, err := validator.Validate(constants.TypeDomain, resp.Domain); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     res.Type,
				Category: constants.CategoryNode,
				Value:    res.Value,
				Applied:  true,
				LocalID:  gen.NextID(),
			})
		}
	}

	portRefs := parsePorts(exec, resp.Ports, targetRef, gen)
	parseSoftware(exec, resp.Software, portRefs, targetRef, gen)
	parseIoC(exec, resp.IoC, targetRef, nil, gen)
	parseDomainDNS(exec, resp.DNS, targetRef, targetValue, gen)

	parseNetlasDomains(exec, resp.DomainsCount, resp.Domains, constants.TagReverseIP, targetRef, gen)
	parseNetlasDomains(exec, resp.RelatedDomainsCount, resp.RelatedDomains, constants.TagPDNS, targetRef, gen)

	if resp.Whois != nil {
		parseDomainWhois(exec, resp.Whois, targetRef, targetValue, gen)
	}
}

func parseDomainDNS(exec *schema.ModuleExecution, dns *netlasDNS, targetRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	if dns == nil {
		return
	}
	parseDomainDNSSimple(exec, dns, targetRef, targetValue, gen)

	for _, mx := range dns.MX {
		if mx == "" {
			continue
		}
		host := strings.TrimSuffix(mx, ".")
		res, err := validator.Validate(constants.TypeDomain, host)
		if err != nil {
			continue
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       res.Type,
			Category:   constants.CategoryNode,
			Value:      res.Value,
			Tags:       []string{constants.TagMX},
			Source:     targetRef,
			LocalID:    gen.NextID(),
			OutOfScope: orgdomain.IsOutOfScope(host, targetValue),
		})
	}
	for _, ns := range dns.NS {
		res, err := validator.Validate(constants.TypeDomain, ns)
		if err != nil {
			continue
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       res.Type,
			Category:   constants.CategoryNode,
			Value:      res.Value,
			Tags:       []string{constants.TagNS},
			Source:     targetRef,
			LocalID:    gen.NextID(),
			OutOfScope: orgdomain.IsOutOfScope(ns, targetValue),
		})
	}
	parseDomainDNSTXT(exec, dns, targetRef, targetValue, gen)
}

func parseDomainDNSTXT(exec *schema.ModuleExecution, dns *netlasDNS, targetRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	for _, txt := range dns.TXT {
		txt = strings.TrimSpace(strings.Trim(txt, "\""))
		if txt == "" {
			continue
		}
		switch {
		case strings.HasPrefix(txt, "v=spf1"):
			parseDomainDNSSPF(exec, txt, targetRef, targetValue, gen)
		case strings.HasPrefix(txt, "v=DMARC1"):
			parseDomainDNSDMARC(exec, txt, targetRef, targetValue, gen)
		default:
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeTXT,
				Category: constants.CategoryProperty,
				Value:    txt,
				Source:   targetRef,
				LocalID:  gen.NextID(),
			})
		}
	}
}

func parseDomainDNSSPF(exec *schema.ModuleExecution, txt string, targetRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	spfLocalID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSPF,
		Category: constants.CategoryProperty,
		Value:    txt,
		Source:   targetRef,
		LocalID:  spfLocalID,
	})
	spfRef := &schema.EntityRef{Type: constants.TypeSPF, Value: txt, LocalID: spfLocalID}

	for _, entity := range dnsutils.ParseSPF(txt) {
		t := constants.TypeDomain
		switch entity.Kind {
		case dnsutils.SPFEntityIP4:
			if strings.Contains(entity.Value, "/") {
				t = constants.TypeCIDR
			} else {
				t = constants.TypeIPv4
			}
		case dnsutils.SPFEntityIP6:
			if strings.Contains(entity.Value, "/") {
				t = constants.TypeCIDR
			} else {
				t = constants.TypeIPv6
			}
		}

		res, err := validator.Validate(t, entity.Value)
		if err != nil {
			continue
		}
		entity.Value = res.Value
		t = res.Type

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       t,
			Category:   constants.CategoryNode,
			Value:      entity.Value,
			Tags:       []string{constants.TagSPF},
			Source:     spfRef,
			LocalID:    gen.NextID(),
			OutOfScope: (t == constants.TypeDomain) && orgdomain.IsOutOfScope(entity.Value, targetValue),
		})
	}
}

func parseDomainDNSDMARC(exec *schema.ModuleExecution, txt string, targetRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	dmarcLocalID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeDMARC,
		Category: constants.CategoryProperty,
		Value:    txt,
		Source:   targetRef,
		LocalID:  dmarcLocalID,
	})
	dmarcRef := &schema.EntityRef{Type: constants.TypeDMARC, Value: txt, LocalID: dmarcLocalID}

	dmarcMap := dnsutils.ParseDMARC(txt)
	emitDMARCEmails := func(tagValue, context string) {
		emails := dnsutils.ExtractDMARCEmails(tagValue)
		for _, email := range emails {
			res, err := validator.Validate(constants.TypeEmail, email)
			if err != nil {
				continue
			}
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       res.Type,
				Category:   constants.CategoryNode,
				Value:      res.Value,
				Context:    context,
				Source:     dmarcRef,
				LocalID:    gen.NextID(),
				OutOfScope: orgdomain.IsEmailOutOfScope(email, targetValue),
			})
		}
	}

	if rua, ok := dmarcMap["rua"]; ok {
		emitDMARCEmails(rua, "DMARC Aggregate Reports (rua)")
	}
	if ruf, ok := dmarcMap["ruf"]; ok {
		emitDMARCEmails(ruf, "DMARC Forensic Reports (ruf)")
	}
}

func parseDomainDNSSimple(exec *schema.ModuleExecution, dns *netlasDNS, targetRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	for _, a := range dns.A {
		if a == "" {
			continue
		}
		if val, err := validator.Validate(constants.TypeIPv4, a); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     val.Type,
				Category: constants.CategoryNode,
				Value:    val.Value,
				Source:   targetRef,
				LocalID:  gen.NextID(),
			})
		}
	}
	for _, aaaa := range dns.AAAA {
		if aaaa == "" {
			continue
		}
		if val, err := validator.Validate(constants.TypeIPv6, aaaa); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     val.Type,
				Category: constants.CategoryNode,
				Value:    val.Value,
				Source:   targetRef,
				LocalID:  gen.NextID(),
			})
		}
	}
	for _, cname := range dns.CNAME {
		res, err := validator.Validate(constants.TypeDomain, cname)
		if err != nil {
			continue
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       res.Type,
			Category:   constants.CategoryNode,
			Value:      res.Value,
			Tags:       []string{constants.TagCNAME},
			Source:     targetRef,
			LocalID:    gen.NextID(),
			OutOfScope: orgdomain.IsOutOfScope(cname, targetValue),
		})
	}
}

func parseDomainWhois(exec *schema.ModuleExecution, w *netlasWhoisDomain, targetRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	ParseWhoisDates(exec, w.CreatedDate, w.UpdatedDate, "", targetRef, gen)
	if w.ExpirationDate != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Expiration Date: " + w.ExpirationDate,
			Context:  "Domain Whois Expiry",
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}
	if w.Server != "" {
		if res, err := validator.Validate(constants.TypeDomain, w.Server); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       res.Type,
				Category:   constants.CategoryNode,
				Value:      res.Value,
				Tags:       []string{constants.TagWhoisServer},
				Source:     targetRef,
				LocalID:    gen.NextID(),
				OutOfScope: true,
			})
		}
	}

	for _, st := range w.Status {
		if st == "" {
			continue
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeStatus,
			Category: constants.CategoryProperty,
			Value:    st,
			Context:  "Domain Whois Status",
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}

	for _, ns := range w.NameServers {
		if !strings.Contains(ns, ".") {
			oos := !strings.HasSuffix(strings.ToLower(ns), "."+strings.ToLower(targetValue))
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       constants.TypeHandle,
				Category:   constants.CategoryProperty,
				Value:      ns,
				Tags:       []string{constants.TagNS},
				Source:     targetRef,
				LocalID:    gen.NextID(),
				OutOfScope: oos,
			})
			continue
		}

		res, err := validator.Validate(constants.TypeDomain, ns)
		if err != nil {
			continue
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       res.Type,
			Category:   constants.CategoryNode,
			Value:      res.Value,
			Tags:       []string{constants.TagNS},
			Source:     targetRef,
			LocalID:    gen.NextID(),
			OutOfScope: orgdomain.IsOutOfScope(res.Value, targetValue),
		})
	}

	addContact(exec, w.Registrar, constants.TypeWhoisRegistrar, targetRef, targetValue, gen)
	addContact(exec, w.Registrant, constants.TypeWhoisRegistrant, targetRef, targetValue, gen)
	addContact(exec, w.Administrative, constants.TypeWhoisAdmin, targetRef, targetValue, gen)
	addContact(exec, w.Technical, constants.TypeWhoisTech, targetRef, targetValue, gen)
}

func getContactRoleName(contactType string) string {
	switch contactType {
	case constants.TypeWhoisRegistrant:
		return "Registrant"
	case constants.TypeWhoisAdmin:
		return "Admin Contact"
	case constants.TypeWhoisTech:
		return "Tech Contact"
	case constants.TypeWhoisRegistrar:
		return "Registrar"
	default:
		return "Contact"
	}
}

func addContact(exec *schema.ModuleExecution, c *netlasWhoisContact, contactType string, targetRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	if c == nil {
		return
	}
	if c.Name == "" && c.Organization == "" && c.Email == "" {
		return
	}

	roleName := getContactRoleName(contactType)
	roleValue := roleName + " of " + targetValue

	isOOS := (contactType == constants.TypeWhoisRegistrar)

	contactID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       contactType,
		Category:   constants.CategoryNode,
		Value:      roleValue,
		Source:     targetRef,
		LocalID:    contactID,
		OutOfScope: isOOS,
	})
	cRef := &schema.EntityRef{Type: contactType, Value: roleValue, LocalID: contactID}

	emitContactNodes(exec, c, cRef, targetValue, isOOS, gen)
}

func emitContactNodes(exec *schema.ModuleExecution, c *netlasWhoisContact, cRef *schema.EntityRef, targetValue string, isOOS bool, gen *modutil.LocalIDGenerator) {
	if c.Name != "" && !isRedacted(c.Name) {
		person := formatPerson(c.Name)
		if person != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       constants.TypePerson,
				Category:   constants.CategoryNode,
				Value:      person,
				Source:     cRef,
				LocalID:    gen.NextID(),
				OutOfScope: isOOS,
			})
		}
	}
	if c.Organization != "" && !isRedacted(c.Organization) {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       constants.TypeOrganization,
			Category:   constants.CategoryNode,
			Value:      c.Organization,
			Source:     cRef,
			LocalID:    gen.NextID(),
			OutOfScope: isOOS,
		})
	}
	if c.Email != "" {
		ParseEmails(exec, []string{c.Email}, constants.CategoryNode, targetValue, isOOS, cRef, gen)
	}
	if c.Phone != "" {
		ParsePhones(exec, []string{c.Phone}, constants.CategoryNode, isOOS, cRef, gen)
	}
	if c.Fax != "" {
		ParsePhones(exec, []string{c.Fax}, constants.CategoryNode, isOOS, cRef, gen)
	}

	addressParts := []string{c.Street, c.City, c.Province, c.PostalCode, c.Country}
	var validAddressParts []string
	for _, part := range addressParts {
		if part != "" && part != "None" && !isRedacted(part) {
			validAddressParts = append(validAddressParts, strings.TrimSpace(part))
		}
	}
	if len(validAddressParts) > 0 {
		address := strings.Join(validAddressParts, ", ")
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       constants.TypeAddress,
			Category:   constants.CategoryNode,
			Value:      address,
			Source:     cRef,
			LocalID:    gen.NextID(),
			OutOfScope: isOOS,
		})
	}
}
