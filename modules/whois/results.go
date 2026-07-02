package whois

import (
	"slices"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

func (m *module) buildResults(metadata *Metadata, target, methodUsed string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	results := make([]schema.ModuleResult, 0, 35)

	sourceCtx := "RDAP"
	if methodUsed == "TCP 43 WHOIS" {
		sourceCtx = "WHOIS"
	}

	registrantAnchor, regResults := m.getRegistrantAnchor(metadata, target, sourceCtx, gen)
	results = append(results, regResults...)

	registrarAnchor, regrResults := m.getRegistrarAnchor(metadata, target, sourceCtx, gen)
	results = append(results, regrResults...)

	m.appendContact(&results, &metadata.Registrar, "Registrar", "", true, registrarAnchor, sourceCtx, target, gen)
	m.appendContact(&results, &metadata.Abuse, "Abuse", constants.TypeWhoisAbuse, true, registrarAnchor, sourceCtx, target, gen)

	m.appendContact(&results, &metadata.Registrant, "Registrant", "", false, registrantAnchor, sourceCtx, target, gen)
	m.appendContact(&results, &metadata.Admin, "Admin", constants.TypeWhoisAdmin, false, registrantAnchor, sourceCtx, target, gen)
	m.appendContact(&results, &metadata.Tech, "Tech", constants.TypeWhoisTech, false, registrantAnchor, sourceCtx, target, gen)
	m.appendContact(&results, &metadata.Billing, "Billing", constants.TypeWhoisBilling, false, registrantAnchor, sourceCtx, target, gen)

	results = append(results, m.buildMetadataResults(metadata, target, sourceCtx, registrarAnchor, gen)...)
	return results
}

func (m *module) appendSlice(results *[]schema.ModuleResult, arr []string, typ, prefix string, isOOS bool, anchor *schema.EntityRef, sourceCtx string, gen *modutil.LocalIDGenerator) {
	for _, v := range arr {
		v = strings.TrimSpace(v)
		if v != "" {
			category := constants.CategoryProperty
			resolvedType := typ
			if typ == constants.TypePerson || typ == constants.TypeEmail {
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
			*results = append(*results, m.result(resolvedType, category, v, prefix+" ("+sourceCtx+")", isOOS, anchor, gen))
		}
	}
}

func (m *module) appendAddress(results *[]schema.ModuleResult, arr []string, typ, prefix string, isOOS bool, anchor *schema.EntityRef, sourceCtx string, gen *modutil.LocalIDGenerator) {
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
		*results = append(*results, m.result(typ, constants.CategoryProperty, mergedAddress, prefix+" Address ("+sourceCtx+")", isOOS, anchor, gen))
	}
}

func (m *module) appendContact(results *[]schema.ModuleResult, c *Contact, roleName, roleType string, forceOOS bool, anchor *schema.EntityRef, sourceCtx, target string, gen *modutil.LocalIDGenerator) {
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
		*results = append(*results, m.result(roleType, constants.CategoryNode, roleValue, roleName+" Contact ("+sourceCtx+")", isOOS, anchor, gen))
		currentAnchor = &schema.EntityRef{Type: roleType, Value: roleValue, LocalID: (*results)[len(*results)-1].LocalID}
	}

	m.appendSlice(results, c.Name, constants.TypePerson, roleName+" Name", isOOS, currentAnchor, sourceCtx, gen)
	m.appendSlice(results, c.Organization, constants.TypeOrganization, roleName+" Organization", isOOS, currentAnchor, sourceCtx, gen)
	m.appendSlice(results, c.Email, constants.TypeEmail, roleName+" Email", isOOS, currentAnchor, sourceCtx, gen)
	m.appendAddress(results, c.Address, "address", roleName, isOOS, currentAnchor, sourceCtx, gen)

	for _, p := range c.Phone {
		cleanPhone := normalizePhone(p)
		if cleanPhone != "" {
			*results = append(*results, m.result(constants.TypePhone, constants.CategoryNode, cleanPhone, roleName+" Phone ("+sourceCtx+")", isOOS, currentAnchor, gen))
		}
	}
}

func (m *module) getRegistrantAnchor(metadata *Metadata, target, sourceCtx string, gen *modutil.LocalIDGenerator) (*schema.EntityRef, []schema.ModuleResult) {
	if hasContactData(&metadata.Registrant) || hasContactData(&metadata.Admin) || hasContactData(&metadata.Tech) || hasContactData(&metadata.Billing) {
		regValue := "Registrant of " + target
		localID := gen.NextID()
		res := []schema.ModuleResult{{
			Type:     constants.TypeWhoisRegistrant,
			Category: constants.CategoryNode,
			Value:    regValue,
			Context:  "Domain Registrant (" + sourceCtx + ")",
			Applied:  true,
			LocalID:  localID,
		}}
		return &schema.EntityRef{Type: constants.TypeWhoisRegistrant, Value: regValue, LocalID: localID}, res
	}
	return nil, nil
}

func (m *module) getRegistrarAnchor(metadata *Metadata, target, sourceCtx string, gen *modutil.LocalIDGenerator) (*schema.EntityRef, []schema.ModuleResult) {
	if hasContactData(&metadata.Registrar) || hasContactData(&metadata.Abuse) || metadata.RegistrarURL != "" || metadata.WhoisServer != "" || metadata.IANAID != "" {
		regValue := "Registrar of " + target
		localID := gen.NextID()
		res := []schema.ModuleResult{{
			Type:     constants.TypeWhoisRegistrar,
			Category: constants.CategoryNode,
			Value:    regValue,
			Context:  "Domain Registrar (" + sourceCtx + ")",
			Applied:  true,
			LocalID:  localID,
		}}
		return &schema.EntityRef{Type: constants.TypeWhoisRegistrar, Value: regValue, LocalID: localID}, res
	}
	return nil, nil
}

func hasContactData(c *Contact) bool {
	return len(c.Name) > 0 || len(c.Organization) > 0 || len(c.Email) > 0 || len(c.Address) > 0 || len(c.Phone) > 0 || len(c.Fax) > 0
}

func (m *module) result(typ, category, value, ctx string, oos bool, anchor *schema.EntityRef, gen *modutil.LocalIDGenerator) schema.ModuleResult {
	res := schema.ModuleResult{
		Type:       typ,
		Category:   category,
		Value:      value,
		Context:    ctx,
		Applied:    true,
		OutOfScope: oos,
		LocalID:    gen.NextID(),
	}
	if anchor != nil {
		res.Source = anchor
	}
	return res
}

func buildWhoisServerResult(host, target string) (schema.ModuleResult, bool) {
	res, err := validator.Validate(constants.TypeDomain, host)
	if err != nil {
		dbg.Printf("%s skip_invalid_whois_server target=%q entity=%q err=%v", constants.FuncGetWhois, target, host, err)
		return schema.ModuleResult{}, false
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	dbg.Printf("%s whois_server target=%q entity=%q out_of_scope=%v", constants.FuncGetWhois, target, res.Value, isOOS)

	return schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagWhoisServer},
		OutOfScope: isOOS,
	}, true
}

func (m *module) buildMetadataResults(metadata *Metadata, target, sourceCtx string, registrarAnchor *schema.EntityRef, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	results := make([]schema.ModuleResult, 0, 15)

	if metadata.RegistrarURL != "" {
		results = append(results, m.result(constants.TypeURL, constants.CategoryProperty, metadata.RegistrarURL, "Registrar URL ("+sourceCtx+")", true, registrarAnchor, gen))
	}
	if metadata.WhoisServer != "" {
		if result, ok := buildWhoisServerResult(metadata.WhoisServer, target); ok {
			result.Context = "Whois Server (" + sourceCtx + ")"
			result.Applied = true
			result.Source = registrarAnchor
			result.LocalID = gen.NextID()
			results = append(results, result)
		}
	}
	if metadata.IANAID != "" {
		results = append(results, m.result(constants.TypeIANAID, constants.CategoryProperty, metadata.IANAID, "IANA ID ("+sourceCtx+")", true, registrarAnchor, gen))
	}

	if metadata.DNSSEC != "" {
		results = append(results, m.result(constants.TypeDNSSEC, constants.CategoryProperty, metadata.DNSSEC, "DNSSEC Status ("+sourceCtx+")", false, nil, gen))
	}
	if metadata.CreationDate != "" {
		results = append(results, m.result(constants.TypeDate, constants.CategoryProperty, "Creation Date: "+metadata.CreationDate, sourceCtx, false, nil, gen))
	}
	if metadata.UpdatedDate != "" {
		results = append(results, m.result(constants.TypeDate, constants.CategoryProperty, "Updated Date: "+metadata.UpdatedDate, sourceCtx, false, nil, gen))
	}
	if metadata.ExpirationDate != "" {
		results = append(results, m.result(constants.TypeDate, constants.CategoryProperty, "Expiration Date: "+metadata.ExpirationDate, sourceCtx, false, nil, gen))
	}
	for _, ns := range metadata.NameServers {
		if !strings.Contains(ns, ".") {
			oos := !strings.HasSuffix(strings.ToLower(ns), "."+strings.ToLower(target))
			results = append(results, m.result(constants.TypeHandle, constants.CategoryProperty, ns, "Name Server ("+sourceCtx+")", oos, nil, gen))
			continue
		}

		res, err := validator.Validate(constants.TypeDomain, ns)
		if err != nil {
			continue
		}

		result := m.result(res.Type, constants.CategoryNode, res.Value, "Name Server ("+sourceCtx+")", orgdomain.IsOutOfScope(res.Value, target), nil, gen)
		result.Tags = []string{constants.TagNS}
		results = append(results, result)
	}
	for _, st := range metadata.DomainStatus {
		results = append(results, m.result(constants.TypeStatus, constants.CategoryProperty, st, "Domain Status ("+sourceCtx+")", false, nil, gen))
	}
	return results
}
