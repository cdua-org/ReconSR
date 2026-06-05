package netlas

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func (m *netlasModule) getNetlasIP(target schema.Entity, fn string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(fn)
	targetValue := target.Value
	dbg.Printf("%s target=%q", fn, targetValue)

	u := fmt.Sprintf("%s/%s/?source_type=include&fields=*", netlasAPIBaseURL, targetValue)

	if m.apiKey == demoIndicator {
		if !m.demoIPFired.CompareAndSwap(false, true) {
			dbg.Printf("%s skipped stage=demo_already_fired target=%q", fn, targetValue)
			return exec
		}
		dbg.Printf("%s start stage=demo_mode", fn)
		return m.runDemoIP(exec, target, gen)
	}

	rawBody, ok := m.doAPIRequest(&exec, u, targetValue, gen)
	if !ok {
		return exec
	}

	exec.RawData = string(rawBody)

	var resp netlasIPResponse
	if err := json.Unmarshal(rawBody, &resp); err != nil {
		dbg.Printf("%s error stage=parse_json err=%v", fn, err)
		modutil.SetError(&exec, "parse json: %v", err)
		return exec
	}

	if resp.IP == "" {
		dbg.Printf("%s empty_response target=%q", fn, targetValue)
		return exec
	}

	parseIPResponse(&exec, &resp, target, gen)
	dbg.Printf("%s success target=%q results=%d", fn, targetValue, len(exec.Results))

	return exec
}

func parseIPResponse(exec *schema.ModuleExecution, resp *netlasIPResponse, target schema.Entity, gen *modutil.LocalIDGenerator) {
	targetValue := target.Value
	targetRef := &schema.EntityRef{Type: target.Type, Value: targetValue}

	if resp.IP != "" {
		if res, err := validator.Validate(constants.TypeIP, resp.IP); err == nil {
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

	var mainASNs []string
	if resp.Whois != nil && resp.Whois.ASN != nil {
		mainASNs = resp.Whois.ASN.Number
	}
	parseIoC(exec, resp.IoC, targetRef, mainASNs, gen)

	if resp.Whois != nil {
		parseIPWhois(exec, resp.Whois, resp.Organization, targetRef, gen)
	}
	parseGeo(exec, resp.Geo, gen)
	parseIPPrivacy(exec, resp.Privacy, gen)

	if resp.Organization != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeOrganization,
			Category: constants.CategoryNode,
			Value:    resp.Organization,
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}

	parseNetlasDomains(exec, resp.DomainsCount, resp.Domains, constants.TagReverseIP, targetRef, gen)
	parseNetlasDomains(exec, resp.RelatedDomainsCount, resp.RelatedDomains, constants.TagPDNS, targetRef, gen)

	parseIPPTR(exec, resp, targetRef, gen)
}

func parseIPPrivacy(exec *schema.ModuleExecution, privacy *netlasPrivacy, gen *modutil.LocalIDGenerator) {
	if privacy == nil {
		return
	}
	if privacy.IsVPN {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    constants.TagVPN,
			LocalID:  gen.NextID(),
		})
	}
	if privacy.IsProxy {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    constants.TagProxy,
			LocalID:  gen.NextID(),
		})
	}
	if privacy.IsTor {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    constants.TagTorExit,
			LocalID:  gen.NextID(),
		})
	}
}

func parseIPPTR(exec *schema.ModuleExecution, resp *netlasIPResponse, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	for _, ptr := range resp.PTR {
		if ptr == "" {
			continue
		}
		if valPtr, err := validator.Validate(constants.TypeDomain, ptr); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     valPtr.Type,
				Category: constants.CategoryNode,
				Value:    valPtr.Value,
				Tags:     []string{constants.TagReverseIP},
				Source:   targetRef,
				LocalID:  gen.NextID(),
			})
		} else {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypePTR,
				Category: constants.CategoryProperty,
				Value:    ptr,
				Source:   targetRef,
				LocalID:  gen.NextID(),
			})
		}
	}
}

func parseIPWhois(exec *schema.ModuleExecution, whois *netlasWhoisIP, rootOrg string, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if whois == nil {
		return
	}
	parseWhoisASN(exec, whois.ASN, targetRef, gen)

	var mainCIDRs []string
	if whois.Net != nil {
		mainCIDRs = whois.Net.CIDR
	}

	parseWhoisNet(exec, whois.Net, rootOrg, targetRef, false, nil, gen)

	for i := range whois.RelatedNets {
		parseWhoisNet(exec, &whois.RelatedNets[i], rootOrg, targetRef, true, mainCIDRs, gen)
	}
}

func parseWhoisASN(exec *schema.ModuleExecution, asn *netlasWhoisASN, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if asn == nil {
		return
	}
	for _, num := range asn.Number {
		if num == "" {
			continue
		}
		valASN, err := validator.Validate(constants.TypeASN, num)
		if err != nil {
			continue
		}
		asnID := gen.NextID()
		asnCtx := ""
		if asn.Country != "" && asn.Name != "" {
			asnCtx = fmt.Sprintf("ASN Origin (%s, %s)", asn.Country, asn.Name)
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     valASN.Type,
			Category: constants.CategoryNode,
			Value:    valASN.Value,
			Context:  asnCtx,
			Source:   targetRef,
			LocalID:  asnID,
		})

		asnRef := &schema.EntityRef{Type: constants.TypeASN, Value: valASN.Value, LocalID: asnID}

		if asn.Name != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeOrganization,
				Category: constants.CategoryNode,
				Value:    asn.Name,
				Context:  "ASN Holder",
				Source:   asnRef,
				LocalID:  gen.NextID(),
			})
		}
		if asn.CIDR != "" {
			if valCIDR, err := validator.Validate(constants.TypeCIDR, asn.CIDR); err == nil {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     valCIDR.Type,
					Category: constants.CategoryProperty,
					Value:    valCIDR.Value,
					Source:   asnRef,
					LocalID:  gen.NextID(),
				})
			}
		}
		if asn.Registry != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeInfo,
				Category: constants.CategoryProperty,
				Value:    "Registry: " + strings.ToUpper(asn.Registry),
				Context:  "ASN Registry",
				Source:   asnRef,
				LocalID:  gen.NextID(),
			})
		}
		ParseWhoisDates(exec, "", asn.Updated, "", asnRef, gen)
	}
}

func resolveWhoisOrg(exec *schema.ModuleExecution, net *netlasWhoisIPNet, rootOrg string, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) (orgRef *schema.EntityRef, orgName string) {
	orgName = rootOrg
	if orgName == "" {
		orgName = net.Organization
	}
	if orgName == "" {
		orgName = net.Name
	}
	if orgName == "" {
		orgName = net.Description
	}
	if orgName == "" {
		orgName = net.Handle
	}

	if orgName != "" {
		orgID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeOrganization,
			Category: constants.CategoryNode,
			Value:    orgName,
			Context:  "Network Organization",
			Source:   targetRef,
			LocalID:  orgID,
		})
		return &schema.EntityRef{Type: constants.TypeOrganization, Value: orgName, LocalID: orgID}, orgName
	}
	return targetRef, orgName
}

func parseWhoisNet(exec *schema.ModuleExecution, net *netlasWhoisIPNet, rootOrg string, targetRef *schema.EntityRef, isRelated bool, mainCIDRs []string, gen *modutil.LocalIDGenerator) {
	if net == nil {
		return
	}

	orgRef, orgName := resolveWhoisOrg(exec, net, rootOrg, targetRef, gen)

	skipDates := false
	if isRelated && len(net.CIDR) > 0 && len(mainCIDRs) > 0 {
		for _, c := range net.CIDR {
			if slices.Contains(mainCIDRs, c) {
				skipDates = true
				break
			}
		}
	}

	var cidrRef *schema.EntityRef
	for _, cidr := range net.CIDR {
		if cidr == "" {
			continue
		}
		valCIDR, err := validator.Validate(constants.TypeCIDR, cidr)
		if err != nil {
			continue
		}
		cidrID := gen.NextID()
		ref := &schema.EntityRef{Type: valCIDR.Type, Value: valCIDR.Value, LocalID: cidrID}
		if cidrRef == nil {
			cidrRef = ref
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     valCIDR.Type,
			Category: constants.CategoryProperty,
			Value:    valCIDR.Value,
			Source:   orgRef,
			LocalID:  cidrID,
		})
	}

	propsRef := orgRef
	if cidrRef != nil {
		propsRef = cidrRef
	}

	parseWhoisNetProperties(exec, net, orgName, propsRef, isRelated, skipDates, gen)
	parseWhoisNetAddress(exec, net, orgName, orgRef, gen)
	parseWhoisNetContacts(exec, net.Contacts, orgRef, gen)
}

func parseWhoisNetProperties(exec *schema.ModuleExecution, net *netlasWhoisIPNet, orgName string, propsRef *schema.EntityRef, isRelated, skipDates bool, gen *modutil.LocalIDGenerator) {
	var netParts []string
	if net.Name != "" && net.Name != orgName {
		netParts = append(netParts, net.Name)
	}
	if net.Handle != "" && net.Handle != orgName {
		netParts = append(netParts, net.Handle)
	}

	prefix := "Network"
	if isRelated {
		prefix = "Related Network"
	}

	if len(netParts) > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeNetwork,
			Category: constants.CategoryProperty,
			Value:    strings.Join(netParts, ", "),
			Context:  prefix + " Identifier",
			Source:   propsRef,
			LocalID:  gen.NextID(),
		})
	}

	if net.Description != "" && net.Description != orgName {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDescription,
			Category: constants.CategoryProperty,
			Value:    prefix + ": " + strings.Join(strings.Fields(net.Description), " "),
			Source:   propsRef,
			LocalID:  gen.NextID(),
		})
	}

	if !skipDates {
		ParseWhoisDates(exec, net.Created, net.Updated, prefix, propsRef, gen)
	}
}

func appendIfNotOrg(parts []string, val, orgName string) []string {
	if val != "" && val != orgName {
		return append(parts, strings.TrimSpace(val))
	}
	return parts
}

func formatWhoisNetAddress(net *netlasWhoisIPNet, orgName string) string {
	var addrParts []string

	addrParts = appendIfNotOrg(addrParts, net.Address, orgName)
	addrParts = appendIfNotOrg(addrParts, net.City, orgName)

	state := ""
	if net.State != "" && net.State != orgName {
		state = strings.TrimSpace(net.State)
	}
	postal := ""
	if net.PostalCode != "" && net.PostalCode != orgName {
		postal = strings.TrimSpace(net.PostalCode)
	}

	switch {
	case state != "" && postal != "":
		addrParts = append(addrParts, state+" "+postal)
	case state != "":
		addrParts = append(addrParts, state)
	case postal != "":
		addrParts = append(addrParts, postal)
	}

	addrParts = appendIfNotOrg(addrParts, net.Country, orgName)

	if len(addrParts) == 0 {
		return ""
	}
	return strings.ReplaceAll(strings.Join(addrParts, ", "), "\n", ", ")
}

func parseWhoisNetAddress(exec *schema.ModuleExecution, net *netlasWhoisIPNet, orgName string, orgRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	addr := formatWhoisNetAddress(net, orgName)
	if addr != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeAddress,
			Category: constants.CategoryProperty,
			Value:    addr,
			Context:  "Network Address",
			Source:   orgRef,
			LocalID:  gen.NextID(),
		})
	}
}

func parseWhoisNetContacts(exec *schema.ModuleExecution, contacts *netlasWhoisIPContacts, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if contacts == nil {
		return
	}
	ParseEmails(exec, contacts.Emails, constants.CategoryProperty, "", false, targetRef, gen)
	ParsePhones(exec, contacts.Phones, constants.CategoryProperty, false, targetRef, gen)
	parseWhoisNetPersons(exec, contacts.Persons, targetRef, gen)
}

func parseWhoisNetPersons(exec *schema.ModuleExecution, persons []string, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	uniquePersons := make(map[string]bool)
	for _, person := range persons {
		person = formatPerson(person)
		if person == "" || uniquePersons[person] {
			continue
		}
		uniquePersons[person] = true

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypePerson,
			Category: constants.CategoryNode,
			Value:    person,
			Source:   targetRef,
			LocalID:  gen.NextID(),
		})
	}
}
