package leakix

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func (m *leakixModule) getLeakixDomain(target schema.Entity, fn string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(fn)

	if blocked := m.blockedStatus.Load(); blocked > 0 {
		var msg string
		if blocked == http.StatusUnauthorized {
			msg = msgInvalidKey
		} else {
			msg = fmt.Sprintf("API access blocked (HTTP %d)", blocked)
		}
		dbg.Printf("%s error target=%q state=blocked status=%d", fn, target.Value, blocked)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    msg,
			LocalID:  gen.NextID(),
		})
		return exec
	}

	if m.apiKey == demoIndicator {
		return m.getLeakixDomainDemo(&exec, target, gen)
	}

	targetValue := target.Value
	u := fmt.Sprintf("%s/domain/%s", leakixAPIBaseURL, url.PathEscape(targetValue))
	dbg.Printf("%s target=%q", constants.FuncGetLeakIXDomain, targetValue)

	rawBody, status, ok := m.doAPIRequest(&exec, u, targetValue)
	dbg.Printf("%s request_complete target=%q body_present=%t status=%d", constants.FuncGetLeakIXDomain, targetValue, rawBody != nil, status)

	if !ok || rawBody == nil {
		return exec
	}

	switch status {
	case http.StatusOK:
		modutil.SetRawFromBytes(&exec, rawBody)

		resp, err := parseLeakixResponse(rawBody)
		if err != nil {
			modutil.SetError(&exec, "parse json: %v", err)
			return exec
		}
		formatLeakixResults(&exec, resp, target, gen)
		dbg.Printf("%s success target=%q results=%d", constants.FuncGetLeakIXDomain, targetValue, len(exec.Results))
	case http.StatusNotFound:
		return exec
	case http.StatusTooManyRequests:
		modutil.SetError(&exec, "rate limit: %v", errors.New("HTTP 429"))
	default:
		modutil.SetError(&exec, "http status: %v", fmt.Errorf("%d", status))
	}

	return exec
}

func (m *leakixModule) getLeakixIP(target schema.Entity, fn string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(fn)

	if blocked := m.blockedStatus.Load(); blocked > 0 {
		var msg string
		if blocked == http.StatusUnauthorized {
			msg = msgInvalidKey
		} else {
			msg = fmt.Sprintf("API access blocked (HTTP %d)", blocked)
		}
		dbg.Printf("%s error target=%q state=blocked status=%d", fn, target.Value, blocked)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    msg,
			LocalID:  gen.NextID(),
		})
		return exec
	}

	if m.apiKey == demoIndicator {
		return m.getLeakixIPDemo(&exec, target, gen)
	}

	targetValue := target.Value
	u := fmt.Sprintf("%s/host/%s", leakixAPIBaseURL, url.PathEscape(targetValue))
	dbg.Printf("%s target=%q", constants.FuncGetLeakIXIP, targetValue)

	rawBody, status, ok := m.doAPIRequest(&exec, u, targetValue)
	dbg.Printf("%s request_complete target=%q body_present=%t status=%d", constants.FuncGetLeakIXIP, targetValue, rawBody != nil, status)

	if !ok || rawBody == nil {
		return exec
	}

	switch status {
	case http.StatusOK:
		modutil.SetRawFromBytes(&exec, rawBody)

		resp, err := parseLeakixResponse(rawBody)
		if err != nil {
			modutil.SetError(&exec, "parse json: %v", err)
			return exec
		}
		formatLeakixResults(&exec, resp, target, gen)
		dbg.Printf("%s success target=%q results=%d", constants.FuncGetLeakIXIP, targetValue, len(exec.Results))
	case http.StatusNotFound:
		return exec
	case http.StatusTooManyRequests:
		modutil.SetError(&exec, "rate limit: %v", errors.New("HTTP 429"))
	default:
		modutil.SetError(&exec, "http status: %v", fmt.Errorf("%d", status))
	}

	return exec
}

func formatLeakixResults(exec *schema.ModuleExecution, resp *Response, target schema.Entity, gen *modutil.LocalIDGenerator) {
	for _, wrapper := range resp.Leaks {
		emitLeakWrapperSummary(exec, &wrapper, target, gen)
	}

	groups := buildEventGroups(resp)

	for _, eg := range groups {
		formatEventGroup(exec, eg, target, gen)
	}
}

func emitLeakWrapperSummary(exec *schema.ModuleExecution, wrapper *LeakWrapper, target schema.Entity, gen *modutil.LocalIDGenerator) {
	if wrapper.Summary == "" || wrapper.IP == "" {
		return
	}

	ipRes, err := validator.Validate(constants.TypeIP, wrapper.IP)
	if err != nil {
		return
	}

	var ipRef *schema.EntityRef
	isTargetIP := (target.Type == constants.TypeIPv4 || target.Type == constants.TypeIPv6) && target.Value == ipRes.Value
	if !isTargetIP {
		ipID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     ipRes.Type,
			Category: constants.CategoryNode,
			Value:    ipRes.Value,
			Context:  "LeakIX Target IP",
			LocalID:  ipID,
		})
		ipRef = &schema.EntityRef{Type: ipRes.Type, Value: ipRes.Value, LocalID: ipID}
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSummary,
		Category: constants.CategoryProperty,
		Value:    wrapper.Summary,
		Context:  "Leak Summary",
		Source:   ipRef,
		LocalID:  gen.NextID(),
		Tags:     []string{constants.TagCompromised},
	})
}

func buildEventGroups(resp *Response) map[groupKey]*eventGroup {
	groups := make(map[groupKey]*eventGroup)

	for i := range resp.Services {
		ev := &resp.Services[i]
		key := groupKey{ip: ev.IP, port: ev.Port, protocol: ev.Protocol, host: ev.Host}

		eg, exists := groups[key]
		if !exists {
			eg = &eventGroup{
				latest:     ev,
				sslDomains: make(map[string]struct{}),
			}
			groups[key] = eg
		} else if ev.Time.After(eg.latest.Time) {
			eg.latest = ev
		}

		collectCredentials(eg, ev)
		collectLeaks(eg, ev)
		collectSSLDomains(eg, ev)
		collectSummaries(eg, ev)
	}

	for i := range resp.Leaks {
		wrapper := &resp.Leaks[i]
		for j := range wrapper.Events {
			ev := &wrapper.Events[j]
			key := groupKey{ip: ev.IP, port: ev.Port, protocol: ev.Protocol, host: ev.Host}

			eg, exists := groups[key]
			if !exists {
				eg = &eventGroup{
					latest:     ev,
					sslDomains: make(map[string]struct{}),
				}
				groups[key] = eg
			}

			collectCredentials(eg, ev)
			collectLeaks(eg, ev)
			collectSSLDomains(eg, ev)
			collectSummaries(eg, ev)
		}
	}

	return groups
}

func collectCredentials(eg *eventGroup, ev *ServiceEvent) {
	if ev.Service == nil || ev.Service.Credentials == nil {
		return
	}
	c := ev.Service.Credentials
	if c.Username == "" && c.Password == "" && c.Key == "" && !c.NoAuth {
		return
	}

	hash := c.Username + "\x00" + c.Password + "\x00" + c.Key
	for _, existing := range eg.credentials {
		ec := existing.creds
		if ec.Username+"\x00"+ec.Password+"\x00"+ec.Key == hash {
			return
		}
	}
	eg.credentials = append(eg.credentials, credentialRecord{creds: c, seen: ev.Time})
}

func collectLeaks(eg *eventGroup, ev *ServiceEvent) {
	if ev.Leak == nil || (ev.Leak.Stage == "" && ev.Leak.Type == "" && ev.Leak.Severity == "") {
		return
	}

	hash := ev.Leak.Stage + "\x00" + ev.Leak.Type + "\x00" + ev.Leak.Severity
	for _, existing := range eg.leaks {
		el := existing.leak
		if el.Stage+"\x00"+el.Type+"\x00"+el.Severity == hash {
			return
		}
	}
	eg.leaks = append(eg.leaks, leakRecord{leak: ev.Leak, seen: ev.Time})
}

func collectSSLDomains(eg *eventGroup, ev *ServiceEvent) {
	if ev.SSL == nil || ev.SSL.Certificate == nil {
		return
	}
	for _, d := range ev.SSL.Certificate.Domain {
		if d != "" {
			eg.sslDomains[d] = struct{}{}
		}
	}
}

func collectSummaries(eg *eventGroup, ev *ServiceEvent) {
	if ev.EventType != "leak" || ev.Summary == "" {
		return
	}
	for _, existing := range eg.summaries {
		if existing.text == ev.Summary {
			return
		}
	}
	eg.summaries = append(eg.summaries, summaryRecord{text: ev.Summary, source: ev.EventSource})
}

func formatEventGroup(exec *schema.ModuleExecution, eg *eventGroup, target schema.Entity, gen *modutil.LocalIDGenerator) {
	srv := eg.latest

	ipRef := emitIP(exec, srv, target, gen)
	hostRef := emitHost(exec, srv, ipRef, target.Value, gen)
	emitReverse(exec, srv, ipRef, target.Value, gen)

	portParent := resolvePortParent(hostRef, ipRef)
	portRef, serviceRef := emitPortAndService(exec, srv, portParent, gen)

	switch {
	case serviceRef != nil:
		emitEventSource(exec, srv, serviceRef, gen)
		emitEventSummary(exec, eg, serviceRef, gen)
		emitLastSeen(exec, srv, serviceRef, gen)
		emitSoftwareAndHTTP(exec, srv, serviceRef, gen)
		emitFaviconHash(exec, srv, serviceRef, gen)
		emitSSLProperties(exec, srv, eg, serviceRef, target.Value, gen)
		emitSSHProperties(exec, srv, serviceRef, gen)
		emitCredentials(exec, eg, srv, serviceRef, target, gen)
		emitLeaks(exec, eg, srv, serviceRef, target, gen)
	case portRef != nil:
		emitCredentials(exec, eg, srv, portRef, target, gen)
		emitLeaks(exec, eg, srv, portRef, target, gen)
	default:
		emitCredentials(exec, eg, srv, portParent, target, gen)
		emitLeaks(exec, eg, srv, portParent, target, gen)
	}

	emitNetwork(exec, srv, ipRef, gen)
	emitGeo(exec, srv, ipRef, gen)
	emitTags(exec, srv.Tags, ipRef, gen)
	emitMAC(exec, srv, ipRef, gen)
}

func emitIP(exec *schema.ModuleExecution, srv *ServiceEvent, target schema.Entity, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	if srv.IP == "" {
		return nil
	}

	valIP, err := validator.Validate(constants.TypeIP, srv.IP)
	if err != nil {
		return nil
	}
	srv.IP = valIP.Value

	isTargetIP := (target.Type == constants.TypeIPv4 || target.Type == constants.TypeIPv6) && target.Value == srv.IP
	if isTargetIP {
		return nil
	}

	ipID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:    valIP.Type,
		Value:   srv.IP,
		LocalID: ipID,
		Applied: true,
	})
	return &schema.EntityRef{Type: valIP.Type, Value: srv.IP, LocalID: ipID}
}

func emitHost(exec *schema.ModuleExecution, srv *ServiceEvent, ipRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	if srv.Host == "" || srv.Host == srv.IP || srv.Host == targetValue {
		return nil
	}

	val, err := validator.Validate(constants.TypeDomain, srv.Host)
	if err != nil {
		return nil
	}

	hostID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     val.Type,
		Category: constants.CategoryNode,
		Value:    val.Value,
		Source:   ipRef,
		LocalID:  hostID,
		Applied:  true,
	})
	return &schema.EntityRef{Type: val.Type, Value: val.Value, LocalID: hostID}
}

func emitReverse(exec *schema.ModuleExecution, srv *ServiceEvent, ipRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	if srv.Reverse == "" || srv.Reverse == srv.IP || srv.Reverse == targetValue || srv.Reverse == srv.Host {
		return
	}

	if validated, err := validator.Validate(constants.TypeDomain, srv.Reverse); err == nil {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     validated.Type,
			Category: constants.CategoryNode,
			Value:    validated.Value,
			Tags:     []string{constants.TagReverseIP},
			Source:   ipRef,
			LocalID:  gen.NextID(),
			Applied:  true,
		})
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypePTR,
		Category: constants.CategoryProperty,
		Value:    srv.Reverse,
		Source:   ipRef,
		LocalID:  gen.NextID(),
	})
}

func resolvePortParent(hostRef, ipRef *schema.EntityRef) *schema.EntityRef {
	if hostRef != nil {
		return hostRef
	}
	return ipRef
}

func emitPortAndService(exec *schema.ModuleExecution, srv *ServiceEvent, parent *schema.EntityRef, gen *modutil.LocalIDGenerator) (portRef, serviceRef *schema.EntityRef) {
	if srv.Port == "" {
		return nil, nil
	}

	portID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypePort,
		Category: constants.CategoryProperty,
		Value:    srv.Port,
		LocalID:  portID,
		Source:   parent,
	})
	portRef = &schema.EntityRef{Type: constants.TypePort, Value: srv.Port, LocalID: portID}

	if srv.Protocol == "" {
		return portRef, nil
	}

	protoID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeService,
		Category: constants.CategoryProperty,
		Value:    srv.Protocol,
		LocalID:  protoID,
		Source:   portRef,
	})
	serviceRef = &schema.EntityRef{Type: constants.TypeService, Value: srv.Protocol, LocalID: protoID}

	return portRef, serviceRef
}

func emitEventSource(exec *schema.ModuleExecution, srv *ServiceEvent, serviceRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if srv.EventSource == "" {
		return
	}
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSource,
		Category: constants.CategoryProperty,
		Value:    srv.EventSource,
		Source:   serviceRef,
		LocalID:  gen.NextID(),
	})
}

func emitEventSummary(exec *schema.ModuleExecution, eg *eventGroup, serviceRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	for _, sr := range eg.summaries {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeSummary,
			Category: constants.CategoryProperty,
			Value:    sr.text,
			Context:  sr.source,
			Source:   serviceRef,
			LocalID:  gen.NextID(),
		})
	}
}

func emitLastSeen(exec *schema.ModuleExecution, srv *ServiceEvent, serviceRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if srv.Time.IsZero() {
		return
	}
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeDate,
		Category: constants.CategoryProperty,
		Value:    "Last Seen: " + srv.Time.Format(time.DateOnly),
		Source:   serviceRef,
		LocalID:  gen.NextID(),
	})
}

func emitSoftwareAndHTTP(exec *schema.ModuleExecution, srv *ServiceEvent, serviceRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	descValue := extractDescValue(srv)
	webServerValue := extractWebServerValue(srv)

	descClean := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(descValue), "/", ""), " ", "")
	webClean := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(webServerValue), "/", ""), " ", "")

	emitDesc := descValue != ""
	emitWeb := webServerValue != ""

	if emitDesc && emitWeb && descClean == webClean {
		if srv.Protocol == "http" || srv.Protocol == "https" {
			emitDesc = false
		} else {
			emitWeb = false
		}
	}

	if emitDesc {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDescription,
			Category: constants.CategoryProperty,
			Value:    descValue,
			Context:  "Software",
			Source:   serviceRef,
			LocalID:  gen.NextID(),
		})
	}
	if emitWeb {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeWebServer,
			Category: constants.CategoryProperty,
			Value:    webServerValue,
			Source:   serviceRef,
			LocalID:  gen.NextID(),
		})
	}
}

func extractDescValue(srv *ServiceEvent) string {
	if srv.Service == nil || srv.Service.Software == nil || srv.Service.Software.Name == "" {
		return ""
	}
	descValue := srv.Service.Software.Name
	if srv.Service.Software.Version != "" {
		descValue += " " + srv.Service.Software.Version
	}
	return descValue
}

func extractWebServerValue(srv *ServiceEvent) string {
	if srv.HTTP == nil || srv.HTTP.Header == nil {
		return ""
	}
	if server, ok := srv.HTTP.Header["server"]; ok {
		return server
	}
	return ""
}

func emitFaviconHash(exec *schema.ModuleExecution, srv *ServiceEvent, serviceRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if srv.HTTP == nil || srv.HTTP.FaviconHash == "" {
		return
	}
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeHash,
		Category: constants.CategoryProperty,
		Value:    srv.HTTP.FaviconHash,
		Context:  "Favicon",
		Source:   serviceRef,
		LocalID:  gen.NextID(),
	})
}

func emitSSLProperties(exec *schema.ModuleExecution, srv *ServiceEvent, eg *eventGroup, serviceRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	if srv.SSL == nil {
		return
	}

	if srv.SSL.JARM != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeJARM,
			Category: constants.CategoryProperty,
			Value:    srv.SSL.JARM,
			Source:   serviceRef,
			LocalID:  gen.NextID(),
		})
	}

	if srv.SSL.Certificate != nil && srv.SSL.Certificate.Fingerprint != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCertFingerprint,
			Category: constants.CategoryProperty,
			Value:    srv.SSL.Certificate.Fingerprint,
			Source:   serviceRef,
			LocalID:  gen.NextID(),
		})
	}

	emitSANDomains(exec, eg, srv, serviceRef, targetValue, gen)
}

func emitSANDomains(exec *schema.ModuleExecution, eg *eventGroup, srv *ServiceEvent, serviceRef *schema.EntityRef, targetValue string, gen *modutil.LocalIDGenerator) {
	issuerName := ""
	notAfterStr := ""
	if srv.SSL != nil && srv.SSL.Certificate != nil {
		issuerName = srv.SSL.Certificate.IssuerName
		if !srv.SSL.Certificate.NotAfter.IsZero() {
			notAfterStr = srv.SSL.Certificate.NotAfter.Format(time.RFC3339)
		}
	}

	for domain := range eg.sslDomains {
		if domain == srv.IP || domain == targetValue {
			continue
		}

		candidate := domain
		isWildcard := false
		if trimmed, found := strings.CutPrefix(domain, "*."); found {
			candidate = trimmed
			isWildcard = true
		}
		if candidate == "" {
			continue
		}

		validated, err := validator.Validate(constants.TypeDomain, candidate)
		if err != nil {
			continue
		}

		sanID := gen.NextID()
		result := schema.ModuleResult{
			Type:     validated.Type,
			Category: constants.CategoryNode,
			Value:    validated.Value,
			Source:   serviceRef,
			LocalID:  sanID,
			Applied:  true,
			Tags:     []string{constants.TagSan},
		}
		if isWildcard {
			result.Tags = append(result.Tags, constants.TagWildcard)
			result.Context = "*." + validated.Value
		}
		exec.Results = append(exec.Results, result)

		sanRef := &schema.EntityRef{Type: validated.Type, Value: validated.Value, LocalID: sanID}

		if issuerName != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeCertIssuer,
				Category: constants.CategoryProperty,
				Value:    issuerName,
				Source:   sanRef,
				LocalID:  gen.NextID(),
			})
		}
		if notAfterStr != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeCertNotAfter,
				Category: constants.CategoryProperty,
				Value:    notAfterStr,
				Source:   sanRef,
				LocalID:  gen.NextID(),
			})
		}
	}
}

func emitSSHProperties(exec *schema.ModuleExecution, srv *ServiceEvent, serviceRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if srv.SSH == nil {
		return
	}

	var parts []string
	if srv.SSH.Banner != "" {
		parts = append(parts, "Banner: "+srv.SSH.Banner)
	}
	if srv.SSH.Fingerprint != "" {
		parts = append(parts, "Fingerprint: "+srv.SSH.Fingerprint)
	}
	if srv.SSH.Motd != "" {
		parts = append(parts, "MOTD: "+srv.SSH.Motd)
	}

	if len(parts) > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    strings.Join(parts, " | "),
			Context:  "SSH",
			Source:   serviceRef,
			LocalID:  gen.NextID(),
		})
	}
}

func emitCredentials(exec *schema.ModuleExecution, eg *eventGroup, srv *ServiceEvent, parentRef *schema.EntityRef, target schema.Entity, gen *modutil.LocalIDGenerator) {
	if len(eg.credentials) == 0 {
		return
	}

	markCompromised(exec, srv, target, gen)

	for _, cr := range eg.credentials {
		credStr := formatCredentialString(cr.creds)
		if credStr == "" {
			continue
		}

		value := credStr
		if !cr.seen.IsZero() {
			value += " (seen: " + cr.seen.Format(time.DateOnly) + ")"
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeLeakedData,
			Category: constants.CategoryProperty,
			Value:    value,
			Context:  "Leaked Credentials",
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})
	}
}

func formatCredentialString(c *CredentialsInfo) string {
	var parts []string
	if c.NoAuth {
		parts = append(parts, "NoAuth: true")
	}
	if c.Username != "" {
		parts = append(parts, "User: "+c.Username)
	}
	if c.Password != "" {
		parts = append(parts, "Pass: "+c.Password)
	}
	if c.Key != "" {
		parts = append(parts, "Key: "+c.Key)
	}
	return strings.Join(parts, " | ")
}

func markCompromised(exec *schema.ModuleExecution, srv *ServiceEvent, target schema.Entity, gen *modutil.LocalIDGenerator) {
	compromisedType := target.Type
	compromisedValue := target.Value

	if srv.Host != "" && srv.Host != srv.IP {
		if val, err := validator.Validate(constants.TypeDomain, srv.Host); err == nil {
			compromisedType = val.Type
			compromisedValue = val.Value
		}
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:    compromisedType,
		Value:   compromisedValue,
		Tags:    []string{constants.TagCompromised},
		LocalID: gen.NextID(),
	})
}

func emitLeaks(exec *schema.ModuleExecution, eg *eventGroup, srv *ServiceEvent, parentRef *schema.EntityRef, target schema.Entity, gen *modutil.LocalIDGenerator) {
	if len(eg.leaks) == 0 {
		return
	}

	markCompromised(exec, srv, target, gen)

	for _, lr := range eg.leaks {
		lk := lr.leak
		leakInfo := fmt.Sprintf("[%s] %s, stage: %s", lk.Severity, lk.Type, lk.Stage)
		if !lr.seen.IsZero() {
			leakInfo += " (seen: " + lr.seen.Format(time.DateOnly) + ")"
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeLeakedData,
			Category: constants.CategoryProperty,
			Value:    leakInfo,
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})

		emitDatasetInfo(exec, lk.Dataset, parentRef, gen)
	}
}

func emitDatasetInfo(exec *schema.ModuleExecution, ds *DatasetInfo, parentRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if ds == nil {
		return
	}
	if ds.Rows <= 0 && ds.Size <= 0 && !ds.Infected {
		return
	}

	dsInfo := fmt.Sprintf("Rows: %d, Size: %d, Infected: %v", ds.Rows, ds.Size, ds.Infected)
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSummary,
		Category: constants.CategoryProperty,
		Value:    dsInfo,
		Context:  "Dataset",
		Source:   parentRef,
		LocalID:  gen.NextID(),
	})
}

func emitNetwork(exec *schema.ModuleExecution, srv *ServiceEvent, ipRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if srv.Network == nil {
		return
	}
	if srv.Network.ASN != 0 {
		if val, err := validator.Validate(constants.TypeASN, fmt.Sprintf("AS%d", srv.Network.ASN)); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     val.Type,
				Category: constants.CategoryNode,
				Value:    val.Value,
				Source:   ipRef,
				LocalID:  gen.NextID(),
			})
		}
	}
	if srv.Network.OrganizationName != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeOrganization,
			Category: constants.CategoryProperty,
			Value:    srv.Network.OrganizationName,
			Source:   ipRef,
			LocalID:  gen.NextID(),
		})
	}
	if srv.Network.Network != "" {
		if val, err := validator.Validate(constants.TypeCIDR, srv.Network.Network); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeCIDR,
				Category: constants.CategoryNode,
				Value:    val.Value,
				Source:   ipRef,
				LocalID:  gen.NextID(),
			})
		}
	}
}

func emitGeo(exec *schema.ModuleExecution, srv *ServiceEvent, ipRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if srv.GeoIP == nil {
		return
	}
	var parts []string
	if srv.GeoIP.CityName != "" {
		parts = append(parts, "City: "+srv.GeoIP.CityName)
	}
	if srv.GeoIP.RegionName != "" {
		parts = append(parts, "Region: "+srv.GeoIP.RegionName)
	}
	if srv.GeoIP.CountryName != "" {
		c := srv.GeoIP.CountryName
		if srv.GeoIP.CountryISOCode != "" {
			c += " (" + srv.GeoIP.CountryISOCode + ")"
		}
		parts = append(parts, "Country: "+c)
	}
	if srv.GeoIP.ContinentName != "" {
		parts = append(parts, "Continent: "+srv.GeoIP.ContinentName)
	}
	if srv.GeoIP.Location != nil && (srv.GeoIP.Location.Lat != 0 || srv.GeoIP.Location.Lon != 0) {
		parts = append(parts, fmt.Sprintf("Lat/Lon: %f, %f", srv.GeoIP.Location.Lat, srv.GeoIP.Location.Lon))
	}

	if len(parts) > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeGeo,
			Category: constants.CategoryProperty,
			Value:    strings.Join(parts, " | "),
			Source:   ipRef,
			LocalID:  gen.NextID(),
		})
	}
}

func emitTags(exec *schema.ModuleExecution, tags []string, ipRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	for _, t := range tags {
		if t == "" {
			continue
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    t,
			Source:   ipRef,
			LocalID:  gen.NextID(),
		})
	}
}

func emitMAC(exec *schema.ModuleExecution, srv *ServiceEvent, ipRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if srv.MAC != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeMAC,
			Category: constants.CategoryProperty,
			Value:    srv.MAC,
			Source:   ipRef,
			LocalID:  gen.NextID(),
		})
	}
	if srv.Vendor != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeVendor,
			Category: constants.CategoryProperty,
			Value:    srv.Vendor,
			Source:   ipRef,
			LocalID:  gen.NextID(),
		})
	}
}
