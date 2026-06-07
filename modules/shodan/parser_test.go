package shodan

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dateutil"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestParseShodanAPIDomainInvalidJSON(t *testing.T) {
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}
	parseShodanAPIDomain(&exec, []byte(`{invalid`), "test.example.com")
	if exec.Error == nil {
		t.Fatal("expected invalid json error")
	}
}

func TestProcessShodanDomainRecordSkipsInvalidAndKeepsNodeForEmptyValue(t *testing.T) {
	invalidExec := schema.ModuleExecution{}
	invalidGen := modutil.NewLocalIDGenerator()
	invalidCollector := dateutil.NewCollector()
	processShodanDomainRecord(&invalidExec, shodanDomainRecord{Subdomain: "bad label", Type: "A", Value: "198.51.100.50", LastSeen: "1999-01-01"}, "example.com", invalidGen, invalidCollector)
	if len(invalidExec.Results) != 0 {
		t.Fatalf("expected invalid record to be skipped, got %+v", invalidExec.Results)
	}

	emptyExec := schema.ModuleExecution{}
	emptyGen := modutil.NewLocalIDGenerator()
	emptyCollector := dateutil.NewCollector()
	processShodanDomainRecord(&emptyExec, shodanDomainRecord{Subdomain: "empty", Type: constants.TypeTXT, Value: " ", LastSeen: "2000-01-01"}, "test.example.net", emptyGen, emptyCollector)
	result := requireModuleResult(t, emptyExec.Results, constants.TypeSubdomain, "empty.test.example.net")
	if result.Source != nil {
		t.Fatalf("expected subdomain node to stay attached to target, got %+v", result.Source)
	}
	if len(emptyCollector.Items()) != 0 {
		t.Fatalf("expected empty value to avoid last_seen collection, got %+v", emptyCollector.Items())
	}
}

func TestAppendShodanMXResultBranches(t *testing.T) {
	t.Run("invalid_exchange_keeps_property_only", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		ref := appendShodanMXResult(&exec, shodanDomainRecord{}, "bad mx", "bad-mx.example.com", nil, gen)
		if ref == nil || ref.Type != constants.TypeMX {
			t.Fatalf("expected MX property ref, got %+v", ref)
		}
		if len(exec.Results) != 1 {
			t.Fatalf("expected only MX property result, got %+v", exec.Results)
		}
	})

	t.Run("self_exchange_keeps_property_only", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		ref := appendShodanMXResult(&exec, shodanDomainRecord{}, "self-e.example.org", "self-e.example.org", nil, gen)
		if ref == nil || ref.Type != constants.TypeMX {
			t.Fatalf("expected MX property ref, got %+v", ref)
		}
		if len(exec.Results) != 1 {
			t.Fatalf("expected self MX target to avoid node creation, got %+v", exec.Results)
		}
	})
}

func TestAppendShodanTXTResultBranches(t *testing.T) {
	t.Run("dkim_property", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		source := &schema.EntityRef{Type: constants.TypeSubdomain, Value: "dkim.example.com", LocalID: 10}

		ref := appendShodanTXTResult(&exec, shodanDomainRecord{Subdomain: "_domainkey"}, "k=rsa; p=ZmFrZQ==", "dkim.example.com", source, gen)
		if ref == nil || ref.Type != constants.TypeDKIM {
			t.Fatalf("expected DKIM ref, got %+v", ref)
		}

		result := requireModuleResultWithContext(t, exec.Results, constants.TypeDKIM, "k=rsa; p=ZmFrZQ==", "_domainkey")
		if result.Source == nil || result.Source.Value != "dkim.example.com" {
			t.Fatalf("expected DKIM property to stay linked to source, got %+v", result.Source)
		}
	})

	t.Run("dmarc_invalid_email_is_skipped", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()

		appendShodanTXTResult(&exec, shodanDomainRecord{Subdomain: "_dmarc"}, "v=DMARC1; p=reject; rua=mailto:not-an-email; ruf=mailto:ops@example.net", "dmark.example.org", nil, gen)

		requireModuleResultWithContext(t, exec.Results, constants.TypeDMARC, "v=DMARC1; p=reject; rua=mailto:not-an-email; ruf=mailto:ops@example.net", "_dmarc")
		ruf := requireModuleResultWithContext(t, exec.Results, constants.TypeEmail, "ops@example.net", "DMARC RUF")
		if !ruf.OutOfScope {
			t.Fatal("expected DMARC RUF email to be out of scope")
		}
		if _, ok := findModuleResult(exec.Results, constants.TypeEmail, "not-an-email"); ok {
			t.Fatalf("expected invalid DMARC email to be skipped, got %+v", exec.Results)
		}
	})

	t.Run("spf_skips_invalid_and_self_references", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()

		appendShodanTXTResult(&exec, shodanDomainRecord{Subdomain: "spf"}, "v=spf1 include:example.com ip4:not-an-ip include:spf.example.net -all", "spf.example.org", nil, gen)

		spfNode := requireModuleResultWithTag(t, exec.Results, constants.TypeSubdomain, "spf.example.net", constants.TagSPF)
		if !spfNode.OutOfScope {
			t.Fatal("expected SPF include node to be out of scope")
		}
		if _, ok := findModuleResult(exec.Results, constants.TypeDomain, "spf.example.org"); ok {
			t.Fatalf("expected self-referential SPF include to be skipped, got %+v", exec.Results)
		}
		if _, ok := findModuleResult(exec.Results, constants.TypeIPv4, "not-an-ip"); ok {
			t.Fatalf("expected invalid SPF ip to be skipped, got %+v", exec.Results)
		}
	})
}

func TestBuildShodanSPFEntityResultBranches(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	source := &schema.EntityRef{Type: constants.TypeSPF, Value: "v=spf1 -all", LocalID: 1}

	if _, ok := buildShodanSPFEntityResult(source, dnsutils.SPFEntity{Kind: dnsutils.SPFEntityIP4, Value: "not-an-ip", Mechanism: "ip4"}, "spf-naip.example.com", gen); ok {
		t.Fatal("expected invalid SPF ip entity to be rejected")
	}

	if _, ok := buildShodanSPFEntityResult(source, dnsutils.SPFEntity{Kind: dnsutils.SPFEntityDomain, Value: "spf-entity.example.com", Mechanism: "include"}, "spf-entity.example.com", gen); ok {
		t.Fatal("expected self-referential SPF domain entity to be rejected")
	}

	if _, ok := buildShodanSPFEntityResult(source, dnsutils.SPFEntity{Kind: dnsutils.SPFEntityType(99), Value: "e.example.net", Mechanism: "include"}, "example.com", gen); ok {
		t.Fatal("expected unknown SPF entity kind to be rejected")
	}
}

func TestShodanDomainHelperEdgeBranches(t *testing.T) {
	if _, _, _, _, ok := buildShodanFQDN("example.com", "bad label"); ok {
		t.Fatal("expected invalid subdomain label to be rejected")
	}

	exec := schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	source := &schema.EntityRef{Type: constants.TypeDomain, Value: "lid.example.com", LocalID: 1}

	if ref := appendShodanIPResult(&exec, "not-an-ip", source, gen); ref != nil {
		t.Fatalf("expected invalid ip to be ignored, got %+v", ref)
	}
	if ref := appendShodanCNAMEResult(&exec, "bad target", "lid.example.com", source, gen); ref != nil {
		t.Fatalf("expected invalid cname to be ignored, got %+v", ref)
	}
	if ref := appendShodanCNAMEResult(&exec, "lid2.example.com", "lid2.example.com", source, gen); ref != nil {
		t.Fatalf("expected self cname to be ignored, got %+v", ref)
	}
	if ref := appendShodanNSResult(&exec, "bad ns", "lid3.example.com", source, gen); ref != nil {
		t.Fatalf("expected invalid ns to be ignored, got %+v", ref)
	}
	if ref := appendShodanNSResult(&exec, "lid4.example.com", "lid4.example.com", source, gen); ref != nil {
		t.Fatalf("expected self ns to be ignored, got %+v", ref)
	}
	if len(exec.Results) != 0 {
		t.Fatalf("expected helper edge cases to add no results, got %+v", exec.Results)
	}
}

func TestShodanDomainDateCollectionBranches(t *testing.T) {
	collectShodanLastSeen(nil, shodanDomainRecord{Type: "A", Value: "198.51.100.1", LastSeen: "2026-06-07"}, nil)

	const sourceRepeatedIP = "198.51.100.28"

	collector := dateutil.NewCollector()
	collectShodanLastSeen(collector, shodanDomainRecord{Type: "A", Subdomain: "@", Value: "198.51.100.15", LastSeen: "2026-06-07T01:02:03Z"}, nil)
	collectShodanLastSeen(collector, shodanDomainRecord{Type: "A", Subdomain: "@", Value: "198.51.100.15", LastSeen: "2026-06-08T01:02:03Z"}, nil)
	collectShodanLastSeen(collector, shodanDomainRecord{Type: constants.TypeTXT, Value: " ", LastSeen: "2026-06-09"}, nil)

	source := &schema.EntityRef{Type: constants.TypeIPv4, Value: sourceRepeatedIP, LocalID: 7}
	collectShodanLastSeen(collector, shodanDomainRecord{Type: "A", Value: sourceRepeatedIP, LastSeen: "2026-06-09 10:00:00"}, source)

	exec := schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	appendShodanLastSeenResults(&exec, collector, gen)

	latestDetached := requireModuleResult(t, exec.Results, constants.TypeDate, "Last Seen: 2026-06-08")
	if latestDetached.Source != nil {
		t.Fatalf("expected detached last_seen to have no source, got %+v", latestDetached.Source)
	}

	linked := requireModuleResult(t, exec.Results, constants.TypeDate, "Last Seen: 2026-06-09")
	if linked.Source == nil || linked.Source.Value != sourceRepeatedIP {
		t.Fatalf("expected sourced last_seen to stay linked, got %+v", linked.Source)
	}
}

func TestAppendShodanCAAResultBranches(t *testing.T) {
	t.Run("unmatched_property_only", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()

		ref := appendShodanCAAResult(&exec, "broken-caa-value", "example.com", nil, gen)
		if ref == nil || ref.Type != constants.TypeCAA {
			t.Fatalf("expected CAA property ref, got %+v", ref)
		}
		if len(exec.Results) != 1 {
			t.Fatalf("expected only property result, got %+v", exec.Results)
		}
	})

	t.Run("issue_self_target_is_skipped", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()

		appendShodanCAAResult(&exec, `0 issue "example.com"`, "example.com", nil, gen)
		if len(exec.Results) != 1 {
			t.Fatalf("expected only self-target CAA property, got %+v", exec.Results)
		}
	})

	t.Run("iodef_email_node", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()

		appendShodanCAAResult(&exec, `0 iodef "mailto:reports@example.net"`, "example.com", nil, gen)

		email := requireModuleResult(t, exec.Results, constants.TypeEmail, "reports@example.net")
		if !email.OutOfScope {
			t.Fatal("expected iodef email to be out of scope")
		}
	})
}

func TestAppendShodanURIResultRawFallback(t *testing.T) {
	exec := schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()

	ref := appendShodanURIResult(&exec, "broken-uri", "example.com", nil, gen)
	if ref == nil || ref.Type != constants.TypeURI {
		t.Fatalf("expected URI ref, got %+v", ref)
	}
	if len(exec.Results) != 1 {
		t.Fatalf("expected raw fallback only, got %+v", exec.Results)
	}
}

func TestBuildShodanSOARawNilOptions(t *testing.T) {
	if got := buildShodanSOARaw("ns1.example.com", nil); got != "ns1.example.com." {
		t.Fatalf("unexpected SOA raw value: %q", got)
	}
}

func TestBannerHelperEdgeBranches(t *testing.T) {
	t.Run("port_zero_returns_parent", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		parent := &schema.EntityRef{Type: constants.TypeIPv4, Value: "198.51.100.20", LocalID: 5}

		if got := extractBannerPort(&exec, &shodanIPBanner{}, parent, gen); got != parent {
			t.Fatalf("expected parent source back, got %+v", got)
		}
		if len(exec.Results) != 0 {
			t.Fatalf("expected no port results, got %+v", exec.Results)
		}
	})

	t.Run("web_only_and_empty_source_helpers", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		parent := &schema.EntityRef{Type: constants.TypePort, Value: "19443/tcp", LocalID: 3}
		banner := &shodanIPBanner{Details: &shodanIPBannerDetails{HTTP: &shodanHTTPBanner{Server: "Caddy"}}}

		source := extractBannerServiceAndWeb(&exec, banner, parent, gen)
		if source == nil || source.Type != constants.TypeWebServer || source.Value != "Caddy" {
			t.Fatalf("expected web server source, got %+v", source)
		}
		if extra := appendBannerSourceResult(&exec, constants.TypeService, "", parent, gen); extra != nil {
			t.Fatalf("expected empty value to be ignored, got %+v", extra)
		}
	})

	t.Run("string_results_skip_empty_values", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		source := &schema.EntityRef{Type: constants.TypeService, Value: "https", LocalID: 4}

		appendBannerStringResults(&exec, constants.TypeCPE, []string{"", "cpe:/a:example:test"}, source, gen)
		requireModuleResult(t, exec.Results, constants.TypeCPE, "cpe:/a:example:test")
		if len(exec.Results) != 1 {
			t.Fatalf("expected one non-empty banner string result, got %+v", exec.Results)
		}
	})

	t.Run("country_format_variants", func(t *testing.T) {
		if got := formatShodanCountry(&shodanBannerLocation{CountryName: "Exampleland"}); got != "Exampleland" {
			t.Fatalf("unexpected country name format: %q", got)
		}
		if got := formatShodanCountry(&shodanBannerLocation{CountryCode: "EX"}); got != "EX" {
			t.Fatalf("unexpected country code format: %q", got)
		}
	})

	t.Run("empty_reverse_ip_hostname", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		appendReverseIPHostnameResult(&exec, "", gen)
		if len(exec.Results) != 0 {
			t.Fatalf("expected empty hostname to be ignored, got %+v", exec.Results)
		}
	})
}

func TestExtractBannerSSLNonSANExtensionStillKeepsProperties(t *testing.T) {
	exec := schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	source := &schema.EntityRef{Type: constants.TypePort, Value: "12443/tcp", LocalID: 8}
	banner := &shodanIPBanner{Details: &shodanIPBannerDetails{SSL: &shodanSSLBanner{JARMValue: "non-san-jarm", Extensions: []shodanSSLExtension{{Name: "issuerAltName", Data: "ignored"}}}}}

	extractBannerSSL(&exec, banner, source, gen)
	result := requireModuleResult(t, exec.Results, constants.TypeJARM, "non-san-jarm")
	if result.Source == nil || result.Source.Value != "12443/tcp" {
		t.Fatalf("expected JARM to stay linked to the port source, got %+v", result.Source)
	}
}

func TestSSLHelperBranches(t *testing.T) {
	t.Run("no_ssl_data", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		extractBannerSSL(&exec, &shodanIPBanner{}, nil, gen)
		if len(exec.Results) != 0 {
			t.Fatalf("expected no SSL results, got %+v", exec.Results)
		}
	})

	t.Run("parse_subject_alt_name_deduplicates", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()

		sources := parseSubjectAltName(&exec, "DNS:*."+"example.net"+`\tDNS:*.`+"example.net"+`\tbad value`, gen)
		if len(sources) != 1 {
			t.Fatalf("expected one SAN source, got %+v", sources)
		}
		result := requireModuleResultWithTag(t, exec.Results, constants.TypeDomain, "example.net", constants.TagSan)
		if result.Context != "*."+"example.net" {
			t.Fatalf("expected wildcard SAN context, got %+v", result)
		}
	})

	t.Run("classify_invalid_subject_alt_name", func(t *testing.T) {
		if _, _, _, ok := classifySubjectAltName("bad value"); ok {
			t.Fatal("expected invalid SAN to be rejected")
		}
		if _, _, _, ok := classifySubjectAltName("*."); ok {
			t.Fatal("expected empty wildcard SAN to be rejected")
		}
	})

	t.Run("metadata_and_property_noops", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		appendSubjectAltNameMetadata(&exec, &shodanSSLBanner{CertIssuerValue: "Issuer"}, nil, gen)
		appendSubjectAltNameProperty(&exec, constants.TypeCertIssuer, "", nil, gen)
		appendBannerSSLProperties(&exec, nil, nil, gen)
		if len(exec.Results) != 0 {
			t.Fatalf("expected no SSL metadata results, got %+v", exec.Results)
		}
	})

	t.Run("jarm_only_property", func(t *testing.T) {
		exec := schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		source := &schema.EntityRef{Type: constants.TypePort, Value: "15443/tcp", LocalID: 3}

		appendBannerSSLProperties(&exec, &shodanSSLBanner{JARMValue: "29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d"}, source, gen)
		result := requireModuleResult(t, exec.Results, constants.TypeJARM, "29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d")
		if result.Source == nil || result.Source.Value != "15443/tcp" {
			t.Fatalf("expected JARM to stay linked to source, got %+v", result.Source)
		}
	})

	t.Run("formatters", func(t *testing.T) {
		if got := formatShodanCertIssuer(nil); got != "" {
			t.Fatalf("expected empty issuer string, got %q", got)
		}
		if got := formatShodanCertIssuer(&shodanCertIssuer{CommonName: "Issuer CN"}); got != "CN: Issuer CN" {
			t.Fatalf("unexpected issuer format: %q", got)
		}
		if got := formatShodanCertTime(""); got != "" {
			t.Fatalf("expected empty cert time, got %q", got)
		}
		if got := formatShodanCertTime("not-a-time"); got != "not-a-time" {
			t.Fatalf("expected invalid cert time to stay unchanged, got %q", got)
		}
		if got := formatShodanTLSVersions(nil); got != "" {
			t.Fatalf("expected empty tls versions for nil input, got %q", got)
		}
		if got := formatShodanTLSVersions([]string{"-SSLv3", ""}); got != "" {
			t.Fatalf("expected filtered tls versions to become empty, got %q", got)
		}
	})
}
