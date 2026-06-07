package shodan

import (
	"encoding/json"
	"testing"

	"slices"
)

func TestShodanIPBannerUnmarshalBranches(t *testing.T) {
	var banner shodanIPBanner
	if err := json.Unmarshal([]byte(`{"hash":1,"port":53,"transport":"udp","timestamp":" 2026-06-07T00:00:00Z ","opts":{"heartbleed":"SAFE"},"product":"dns","version":"1","_shodan":{"module":"dns-udp"}}`), &banner); err != nil {
		t.Fatalf("unexpected banner unmarshal error: %v", err)
	}
	if banner.Hash != 1 || banner.Port != 53 || banner.Transport != shodanTransportUDP {
		t.Fatalf("unexpected banner core values: %+v", banner)
	}
	if banner.Timestamp != "2026-06-07T00:00:00Z" {
		t.Fatalf("expected trimmed timestamp, got %q", banner.Timestamp)
	}
	if banner.Heartbleed != "" {
		t.Fatalf("expected safe heartbleed to be ignored, got %q", banner.Heartbleed)
	}
	if banner.ModuleLabel != "dns-udp" {
		t.Fatalf("unexpected module label: %q", banner.ModuleLabel)
	}
	if banner.ServiceValue == nil || *banner.ServiceValue != "dns 1" {
		t.Fatalf("unexpected service value: %+v", banner.ServiceValue)
	}

	if err := json.Unmarshal([]byte(`[]`), &banner); err == nil {
		t.Fatal("expected invalid banner payload to fail")
	}
}

func TestShodanIPBannerUnmarshalWithArtifactsAndDetails(t *testing.T) {
	var banner shodanIPBanner
	if err := json.Unmarshal([]byte(`{"hash":11,"port":443,"transport":"UDP","timestamp":"2026-06-07T00:00:00Z","cpe":["cpe:/a:example:test"],"cpe23":["cpe:2.3:a:example:test"],"vulns":{"CVE-2026-0001":{"verified":true}},"http":{"server":"ExampleHTTP"},"ssl":{"jarm":"artifact-jarm","versions":["TLSv1.3"],"cert":{"expires":"20270720194415Z","issuer":{"CN":"Issuer CN"},"fingerprint":{"sha1":"aa"},"extensions":[{"name":"subjectAltName","data":"DNS:*.example.net"}]}},"location":{"country_code":"EX"}}`), &banner); err != nil {
		t.Fatalf("unexpected banner unmarshal error: %v", err)
	}
	if banner.Artifacts == nil || len(banner.Artifacts.CPE) != 1 || len(banner.Artifacts.CPE23) != 1 || len(banner.Artifacts.Vulns) != 1 {
		t.Fatalf("expected artifacts to be populated, got %+v", banner.Artifacts)
	}
	if banner.Details == nil || banner.Details.HTTP == nil || banner.Details.SSL == nil || banner.Details.Location == nil {
		t.Fatalf("expected banner details to be populated, got %+v", banner.Details)
	}
}

func TestShodanRawBannerCoreBranches(t *testing.T) {
	artifacts, hash, port, transport, err := parseShodanRawBannerCore([]byte(`{"hash":2,"port":443}`))
	if err != nil {
		t.Fatalf("unexpected core parse error: %v", err)
	}
	if artifacts != nil || hash != 2 || port != 443 || transport != shodanTransportUnknown {
		t.Fatalf("unexpected minimal core parse result: artifacts=%+v hash=%d port=%d transport=%d", artifacts, hash, port, transport)
	}

	artifacts, _, _, transport, err = parseShodanRawBannerCore([]byte(`{"hash":3,"port":53,"transport":"udp","cpe":["cpe:/a:example:test"],"cpe23":["cpe:2.3:a:example:test"],"vulns":{"CVE-2026-0001":{"verified":true}}}`))
	if err != nil {
		t.Fatalf("unexpected populated core parse error: %v", err)
	}
	if artifacts == nil || len(artifacts.CPE) != 1 || len(artifacts.CPE23) != 1 || len(artifacts.Vulns) != 1 || transport != shodanTransportUDP {
		t.Fatalf("unexpected populated core result: artifacts=%+v transport=%d", artifacts, transport)
	}

	if _, _, _, _, err := parseShodanRawBannerCore([]byte(`{"cpe":1,"hash":2,"port":443}`)); err == nil {
		t.Fatal("expected invalid cpe field to fail")
	}
}

func TestShodanRawBannerMetaBranches(t *testing.T) {
	heartbleed, timestamp, err := parseShodanRawBannerMeta([]byte(`{"timestamp":" 2026-06-07T00:00:00Z ","opts":{"heartbleed":"status - VULNERABLE"}}`))
	if err != nil {
		t.Fatalf("unexpected meta parse error: %v", err)
	}
	if heartbleed != "VULNERABLE" || timestamp != "2026-06-07T00:00:00Z" {
		t.Fatalf("unexpected meta parse result: heartbleed=%q timestamp=%q", heartbleed, timestamp)
	}

	if _, _, err := parseShodanRawBannerMeta([]byte(`{"timestamp":1}`)); err == nil {
		t.Fatal("expected invalid timestamp type to fail")
	}
	if _, _, err := parseShodanRawBannerMeta([]byte(`{"opts":1}`)); err == nil {
		t.Fatal("expected invalid opts field to fail")
	}
}

func TestDecodeAndUnmarshalShodanBannerFieldBranches(t *testing.T) {
	if _, err := decodeShodanRawBannerObject([]byte(`{`)); err == nil {
		t.Fatal("expected invalid json object to fail")
	}

	fields := map[string]json.RawMessage{
		"null_field":    json.RawMessage("null"),
		"invalid_field": json.RawMessage(`1`),
	}
	var target string
	if err := unmarshalShodanBannerField(fields, "missing", &target); err != nil {
		t.Fatalf("expected missing field to be ignored, got %v", err)
	}
	if err := unmarshalShodanBannerField(fields, "null_field", &target); err != nil {
		t.Fatalf("expected null field to be ignored, got %v", err)
	}
	if err := unmarshalShodanBannerField(fields, "invalid_field", &target); err == nil {
		t.Fatal("expected invalid field type to fail")
	}
}

func TestShodanRawBannerServiceAndDetailsErrors(t *testing.T) {
	if _, err := parseShodanRawBannerService([]byte(`{`)); err == nil {
		t.Fatal("expected invalid service payload to fail")
	}
	if _, err := parseShodanRawBannerDetails([]byte(`{`)); err == nil {
		t.Fatal("expected invalid details payload to fail")
	}
}

func TestShodanTransportAndFormatHelpers(t *testing.T) {
	var transport shodanTransport
	if err := transport.UnmarshalJSON([]byte(`"udp"`)); err != nil {
		t.Fatalf("unexpected udp transport error: %v", err)
	}
	if transport != shodanTransportUDP {
		t.Fatalf("expected udp transport, got %d", transport)
	}
	if err := transport.UnmarshalJSON([]byte(`"icmp"`)); err != nil {
		t.Fatalf("unexpected unknown transport error: %v", err)
	}
	if transport != shodanTransportUnknown {
		t.Fatalf("expected unknown transport, got %d", transport)
	}
	if err := transport.UnmarshalJSON([]byte(`1`)); err == nil {
		t.Fatal("expected invalid transport payload to fail")
	}

	if got := formatShodanTransport(shodanTransportUDP); got == "" {
		t.Fatalf("expected non-empty udp transport string, got %q", got)
	}
	if got := formatShodanTransport(shodanTransportTCP); got == "" {
		t.Fatalf("expected non-empty tcp transport string, got %q", got)
	}
	if got := formatShodanTransport(shodanTransportUnknown); got != "" {
		t.Fatalf("expected empty unknown transport string, got %q", got)
	}
}

func TestShodanFingerprintAndHeartbleedHelpers(t *testing.T) {
	if got := formatShodanCertFingerprints(nil); got != nil {
		t.Fatalf("expected nil fingerprints for nil input, got %+v", got)
	}

	emptyOnly := shodanRawBannerCertFingerprint{"": "value", "sha1": " "}
	if got := formatShodanCertFingerprints(&emptyOnly); got != nil {
		t.Fatalf("expected invalid-only fingerprints to be ignored, got %+v", got)
	}

	mixed := shodanRawBannerCertFingerprint{" SHA1 ": "aa", "sha1": "aa", " sha256 ": "bb", "md5": " "}
	formatted := formatShodanCertFingerprints(&mixed)
	if !slices.Equal(formatted, []string{"sha1:aa", "sha256:bb"}) {
		t.Fatalf("unexpected formatted fingerprints: %+v", formatted)
	}

	if got := formatShodanHeartbleed(nil); got != "" {
		t.Fatalf("expected nil heartbleed to be empty, got %q", got)
	}
	if got := formatShodanHeartbleed(&shodanRawBannerOpts{}); got != "" {
		t.Fatalf("expected empty heartbleed to be ignored, got %q", got)
	}
	if got := formatShodanHeartbleed(&shodanRawBannerOpts{Heartbleed: "NOT VULNERABLE"}); got != "" {
		t.Fatalf("expected not vulnerable to be ignored, got %q", got)
	}
	if got := formatShodanHeartbleed(&shodanRawBannerOpts{Heartbleed: "SAFE"}); got != "" {
		t.Fatalf("expected safe value to be ignored, got %q", got)
	}
	if got := formatShodanHeartbleed(&shodanRawBannerOpts{Heartbleed: "status - VULNERABLE"}); got != "VULNERABLE" {
		t.Fatalf("unexpected vulnerable heartbleed status: %q", got)
	}
}
