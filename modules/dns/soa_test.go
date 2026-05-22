package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestBuildSOAPrimaryNSResultSkipsInvalidAndNormalizes(t *testing.T) {
	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: "ns1.example.com. admin.example.com. 2025010101 3600 900 604800 86400"}
	result := buildSOAPrimaryNSResult("NS1.EXAMPLE.COM.", "primary.soa.example.com", soaRef, modutil.NewLocalIDGenerator())
	if result == nil {
		t.Fatal("expected primary NS result")
	}

	if result.Type != constants.TypeSubdomain {
		t.Fatalf("expected type subdomain, got %q", result.Type)
	}

	if result.Value != "ns1.example.com" {
		t.Fatalf("expected normalized NS value, got %q", result.Value)
	}

	if !slices.Contains(result.Tags, constants.TagNS) {
		t.Fatalf("expected ns tag, got %v", result.Tags)
	}

	if result.Context != "Primary NS" {
		t.Fatalf("expected primary NS context, got %q", result.Context)
	}

	if result.OutOfScope {
		t.Fatal("expected in-scope NS")
	}

	if result.Source != soaRef {
		t.Fatal("expected source reference")
	}

	if buildSOAPrimaryNSResult(".bad.example.com.", "primary.soa.example.com", soaRef, modutil.NewLocalIDGenerator()) != nil {
		t.Fatal("expected invalid primary NS to be skipped")
	}
}

func TestBuildSOAPrimaryNSResultSelfReferential(t *testing.T) {
	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: "soa_record"}
	if buildSOAPrimaryNSResult("example.com.", "example.com", soaRef, modutil.NewLocalIDGenerator()) != nil {
		t.Fatal("expected self-referential primary NS to be skipped")
	}
}

func TestBuildSOAResponsibleEmailResultSkipsInvalidAndUsesValidatedType(t *testing.T) {
	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: "ns2.example.net. hostmaster.example.net. 2025020101 7200 1800 1209600 3600"}
	result := buildSOAResponsibleEmailResult(`"john".example.com.`, "responsible.soa.example.com", soaRef, modutil.NewLocalIDGenerator())
	if result == nil {
		t.Fatal("expected responsible email result")
	}

	if result.Type != constants.TypeEmailExtra {
		t.Fatalf("expected type email-extra, got %q", result.Type)
	}

	if result.Value != `"john"@example.com` {
		t.Fatalf("expected validated responsible email value, got %q", result.Value)
	}

	if result.Context != "Responsible Email" {
		t.Fatalf("expected responsible email context, got %q", result.Context)
	}

	if result.OutOfScope {
		t.Fatal("expected in-scope responsible email")
	}

	if result.Source != soaRef {
		t.Fatal("expected source reference")
	}

	if buildSOAResponsibleEmailResult("bad..example.com.", "responsible.soa.example.com", soaRef, modutil.NewLocalIDGenerator()) != nil {
		t.Fatal("expected invalid responsible email to be skipped")
	}
}

func TestGetSOAData(t *testing.T) {
	res := getSOAData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Log("No SOA records found for example.com")
	default:
		if len(res.Results) != 4 {
			t.Errorf("expected 4 results, got %d", len(res.Results))
		}
	}
}

func TestSOACapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSOA) {
		t.Error("expected get_soa in capabilities")
	}
}
