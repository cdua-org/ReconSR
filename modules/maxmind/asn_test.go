package maxmind

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"

	"github.com/oschwald/geoip2-golang"
)

func TestGetIPASN_Fixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/GeoIP2-ISP-Test.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var fixtures []map[string]geoip2.ISP
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("failed to unmarshal fixture: %v", err)
	}

	origAsnQuery := asnQueryFunc
	defer func() { asnQueryFunc = origAsnQuery }()

	for _, fixture := range fixtures {
		for cidr, mockResponse := range fixture {
			mockRespCopy := mockResponse
			runASNFixtureTest(t, cidr, &mockRespCopy)
		}
	}
}

func runASNFixtureTest(t *testing.T, cidr string, mockResponse *geoip2.ISP) {
	t.Run(cidr, func(t *testing.T) {
		asnQueryFunc = func(_, _ string) (*geoip2.ISP, *geoip2.ASN, error) {
			return mockResponse, nil, nil
		}

		ipStr := strings.Split(cidr, "/")[0]
		exec := getIPASN(ipStr, "mock.mmdb")

		if exec.Error != nil {
			t.Fatalf("expected no error, got %v", *exec.Error)
		}

		validateASNResults(t, exec, mockResponse)
	})
}

func validateASNResults(t *testing.T, exec schema.ModuleExecution, mockResponse *geoip2.ISP) {
	if mockResponse.AutonomousSystemNumber == 0 && mockResponse.AutonomousSystemOrganization == "" {
		if len(exec.Results) > 0 {
			t.Errorf("expected 0 results for empty ASN")
		}
		return
	}

	var asnRes, orgRes, ispRes string
	for _, res := range exec.Results {
		if res.Type == constants.TypeASN {
			asnRes = res.Value
		}
		if res.Type == constants.TypeOrganization {
			orgRes = res.Value
		}
		if res.Type == constants.TypeISP {
			ispRes = res.Value
		}
	}

	expectedAsn := fmt.Sprintf("AS%d", mockResponse.AutonomousSystemNumber)
	if mockResponse.AutonomousSystemNumber > 0 && asnRes != expectedAsn {
		t.Errorf("expected ASN %s, got %s", expectedAsn, asnRes)
	}
	if mockResponse.AutonomousSystemOrganization != "" && orgRes != mockResponse.AutonomousSystemOrganization && orgRes != mockResponse.Organization {
		t.Errorf("expected Org %s, got %s", mockResponse.AutonomousSystemOrganization, orgRes)
	}
	if mockResponse.ISP != "" && ispRes != mockResponse.ISP {
		t.Errorf("expected ISP %s, got %s", mockResponse.ISP, ispRes)
	}
}

func TestGetIPASN_Error(t *testing.T) {
	origAsnQuery := asnQueryFunc
	defer func() { asnQueryFunc = origAsnQuery }()

	asnQueryFunc = func(_, _ string) (*geoip2.ISP, *geoip2.ASN, error) {
		return nil, nil, errors.New("mock error")
	}

	exec := getIPASN("127.0.0.1", "mock.mmdb")
	if exec.Error == nil {
		t.Error("expected error, got nil")
	}
}

func TestGetIPASN_ASNOnly(t *testing.T) {
	origAsnQuery := asnQueryFunc
	defer func() { asnQueryFunc = origAsnQuery }()

	asnQueryFunc = func(_, _ string) (*geoip2.ISP, *geoip2.ASN, error) {
		asn := &geoip2.ASN{
			AutonomousSystemNumber:       12345,
			AutonomousSystemOrganization: "Test Org",
		}
		return nil, asn, nil
	}

	exec := getIPASN("127.0.0.1", "mock.mmdb")
	if exec.Error != nil {
		t.Errorf("expected no error, got %v", *exec.Error)
	}
	if len(exec.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(exec.Results))
	}
}

func TestGetIPASN_Empty(t *testing.T) {
	origAsnQuery := asnQueryFunc
	defer func() { asnQueryFunc = origAsnQuery }()

	asnQueryFunc = func(_, _ string) (*geoip2.ISP, *geoip2.ASN, error) {
		return nil, nil, nil
	}

	exec := getIPASN("127.0.0.1", "mock.mmdb")
	if exec.Error != nil {
		t.Errorf("expected no error, got %v", *exec.Error)
	}
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(exec.Results))
	}
}
