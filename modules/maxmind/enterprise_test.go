package maxmind

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/oschwald/geoip2-golang"
)

func TestGetEnterpriseData(t *testing.T) {
	data, err := os.ReadFile("testdata/GeoIP2-Enterprise-Test.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var fixtures []map[string]geoip2.Enterprise
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("failed to unmarshal fixture: %v", err)
	}

	origEntQuery := entQueryFunc
	defer func() { entQueryFunc = origEntQuery }()

	for _, fixture := range fixtures {
		for cidr, mockResponse := range fixture {
			mockRespCopy := mockResponse
			runEnterpriseFixtureTest(t, cidr, &mockRespCopy)
		}
	}
}

func runEnterpriseFixtureTest(t *testing.T, cidr string, mockResponse *geoip2.Enterprise) {
	t.Run(cidr, func(t *testing.T) {
		entQueryFunc = func(_, _ string) (*geoip2.Enterprise, error) {
			return mockResponse, nil
		}

		ipStr := strings.Split(cidr, "/")[0]
		exec := getEnterpriseData(ipStr, "mock.mmdb")

		if exec.Error != nil {
			t.Fatalf("expected no error, got %v", *exec.Error)
		}

		if len(exec.Results) == 0 {
			return
		}
	})
}

func TestGetEnterpriseData_Error(t *testing.T) {
	origEntQuery := entQueryFunc
	defer func() { entQueryFunc = origEntQuery }()

	entQueryFunc = func(_, _ string) (*geoip2.Enterprise, error) {
		return nil, errors.New("mock enterprise error")
	}

	exec := getEnterpriseData("127.0.0.1", "mock.mmdb")
	if exec.Error == nil {
		t.Error("expected error, got nil")
	}
}

func TestGetEnterpriseData_Empty(t *testing.T) {
	origEntQuery := entQueryFunc
	defer func() { entQueryFunc = origEntQuery }()

	entQueryFunc = func(_, _ string) (*geoip2.Enterprise, error) {
		return &geoip2.Enterprise{}, nil
	}

	exec := getEnterpriseData("127.0.0.1", "mock.mmdb")
	if exec.Error != nil {
		t.Errorf("expected no error, got %v", *exec.Error)
	}
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(exec.Results))
	}
}

func TestGetEnterpriseData_FullFields(t *testing.T) {
	origEntQuery := entQueryFunc
	defer func() { entQueryFunc = origEntQuery }()

	entQueryFunc = func(_, _ string) (*geoip2.Enterprise, error) {
		ent := &geoip2.Enterprise{}
		ent.Continent.Code = "TC"
		ent.Continent.Names = map[string]string{"en": "Test Continent"}
		ent.Country.IsoCode = "T1"
		ent.Country.Names = map[string]string{"en": "Test Country One"}
		ent.RegisteredCountry.IsoCode = "T2"
		ent.RegisteredCountry.Names = map[string]string{"en": "Test Country Two"}
		ent.City.Names = map[string]string{"en": "TestCity"}
		ent.Location.AccuracyRadius = 10
		ent.Location.TimeZone = "UTC"
		ent.Postal.Code = "12345"
		ent.City.Confidence = 90
		ent.Country.Confidence = 95
		ent.Postal.Confidence = 80

		ent.Subdivisions = append(ent.Subdivisions, struct {
			Names      map[string]string `maxminddb:"names"`
			IsoCode    string            `maxminddb:"iso_code"`
			GeoNameID  uint              `maxminddb:"geoname_id"`
			Confidence uint8             `maxminddb:"confidence"`
		}{
			Confidence: 85,
			Names:      map[string]string{"en": "TestRegion"},
		})

		ent.Traits.AutonomousSystemNumber = 12345
		ent.Traits.AutonomousSystemOrganization = "Test ASN Org"
		ent.Traits.ConnectionType = "Cable"
		ent.Traits.Domain = "example.com"
		ent.Traits.ISP = "Test ISP"
		ent.Traits.MobileCountryCode = "123"
		ent.Traits.MobileNetworkCode = "45"
		ent.Traits.Organization = "Test Org"
		ent.Traits.StaticIPScore = 20.5
		ent.Traits.UserType = "business"

		return ent, nil
	}

	exec := getEnterpriseData("127.0.0.1", "mock.mmdb")
	if exec.Error != nil {
		t.Fatalf("expected no error, got %v", *exec.Error)
	}
	if len(exec.Results) == 0 {
		t.Fatalf("expected results, got 0")
	}
}

func TestGetEnterpriseData_StaticIPScore_Dynamic(t *testing.T) {
	origEntQuery := entQueryFunc
	defer func() { entQueryFunc = origEntQuery }()

	entQueryFunc = func(_, _ string) (*geoip2.Enterprise, error) {
		ent := &geoip2.Enterprise{}
		ent.Traits.StaticIPScore = 50.0
		return ent, nil
	}
	exec := getEnterpriseData("127.0.0.1", "mock.mmdb")
	if exec.Error != nil {
		t.Fatalf("expected no error")
	}
}

func TestGetEnterpriseData_StaticIPScore_Static(t *testing.T) {
	origEntQuery := entQueryFunc
	defer func() { entQueryFunc = origEntQuery }()

	entQueryFunc = func(_, _ string) (*geoip2.Enterprise, error) {
		ent := &geoip2.Enterprise{}
		ent.Traits.StaticIPScore = 80.0
		return ent, nil
	}
	exec := getEnterpriseData("127.0.0.1", "mock.mmdb")
	if exec.Error != nil {
		t.Fatalf("expected no error")
	}
}

func TestGetEnterpriseData_NilResponse(t *testing.T) {
	origEntQuery := entQueryFunc
	defer func() { entQueryFunc = origEntQuery }()

	entQueryFunc = func(_, _ string) (*geoip2.Enterprise, error) {
		var res *geoip2.Enterprise
		return res, nil
	}

	exec := getEnterpriseData("127.0.0.1", "mock.mmdb")
	if exec.Error != nil {
		t.Fatalf("expected no error, got %v", *exec.Error)
	}
	if len(exec.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(exec.Results))
	}
}
