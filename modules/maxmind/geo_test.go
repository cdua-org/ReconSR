package maxmind

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"

	"github.com/oschwald/geoip2-golang"
)

func TestGetGeoIP_City_Fixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/GeoIP2-Enterprise-Test.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var fixtures []map[string]geoip2.City
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("failed to unmarshal fixture: %v", err)
	}

	origGeoQuery := geoQueryFunc
	defer func() { geoQueryFunc = origGeoQuery }()

	for _, fixture := range fixtures {
		for cidr, mockResponse := range fixture {
			mockRespCopy := mockResponse
			runCityFixtureTest(t, cidr, &mockRespCopy)
		}
	}
}

func runCityFixtureTest(t *testing.T, cidr string, mockResponse *geoip2.City) {
	t.Run(cidr, func(t *testing.T) {
		geoQueryFunc = func(_, _ string) (*geoip2.City, error) {
			return mockResponse, nil
		}

		ipStr := strings.Split(cidr, "/")[0]
		exec := getGeoIP(ipStr, "mock-city.mmdb")

		if exec.Error != nil {
			t.Fatalf("expected no error, got %v", *exec.Error)
		}

		cityName := mockResponse.City.Names["en"]
		countryName := mockResponse.Country.Names["en"]
		iso := mockResponse.Country.IsoCode

		if cityName == "" && countryName == "" {
			return
		}

		var geoRes string
		for _, res := range exec.Results {
			if res.Type == constants.TypeGeo {
				geoRes = res.Value
				break
			}
		}

		if cityName != "" && !strings.Contains(geoRes, "City: "+cityName) {
			t.Errorf("expected City %s in result %s", cityName, geoRes)
		}
		if countryName != "" && !strings.Contains(geoRes, "Country: "+countryName) {
			t.Errorf("expected Country %s in result %s", countryName, geoRes)
		}
		if iso != "" && !strings.Contains(geoRes, "("+iso+")") {
			t.Errorf("expected ISO %s in result %s", iso, geoRes)
		}
	})
}
