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

func TestGetGeoIP_EmptyPath(t *testing.T) {
	exec := getGeoIP("192.0.2.1", "")
	if exec.Error != nil {
		t.Errorf("expected no error for empty path")
	}
	if len(exec.Results) > 0 {
		t.Errorf("expected 0 results for empty path")
	}
}

func TestGetGeoIP_NilResponse(t *testing.T) {
	origGeoQuery := geoQueryFunc
	defer func() { geoQueryFunc = origGeoQuery }()

	geoQueryFunc = func(_, _ string) (*geoip2.City, error) {
		var empty *geoip2.City
		return empty, nil
	}

	exec := getGeoIP("192.0.2.1", "mock-city.mmdb")
	if exec.Error != nil {
		t.Errorf("expected no error")
	}
	if len(exec.Results) > 0 {
		t.Errorf("expected 0 results")
	}
}

func TestGetGeoIP_Empty(t *testing.T) {
	origGeoQuery := geoQueryFunc
	defer func() { geoQueryFunc = origGeoQuery }()

	geoQueryFunc = func(_, _ string) (*geoip2.City, error) {
		return &geoip2.City{}, nil
	}

	exec := getGeoIP("192.0.2.1", "mock-city.mmdb")
	if exec.Error != nil {
		t.Errorf("expected no error")
	}
	if len(exec.Results) > 0 {
		t.Errorf("expected 0 results")
	}
}

func TestGetGeoIP_FullFields(t *testing.T) {
	origGeoQuery := geoQueryFunc
	defer func() { geoQueryFunc = origGeoQuery }()

	geoQueryFunc = func(_, _ string) (*geoip2.City, error) {
		var city geoip2.City
		if err := json.Unmarshal([]byte(`{
			"City": {"Names": {"en": "TestCity"}},
			"Subdivisions": [{"Names": {"en": "TestRegion"}}],
			"Continent": {"Code": "TC", "Names": {"en": "Test Continent"}},
			"Country": {"IsoCode": "T1", "Names": {"en": "Test Country One"}},
			"RegisteredCountry": {"IsoCode": "T2", "Names": {"en": "Test Country Two"}},
			"Location": {"AccuracyRadius": 50, "Latitude": 48.8566, "Longitude": 2.3522, "TimeZone": "Test/Zone"},
			"Postal": {"Code": "75000"}
		}`), &city); err != nil {
			panic(err)
		}
		return &city, nil
	}

	exec := getGeoIP("192.0.2.1", "mock-city.mmdb")
	if exec.Error != nil {
		t.Errorf("expected no error")
	}
	if len(exec.Results) == 0 {
		t.Fatalf("expected results")
	}

	val := exec.Results[0].Value
	if !strings.Contains(val, "Region: TestRegion") {
		t.Errorf("expected Region in result: %s", val)
	}
	if !strings.Contains(val, "Continent: Test Continent (TC)") {
		t.Errorf("expected Continent with code in result: %s", val)
	}
	if !strings.Contains(val, "Country: Test Country One (T1)") {
		t.Errorf("expected Country with ISO in result: %s", val)
	}
	if !strings.Contains(val, "RegisteredCountry: Test Country Two (T2)") {
		t.Errorf("expected RegisteredCountry with ISO in result: %s", val)
	}
	if !strings.Contains(val, "AccuracyRadius: 50km") {
		t.Errorf("expected AccuracyRadius in result: %s", val)
	}
	if !strings.Contains(val, "TZ: Test/Zone") {
		t.Errorf("expected TZ in result: %s", val)
	}
	if !strings.Contains(val, "Zip: 75000") {
		t.Errorf("expected Zip in result: %s", val)
	}
}

func TestParseGeo_UnsupportedType(t *testing.T) {
	res := ParseGeo("some string instead of expected struct")
	if res != nil {
		t.Errorf("expected nil for unsupported type, got %v", res)
	}
}

func TestParseGeo_Nil(t *testing.T) {
	res := ParseGeo(nil)
	if res != nil {
		t.Errorf("expected nil for nil input, got %v", res)
	}
}
