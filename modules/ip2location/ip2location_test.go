package ip2location

import (
	"testing"

	"github.com/ip2location/ip2location-go/v9"
	"github.com/ip2location/ip2proxy-go/v4"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

var mockGeoRecord = &ip2location.IP2Locationrecord{
	Country_short: "EX",
	Country_long:  "Exampleland",
	Region:        "Exampleshire",
	City:          "Exampleville",
	Latitude:      51.509865,
	Longitude:     -0.118092,
	Zipcode:       "EX1 2AB",
	Timezone:      "+00:00",
	Isp:           "Example ISP Ltd",
	Domain:        "example.net",
	Netspeed:      "DSL",
	Iddcode:       "44",
	Areacode:      "020",
	Mcc:           "234",
	Mnc:           "15",
	Mobilebrand:   "Example Telecom",
	Elevation:     15,
	Usagetype:     "ISP/MOB",
	Addresstype:   "U",
	Category:      "IAB19",
	District:      "Example District",
}

var mockGeoRecordLite = &ip2location.IP2Locationrecord{
	Country_short: "-",
	Country_long:  "This parameter is unavailable for selected data file. Please upgrade the data file.",
	Region:        "-",
	City:          "This parameter is unavailable",
	Latitude:      0.0,
	Longitude:     0.0,
	Elevation:     0.0,
}

var mockASNRecord = &ip2location.IP2Locationrecord{
	Asn:         "12345",
	As:          "Example Org",
	Asdomain:    "example.org",
	Asusagetype: "ORG",
	Ascidr:      "192.0.2.0/24",
}

var mockProxyRecord = &ip2proxy.IP2ProxyRecord{
	IsProxy:      1,
	ProxyType:    "VPN",
	Threat:       "SCANNER/SPAM",
	FraudScore:   "99",
	LastSeen:     "14",
	Provider:     "Example VPN Provider",
	CountryShort: "EX",
	CountryLong:  "Exampleland",
	Region:       "Exampleshire",
	City:         "Exampleville",
	Isp:          "Example ISP Ltd",
	Domain:       "example.net",
	UsageType:    "EDU",
	Asn:          "AS12345",
	As:           "Example Hosting",
}

func requireModuleResult(t *testing.T, results []schema.ModuleResult, resType, expectedValue string) {
	t.Helper()
	for _, r := range results {
		if r.Type == resType && r.Value == expectedValue {
			return
		}
	}
	t.Fatalf("expected result type %q with value %q not found in %d results", resType, expectedValue, len(results))
}

func requireNoModuleResult(t *testing.T, results []schema.ModuleResult, resType string) {
	t.Helper()
	for _, r := range results {
		if r.Type == resType {
			t.Fatalf("did not expect result type %q, but found value %q", resType, r.Value)
		}
	}
}

func requireResultWithContext(t *testing.T, results []schema.ModuleResult, resType, expectedValue, expectedContext string) {
	t.Helper()
	for _, r := range results {
		if r.Type == resType && r.Value == expectedValue && r.Context == expectedContext {
			return
		}
	}
	t.Fatalf("expected result type %q, value %q, context %q not found", resType, expectedValue, expectedContext)
}

func TestModuleInitialization(t *testing.T) {
	originalCheck := checkFileExists
	checkFileExists = func(_ string) bool {
		return true
	}
	defer func() { checkFileExists = originalCheck }()

	m := New()
	if m.Name() != "ip2location" {
		t.Errorf("expected name ip2location, got %q", m.Name())
	}

	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("capabilities error: %v", err)
	}

	foundGeo := false
	for _, f := range caps.Functions {
		if f == constants.FuncGetGeoIP {
			foundGeo = true
		}
	}
	if !foundGeo {
		t.Errorf("expected %q function in capabilities", constants.FuncGetGeoIP)
	}
}

func requireUniqueLocalIDs(t *testing.T, results []schema.ModuleResult) {
	seen := make(map[int]bool)
	for _, res := range results {
		if res.LocalID <= 0 {
			t.Errorf("expected positive LocalID, got %d for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		if seen[res.LocalID] {
			t.Errorf("duplicate LocalID %d found for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		seen[res.LocalID] = true

		if res.Source != nil {
			if res.Source.LocalID <= 0 {
				t.Errorf("expected positive LocalID in source, got %d", res.Source.LocalID)
			}
			if res.Source.LocalID >= res.LocalID {
				t.Errorf("expected source LocalID %d to be strictly less than result LocalID %d (Type: %s, Value: %s)", res.Source.LocalID, res.LocalID, res.Type, res.Value)
			}
		}
	}
}

func TestModule_LocalIDChaining_Geo(t *testing.T) {
	geoQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return mockGeoRecord, nil
	}
	defer func() { geoQueryFunc = defaultGeoQuery }()

	exec := getGeoIP("192.0.2.1", "dummy.bin")
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestModule_LocalIDChaining_ASN(t *testing.T) {
	asnQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return mockASNRecord, nil
	}
	defer func() { asnQueryFunc = defaultASNQuery }()

	exec := getIPASN("192.0.2.1", "dummy.bin")
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestModule_LocalIDChaining_Proxy(t *testing.T) {
	proxyQueryFunc = func(_, _ string) (*ip2proxy.IP2ProxyRecord, error) {
		return mockProxyRecord, nil
	}
	defer func() { proxyQueryFunc = defaultProxyQuery }()

	exec := getProxyCheck("192.0.2.1", "dummy.bin")
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireUniqueLocalIDs(t, exec.Results)
}
