package ip2location

import (
	"errors"
	"testing"

	"github.com/ip2location/ip2location-go/v9"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestGetGeoIP_FullPremium(t *testing.T) {
	geoQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return mockGeoRecord, nil
	}
	defer func() { geoQueryFunc = defaultGeoQuery }()

	exec := getGeoIP("192.0.2.1", "dummy.bin")

	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireResultWithContext(t, exec.Results, constants.TypeGeo, "City: Exampleville | District: Example District | Region: Exampleshire | Country: Exampleland (EX) | Lat/Lon: 51.509865, -0.118092 | Zip: EX1 2AB | TZ: +00:00 | Elevation: 15m", "Geo Location")
	requireResultWithContext(t, exec.Results, constants.TypeISP, "Example ISP Ltd", "ISP")
	requireModuleResult(t, exec.Results, constants.TypeDomain, "example.net")
	requireResultWithContext(t, exec.Results, constants.TypeUsageType, "Fixed Line or Mobile ISP", "Usage Type")
	requireResultWithContext(t, exec.Results, constants.TypeInfo, "DSL", "Connection Speed")
	requireResultWithContext(t, exec.Results, constants.TypeInfo, "U", "Address Type")
	requireResultWithContext(t, exec.Results, constants.TypeInfo, "IAB19", "IAB Category")
	requireResultWithContext(t, exec.Results, constants.TypeInfo, "Example Telecom (MCC: 234, MNC: 15)", "Mobile Network")
}

func TestGetGeoIP_LiteAndUnavailable(t *testing.T) {
	geoQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return mockGeoRecordLite, nil
	}
	defer func() { geoQueryFunc = defaultGeoQuery }()

	exec := getGeoIP("198.51.100.1", "dummy.bin")

	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireNoModuleResult(t, exec.Results, constants.TypeGeo)
	requireNoModuleResult(t, exec.Results, constants.TypeISP)
	requireNoModuleResult(t, exec.Results, constants.TypeDomain)
}

func TestGetGeoIP_Error(t *testing.T) {
	geoQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return nil, errors.New("db read error")
	}
	defer func() { geoQueryFunc = defaultGeoQuery }()

	exec := getGeoIP("203.0.113.1", "dummy.bin")

	if exec.Error == nil {
		t.Fatal("expected error, got nil")
	}

	if len(exec.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(exec.Results))
	}
}

func TestGetGeoIP_MobileNetworkOnly(t *testing.T) {
	geoQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return &ip2location.IP2Locationrecord{
			Mobilebrand: "-",
			Mcc:         "123",
			Mnc:         "45",
		}, nil
	}
	defer func() { geoQueryFunc = defaultGeoQuery }()

	exec := getGeoIP("192.0.2.2", "dummy.bin")

	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireResultWithContext(t, exec.Results, constants.TypeInfo, "MCC: 123, MNC: 45", "Mobile Network")
}
