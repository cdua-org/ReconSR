package ip2location

import (
	"errors"
	"testing"

	"github.com/ip2location/ip2location-go/v9"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestGetIPASN_FullPremium(t *testing.T) {
	asnQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return mockASNRecord, nil
	}
	defer func() { asnQueryFunc = defaultASNQuery }()

	exec := getIPASN("192.0.2.1", "dummy.bin")

	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireModuleResult(t, exec.Results, constants.TypeASN, "AS12345")
	requireResultWithContext(t, exec.Results, constants.TypeOrganization, "Example Org", "AS Owner")
	requireModuleResult(t, exec.Results, constants.TypeDomain, "example.org")
	requireResultWithContext(t, exec.Results, constants.TypeUsageType, "Organization", "AS Usage Type")
	requireResultWithContext(t, exec.Results, constants.TypeCIDR, "192.0.2.0/24", "AS CIDR")
}

func TestGetIPASN_Error(t *testing.T) {
	asnQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return nil, errors.New("asn read error")
	}
	defer func() { asnQueryFunc = defaultASNQuery }()

	exec := getIPASN("198.51.100.1", "dummy.bin")

	if exec.Error == nil {
		t.Fatal("expected error, got nil")
	}
}
