package maxmind

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestGetProxyCheck_Fixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/GeoIP-Anonymous-Plus-Test.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var fixtures []map[string]AnonymousPlusIP
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("failed to unmarshal fixture: %v", err)
	}

	origProxyQuery := proxyQueryFunc
	defer func() { proxyQueryFunc = origProxyQuery }()

	for _, fixture := range fixtures {
		for cidr, mockResponse := range fixture {
			mockRespCopy := mockResponse
			runFixtureTest(t, cidr, &mockRespCopy)
		}
	}
}

func runFixtureTest(t *testing.T, cidr string, mockResponse *AnonymousPlusIP) {
	t.Run(cidr, func(t *testing.T) {
		proxyQueryFunc = func(_, _ string) (*AnonymousPlusIP, error) {
			return mockResponse, nil
		}

		ipStr := strings.Split(cidr, "/")[0]
		exec := getProxyCheck(ipStr, "mock.mmdb")

		if exec.Error != nil {
			t.Fatalf("expected no error, got %v", *exec.Error)
		}

		if !mockResponse.IsAnonymous && len(exec.Results) > 0 {
			t.Fatalf("expected 0 results for non-anonymous IP, got %d", len(exec.Results))
		}

		var tags []string
		for _, res := range exec.Results {
			if res.Type == constants.TypeTag {
				tags = append(tags, res.Value)
			}
		}

		assertTag(t, tags, mockResponse.IsAnonymousVPN, constants.TagVPN)
		assertTag(t, tags, mockResponse.IsHostingProvider, constants.TagDataCenter)
		assertTag(t, tags, mockResponse.IsPublicProxy, constants.TagProxy)
		assertTag(t, tags, mockResponse.IsResidentialProxy, constants.TagResidentialProxy)
		assertTag(t, tags, mockResponse.IsTorExitNode, constants.TagTorExit)
	})
}

func assertTag(t *testing.T, tags []string, condition bool, expectedTag string) {
	t.Helper()
	if condition && !slices.Contains(tags, expectedTag) {
		t.Errorf("expected tag %s", expectedTag)
	}
}

func TestGetProxyCheck_Error(t *testing.T) {
	origProxyQuery := proxyQueryFunc
	defer func() { proxyQueryFunc = origProxyQuery }()

	proxyQueryFunc = func(_, _ string) (*AnonymousPlusIP, error) {
		return nil, os.ErrNotExist
	}

	exec := getProxyCheck("192.0.2.1", "mock.mmdb")
	if exec.Error == nil {
		t.Errorf("expected error, got nil")
	}
}

func TestGetProxyCheck_Empty(t *testing.T) {
	origProxyQuery := proxyQueryFunc
	defer func() { proxyQueryFunc = origProxyQuery }()

	proxyQueryFunc = func(_, _ string) (*AnonymousPlusIP, error) {
		return &AnonymousPlusIP{IsAnonymous: true}, nil
	}

	exec := getProxyCheck("192.0.2.1", "mock.mmdb")
	if exec.Error != nil {
		t.Errorf("expected no error")
	}
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(exec.Results))
	}
}

func TestGetProxyCheck_FullFields(t *testing.T) {
	origProxyQuery := proxyQueryFunc
	defer func() { proxyQueryFunc = origProxyQuery }()

	proxyQueryFunc = func(_, _ string) (*AnonymousPlusIP, error) {
		return &AnonymousPlusIP{
			NetworkLastSeen:      "2026-05-23",
			ProviderName:         "Test VPN",
			IsAnonymous:          true,
			IsAnonymousVPN:       true,
			IsHostingProvider:    true,
			IsPublicProxy:        true,
			IsResidentialProxy:   true,
			IsTorExitNode:        true,
			AnonymizerConfidence: 99,
		}, nil
	}

	exec := getProxyCheck("192.0.2.1", "mock.mmdb")
	if exec.Error != nil {
		t.Errorf("expected no error")
	}

	var tags []string
	for _, res := range exec.Results {
		if res.Type == constants.TypeTag {
			tags = append(tags, res.Value)
		}
	}

	assertTag(t, tags, true, constants.TagVPN)
	assertTag(t, tags, true, constants.TagDataCenter)
	assertTag(t, tags, true, constants.TagProxy)
	assertTag(t, tags, true, constants.TagResidentialProxy)
	assertTag(t, tags, true, constants.TagTorExit)

	var hasProvider, hasConfidence, hasLastSeen bool
	for _, res := range exec.Results {
		if strings.Contains(res.Value, "Test VPN") {
			hasProvider = true
		}
		if strings.Contains(res.Value, "99") {
			hasConfidence = true
		}
		if strings.Contains(res.Value, "2026-05-23") {
			hasLastSeen = true
		}
	}
	if !hasProvider {
		t.Errorf("expected provider name")
	}
	if !hasConfidence {
		t.Errorf("expected confidence")
	}
	if !hasLastSeen {
		t.Errorf("expected network last seen")
	}
}
