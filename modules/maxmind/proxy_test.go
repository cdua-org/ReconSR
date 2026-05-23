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
