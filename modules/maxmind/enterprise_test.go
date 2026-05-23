package maxmind

import (
	"encoding/json"
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
