package ip2location

import (
	"errors"
	"testing"

	"github.com/ip2location/ip2proxy-go/v4"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestGetProxyCheck_Full(t *testing.T) {
	proxyQueryFunc = func(_, _ string) (*ip2proxy.IP2ProxyRecord, error) {
		return mockProxyRecord, nil
	}
	defer func() { proxyQueryFunc = defaultProxyQuery }()

	exec := getProxyCheck("192.0.2.1", "dummy.bin")

	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireModuleResult(t, exec.Results, constants.TypeTag, constants.TagVPN)
	requireModuleResult(t, exec.Results, constants.TypeTag, constants.TagScanner)
	requireModuleResult(t, exec.Results, constants.TypeTag, constants.TagSpam)

	requireResultWithContext(t, exec.Results, constants.TypeAbuseScore, "99", "IP2Proxy Fraud Score")
	requireModuleResult(t, exec.Results, constants.TypeDate, "Last Seen: 14 days ago")
	requireResultWithContext(t, exec.Results, constants.TypeInfo, "Example VPN Provider", "VPN/Proxy Provider")
	requireModuleResult(t, exec.Results, constants.TypeDomain, "example.net")
	requireResultWithContext(t, exec.Results, constants.TypeUsageType, "University/College/School", "Proxy Usage Type")
}

func TestGetProxyCheck_NotProxy(t *testing.T) {
	proxyQueryFunc = func(_, _ string) (*ip2proxy.IP2ProxyRecord, error) {
		return &ip2proxy.IP2ProxyRecord{IsProxy: 0}, nil
	}
	defer func() { proxyQueryFunc = defaultProxyQuery }()

	exec := getProxyCheck("198.51.100.1", "dummy.bin")

	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	if len(exec.Results) != 0 {
		t.Fatalf("expected 0 results for non-proxy, got %d", len(exec.Results))
	}
}

func TestGetProxyCheck_Error(t *testing.T) {
	proxyQueryFunc = func(_, _ string) (*ip2proxy.IP2ProxyRecord, error) {
		return nil, errors.New("proxy read error")
	}
	defer func() { proxyQueryFunc = defaultProxyQuery }()

	exec := getProxyCheck("203.0.113.1", "dummy.bin")

	if exec.Error == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetProxyCheck_EmptyDetails(t *testing.T) {
	proxyQueryFunc = func(_, _ string) (*ip2proxy.IP2ProxyRecord, error) {
		return &ip2proxy.IP2ProxyRecord{
			IsProxy:    1,
			ProxyType:  "-",
			Threat:     "-",
			FraudScore: "-",
			LastSeen:   "-",
			Provider:   "-",
			Domain:     "-",
			UsageType:  "-",
		}, nil
	}
	defer func() { proxyQueryFunc = defaultProxyQuery }()

	exec := getProxyCheck("192.0.2.1", "dummy.bin")
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	if len(exec.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(exec.Results))
	}
}

func TestMapProxyTypeToTag(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{netTypeVPN, constants.TagVPN},
		{netTypeTOR, constants.TagTorExit},
		{netTypePUB, constants.TagProxy},
		{netTypeWEB, constants.TagProxy},
		{netTypeDCH, constants.TagDataCenter},
		{netTypeSES, constants.TagCrawler},
		{netTypeAIC, constants.TagAICrawler},
		{netTypeRES, constants.TagResidentialProxy},
		{netTypeCPN, constants.TagPrivacyNetwork},
		{netTypeEPN, constants.TagPrivacyNetwork},
		{"UNKNOWN_PROXY_TYPE", "unknown_proxy_type"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := mapProxyTypeToTag(tt.input); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestMapThreatToTag(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{threatScanner, constants.TagScanner},
		{threatBotnet, constants.TagSpamBotnet},
		{threatSpam, constants.TagSpam},
		{threatBogon, constants.TagBogon},
		{"UNKNOWN_THREAT_TYPE", "unknown_threat_type"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := mapThreatToTag(tt.input); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
