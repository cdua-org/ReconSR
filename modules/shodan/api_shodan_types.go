package shodan

import (
	"encoding/json"
	"fmt"
	"strings"
)

type shodanIPResponse struct {
	Tags       []string         `json:"tags"`
	Domains    []string         `json:"domains"`
	ASN        string           `json:"asn"`
	ISP        string           `json:"isp"`
	Org        string           `json:"org"`
	OS         string           `json:"os"`
	Hostnames  []string         `json:"hostnames"`
	LastUpdate string           `json:"last_update"`
	Data       []shodanIPBanner `json:"data"`
}

type shodanIPBanner struct {
	Artifacts    *shodanIPBannerArtifacts `json:"-"`
	Details      *shodanIPBannerDetails   `json:"-"`
	ServiceValue *string                  `json:"-"`
	ModuleLabel  string                   `json:"-"`
	Hash         int64                    `json:"hash"`
	Port         int                      `json:"port"`
	Transport    shodanTransport          `json:"transport"`
}

type shodanIPBannerArtifacts struct {
	Vulns map[string]shodanVuln `json:"vulns"`
	CPE   []string              `json:"cpe"`
	CPE23 []string              `json:"cpe23"`
}

type shodanIPBannerDetails struct {
	HTTP     *shodanHTTPBanner     `json:"-"`
	SSL      *shodanSSLBanner      `json:"-"`
	Location *shodanBannerLocation `json:"-"`
}

type shodanHTTPBanner struct {
	Server string `json:"server"`
}

type shodanSSLBanner struct {
	CertIssuerValue   string               `json:"-"`
	CertNotAfterValue string               `json:"-"`
	TLSVersionsValue  string               `json:"-"`
	Extensions        []shodanSSLExtension `json:"-"`
}

type shodanCertIssuer struct {
	CommonName string `json:"CN"`
	Country    string `json:"C"`
	Org        string `json:"O"`
}

type shodanSSLExtension struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type shodanVuln struct {
	Summary  string `json:"summary"`
	Verified bool   `json:"verified"`
}

type shodanBannerLocation struct {
	City        string  `json:"city"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

type shodanDomainResponse struct {
	Data []shodanDomainRecord `json:"data"`
}

type shodanDomainRecord struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Value     string `json:"value"`
}

type shodanTransport uint8

type shodanRawBannerCore struct {
	Vulns     map[string]shodanVuln `json:"vulns"`
	CPE       []string              `json:"cpe"`
	CPE23     []string              `json:"cpe23"`
	Hash      int64                 `json:"hash"`
	Port      int                   `json:"port"`
	Transport shodanTransport       `json:"transport"`
}

type shodanRawBannerService struct {
	Product *string `json:"product"`
	Version *string `json:"version"`
	Info    *string `json:"info"`
	Shodan  *struct {
		Module string `json:"module"`
	} `json:"_shodan"`
}

type shodanRawBannerCert struct {
	Expires    string               `json:"expires"`
	Issuer     *shodanCertIssuer    `json:"issuer"`
	Extensions []shodanSSLExtension `json:"extensions"`
}

type shodanRawBannerSSL struct {
	Cert     *shodanRawBannerCert `json:"cert"`
	Versions []string             `json:"versions"`
}

type shodanRawBannerDetails struct {
	HTTP     *shodanHTTPBanner     `json:"http"`
	SSL      *shodanRawBannerSSL   `json:"ssl"`
	Location *shodanBannerLocation `json:"location"`
}

const (
	shodanTransportUnknown shodanTransport = iota
	shodanTransportTCP
	shodanTransportUDP
)

func (b *shodanIPBanner) UnmarshalJSON(data []byte) error {
	core, err := parseShodanRawBannerCore(data)
	if err != nil {
		return err
	}

	service, err := parseShodanRawBannerService(data)
	if err != nil {
		return err
	}

	details, err := parseShodanRawBannerDetails(data)
	if err != nil {
		return err
	}

	b.applyShodanRawBannerCore(core)
	b.ServiceValue = joinBannerServiceValue(service.Product, service.Version, service.Info)
	b.ModuleLabel = shodanRawBannerModule(service)
	b.Details = mapShodanRawBannerDetails(details)

	return nil
}

func parseShodanRawBannerCore(data []byte) (shodanRawBannerCore, error) {
	var core shodanRawBannerCore
	if err := json.Unmarshal(data, &core); err != nil {
		return shodanRawBannerCore{}, fmt.Errorf("unmarshal banner core: %w", err)
	}

	return core, nil
}

func parseShodanRawBannerService(data []byte) (shodanRawBannerService, error) {
	var service shodanRawBannerService
	if err := json.Unmarshal(data, &service); err != nil {
		return shodanRawBannerService{}, fmt.Errorf("unmarshal banner service: %w", err)
	}

	return service, nil
}

func parseShodanRawBannerDetails(data []byte) (shodanRawBannerDetails, error) {
	var details shodanRawBannerDetails
	if err := json.Unmarshal(data, &details); err != nil {
		return shodanRawBannerDetails{}, fmt.Errorf("unmarshal banner details: %w", err)
	}

	return details, nil
}

func (b *shodanIPBanner) applyShodanRawBannerCore(core shodanRawBannerCore) {
	if core.Vulns != nil || len(core.CPE) > 0 || len(core.CPE23) > 0 {
		b.Artifacts = &shodanIPBannerArtifacts{
			Vulns: core.Vulns,
			CPE:   core.CPE,
			CPE23: core.CPE23,
		}
	}
	b.Hash = core.Hash
	b.Port = core.Port
	b.Transport = core.Transport
}

func mapShodanRawBannerDetails(details shodanRawBannerDetails) *shodanIPBannerDetails {
	mapped := shodanIPBannerDetails{
		HTTP:     details.HTTP,
		Location: details.Location,
	}
	if details.SSL != nil {
		mapped.SSL = mapShodanRawBannerSSL(details.SSL)
	}
	if mapped.HTTP == nil && mapped.SSL == nil && mapped.Location == nil {
		return nil
	}

	return &mapped
}

func mapShodanRawBannerSSL(raw *shodanRawBannerSSL) *shodanSSLBanner {
	mapped := shodanSSLBanner{
		TLSVersionsValue: formatShodanTLSVersions(raw.Versions),
	}
	if raw.Cert != nil {
		mapped.CertIssuerValue = formatShodanCertIssuer(raw.Cert.Issuer)
		mapped.CertNotAfterValue = formatShodanCertTime(raw.Cert.Expires)
		mapped.Extensions = raw.Cert.Extensions
	}
	if mapped.CertIssuerValue == "" && mapped.CertNotAfterValue == "" && mapped.TLSVersionsValue == "" && len(mapped.Extensions) == 0 {
		return nil
	}

	return &mapped
}

func shodanRawBannerModule(service shodanRawBannerService) string {
	if service.Shodan == nil {
		return ""
	}

	return service.Shodan.Module
}

func joinBannerServiceValue(product, version, info *string) *string {
	serviceParts := make([]string, 0, 3)
	appendBannerServiceString(&serviceParts, product)
	appendBannerServiceString(&serviceParts, version)
	appendBannerServiceString(&serviceParts, info)
	if len(serviceParts) == 0 {
		return nil
	}

	value := strings.Join(serviceParts, " ")
	return &value
}

func appendBannerServiceString(serviceParts *[]string, value *string) {
	if value != nil && *value != "" {
		*serviceParts = append(*serviceParts, *value)
	}
}

func (t *shodanTransport) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("unmarshal transport: %w", err)
	}

	switch value {
	case "tcp":
		*t = shodanTransportTCP
	case "udp":
		*t = shodanTransportUDP
	default:
		*t = shodanTransportUnknown
	}

	return nil
}

func formatShodanTransport(transport shodanTransport) string {
	switch transport {
	case shodanTransportTCP:
		return "tcp"
	case shodanTransportUDP:
		return "udp"
	default:
		return ""
	}
}
