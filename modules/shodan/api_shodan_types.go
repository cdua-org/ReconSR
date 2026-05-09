package shodan

import (
	"encoding/json"
	"fmt"
	"sort"
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
	Heartbleed   string                   `json:"-"`
	Timestamp    string                   `json:"-"`
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
	CertFingerprintValues []string             `json:"-"`
	CertIssuerValue       string               `json:"-"`
	CertNotAfterValue     string               `json:"-"`
	JARMValue             string               `json:"-"`
	TLSVersionsValue      string               `json:"-"`
	Extensions            []shodanSSLExtension `json:"-"`
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
	Summary     string  `json:"summary"`
	CvssVersion float64 `json:"cvss_version"`
	Cvss        float64 `json:"cvss"`
	EPSS        float64 `json:"epss"`
	RankingEPSS float64 `json:"ranking_epss"`
	Verified    bool    `json:"verified"`
}

type shodanBannerLocation struct {
	City        string  `json:"city"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

type shodanDomainResponse struct {
	Tags []string             `json:"tags"`
	Data []shodanDomainRecord `json:"data"`
}

type shodanDomainRecord struct {
	Options   *shodanDomainRecordOptions `json:"options,omitempty"`
	Subdomain string                     `json:"subdomain"`
	Type      string                     `json:"type"`
	Value     string                     `json:"value"`
	LastSeen  string                     `json:"last_seen"`
}

type shodanDomainRecordOptions struct {
	Hostmaster string `json:"hostmaster"`
	Serial     uint64 `json:"serial"`
	Refresh    uint64 `json:"refresh"`
	Retry      uint64 `json:"retry"`
	Expires    uint64 `json:"expires"`
	MinTTL     uint64 `json:"minttl"`
	Priority   uint16 `json:"priority"`
}

type shodanTransport uint8

type shodanRawBannerService struct {
	Product *string `json:"product"`
	Version *string `json:"version"`
	Info    *string `json:"info"`
	Shodan  *struct {
		Module string `json:"module"`
	} `json:"_shodan"`
}

type shodanRawBannerCert struct {
	Expires     string                          `json:"expires"`
	Issuer      *shodanCertIssuer               `json:"issuer"`
	Fingerprint *shodanRawBannerCertFingerprint `json:"fingerprint"`
	Extensions  []shodanSSLExtension            `json:"extensions"`
}

type shodanRawBannerSSL struct {
	Cert     *shodanRawBannerCert `json:"cert"`
	JARM     string               `json:"jarm"`
	Versions []string             `json:"versions"`
}

type shodanRawBannerDetails struct {
	HTTP     *shodanHTTPBanner     `json:"http"`
	SSL      *shodanRawBannerSSL   `json:"ssl"`
	Location *shodanBannerLocation `json:"location"`
}

type shodanRawBannerOpts struct {
	Heartbleed string `json:"heartbleed"`
}

type shodanRawBannerCertFingerprint map[string]string

const (
	shodanTransportUnknown shodanTransport = iota
	shodanTransportTCP
	shodanTransportUDP
)

func (b *shodanIPBanner) UnmarshalJSON(data []byte) error {
	artifacts, hash, port, transport, err := parseShodanRawBannerCore(data)
	if err != nil {
		return err
	}

	heartbleed, timestamp, err := parseShodanRawBannerMeta(data)
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

	b.Artifacts = artifacts
	b.Hash = hash
	b.Port = port
	b.Transport = transport
	b.Heartbleed = heartbleed
	b.Timestamp = timestamp
	b.ServiceValue = joinBannerServiceValue(service.Product, service.Version, service.Info)
	b.ModuleLabel = shodanRawBannerModule(service)
	b.Details = mapShodanRawBannerDetails(details)

	return nil
}

func parseShodanRawBannerCore(data []byte) (artifacts *shodanIPBannerArtifacts, hash int64, port int, transport shodanTransport, err error) {
	fields, err := decodeShodanRawBannerObject(data)
	if err != nil {
		return nil, 0, 0, shodanTransportUnknown, fmt.Errorf("unmarshal banner core: %w", err)
	}

	var cpe []string
	if err = unmarshalShodanBannerField(fields, "cpe", &cpe); err != nil {
		return nil, 0, 0, shodanTransportUnknown, fmt.Errorf("unmarshal banner core: %w", err)
	}

	var cpe23 []string
	if err = unmarshalShodanBannerField(fields, "cpe23", &cpe23); err != nil {
		return nil, 0, 0, shodanTransportUnknown, fmt.Errorf("unmarshal banner core: %w", err)
	}

	var vulns map[string]shodanVuln
	if err = unmarshalShodanBannerField(fields, "vulns", &vulns); err != nil {
		return nil, 0, 0, shodanTransportUnknown, fmt.Errorf("unmarshal banner core: %w", err)
	}

	if err = unmarshalShodanBannerField(fields, "hash", &hash); err != nil {
		return nil, 0, 0, shodanTransportUnknown, fmt.Errorf("unmarshal banner core: %w", err)
	}

	if err = unmarshalShodanBannerField(fields, "port", &port); err != nil {
		return nil, 0, 0, shodanTransportUnknown, fmt.Errorf("unmarshal banner core: %w", err)
	}

	transport = shodanTransportUnknown
	if err = unmarshalShodanBannerField(fields, "transport", &transport); err != nil {
		return nil, 0, 0, shodanTransportUnknown, fmt.Errorf("unmarshal banner core: %w", err)
	}

	if vulns != nil || len(cpe) > 0 || len(cpe23) > 0 {
		artifacts = &shodanIPBannerArtifacts{
			Vulns: vulns,
			CPE:   cpe,
			CPE23: cpe23,
		}
	}

	return artifacts, hash, port, transport, nil
}

func parseShodanRawBannerMeta(data []byte) (heartbleed, timestamp string, err error) {
	fields, err := decodeShodanRawBannerObject(data)
	if err != nil {
		return "", "", fmt.Errorf("unmarshal banner meta: %w", err)
	}

	if err = unmarshalShodanBannerField(fields, "timestamp", &timestamp); err != nil {
		return "", "", fmt.Errorf("unmarshal banner meta: %w", err)
	}

	var opts shodanRawBannerOpts
	if err = unmarshalShodanBannerField(fields, "opts", &opts); err != nil {
		return "", "", fmt.Errorf("unmarshal banner meta: %w", err)
	}
	if opts != (shodanRawBannerOpts{}) {
		heartbleed = formatShodanHeartbleed(&opts)
	}

	return heartbleed, strings.TrimSpace(timestamp), nil
}

func decodeShodanRawBannerObject(data []byte) (fields map[string]json.RawMessage, err error) {
	fields = make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}

	return fields, nil
}

func unmarshalShodanBannerField(fields map[string]json.RawMessage, key string, target any) error {
	rawValue, ok := fields[key]
	if !ok || string(rawValue) == "null" {
		return nil
	}

	if err := json.Unmarshal(rawValue, target); err != nil {
		return fmt.Errorf("field %s: %w", key, err)
	}

	return nil
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
		JARMValue:        strings.TrimSpace(raw.JARM),
		TLSVersionsValue: formatShodanTLSVersions(raw.Versions),
	}
	if raw.Cert != nil {
		mapped.CertIssuerValue = formatShodanCertIssuer(raw.Cert.Issuer)
		mapped.CertNotAfterValue = formatShodanCertTime(raw.Cert.Expires)
		mapped.CertFingerprintValues = formatShodanCertFingerprints(raw.Cert.Fingerprint)
		mapped.Extensions = raw.Cert.Extensions
	}
	if len(mapped.CertFingerprintValues) == 0 && mapped.CertIssuerValue == "" && mapped.CertNotAfterValue == "" && mapped.JARMValue == "" && mapped.TLSVersionsValue == "" && len(mapped.Extensions) == 0 {
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

func formatShodanCertFingerprints(fingerprint *shodanRawBannerCertFingerprint) []string {
	if fingerprint == nil || len(*fingerprint) == 0 {
		return nil
	}

	normalized := make(map[string]string, len(*fingerprint))
	for algorithm, value := range *fingerprint {
		algorithm = strings.ToLower(strings.TrimSpace(algorithm))
		value = strings.TrimSpace(value)
		if algorithm == "" || value == "" {
			continue
		}
		normalized[algorithm] = value
	}
	if len(normalized) == 0 {
		return nil
	}

	algorithms := make([]string, 0, len(normalized))
	for algorithm := range normalized {
		algorithms = append(algorithms, algorithm)
	}
	sort.Strings(algorithms)
	formatted := make([]string, 0, len(algorithms))
	seen := make(map[string]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		value := normalized[algorithm]
		entry := algorithm + ":" + value
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		formatted = append(formatted, entry)
	}
	if len(formatted) == 0 {
		return nil
	}

	return formatted
}

func formatShodanHeartbleed(opts *shodanRawBannerOpts) string {
	if opts == nil {
		return ""
	}

	value := strings.TrimSpace(opts.Heartbleed)
	if value == "" {
		return ""
	}

	status := value
	if _, parsedStatus, ok := strings.Cut(value, " - "); ok {
		parsedStatus = strings.TrimSpace(parsedStatus)
		if parsedStatus != "" {
			status = parsedStatus
		}
	}

	upperStatus := strings.ToUpper(status)
	if !strings.Contains(upperStatus, "VULNERABLE") || strings.Contains(upperStatus, "NOT VULNERABLE") || strings.Contains(upperStatus, "SAFE") {
		return ""
	}

	return status
}
