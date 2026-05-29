package leakix

import (
	"time"
)

// LeakWrapper represents the outer object wrapping leak events in LeakIX API responses.
type LeakWrapper struct {
	Summary        string         `json:"Summary"`
	IP             string         `json:"Ip"`
	ResourceID     string         `json:"resource_id"`
	Events         []ServiceEvent `json:"events"`
	OpenPorts      []string       `json:"open_ports"`
	LeakCount      int            `json:"leak_count"`
	LeakEventCount int            `json:"leak_event_count"`
}

// Response represents the top-level response from LeakIX host/domain API containing both service discoveries and leak findings.
type Response struct {
	Services []ServiceEvent `json:"Services"`
	Leaks    []LeakWrapper  `json:"Leaks"`
}

// ServiceEvent represents a single L9Event from LeakIX covering both service and leak event types.
type ServiceEvent struct {
	Time             time.Time    `json:"time"`
	HTTP             *HTTPInfo    `json:"http"`
	SSL              *SSLInfo     `json:"ssl"`
	SSH              *SSHInfo     `json:"ssh"`
	Service          *ServiceInfo `json:"service"`
	Network          *NetworkInfo `json:"network"`
	GeoIP            *GeoIPInfo   `json:"geoip"`
	Leak             *LeakInfo    `json:"leak"`
	EventType        string       `json:"event_type"`
	EventSource      string       `json:"event_source"`
	EventFingerprint string       `json:"event_fingerprint"`
	IP               string       `json:"ip"`
	Host             string       `json:"host"`
	Reverse          string       `json:"reverse"`
	Port             string       `json:"port"`
	Protocol         string       `json:"protocol"`
	MAC              string       `json:"mac"`
	Vendor           string       `json:"vendor"`
	Summary          string       `json:"summary"`
	Transport        []string     `json:"transport"`
	Tags             []string     `json:"tags"`
}

// HTTPInfo contains HTTP-specific properties from the L9HttpEvent schema.
type HTTPInfo struct {
	Header      map[string]string `json:"header"`
	Root        string            `json:"root"`
	URL         string            `json:"url"`
	Title       string            `json:"title"`
	FaviconHash string            `json:"favicon_hash"`
	Status      int               `json:"status"`
	Length      int64             `json:"length"`
}

// SSLInfo contains TLS/SSL specific properties from the L9SSLEvent schema.
type SSLInfo struct {
	Certificate *SSLCertificate `json:"certificate"`
	JARM        string          `json:"jarm"`
	CypherSuite string          `json:"cypher_suite"`
	Version     string          `json:"version"`
	Detected    bool            `json:"detected"`
	Enabled     bool            `json:"enabled"`
}

// SSLCertificate contains detailed certificate data from the L9SSLCertificate schema.
type SSLCertificate struct {
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	CN          string    `json:"cn"`
	Fingerprint string    `json:"fingerprint"`
	IssuerName  string    `json:"issuer_name"`
	KeyAlgo     string    `json:"key_algo"`
	Domain      []string  `json:"domain"`
	KeySize     int       `json:"key_size"`
	Valid       bool      `json:"valid"`
}

// ServiceInfo contains details about the running service.
type ServiceInfo struct {
	Software    *SoftwareInfo    `json:"software"`
	Credentials *CredentialsInfo `json:"credentials"`
}

// CredentialsInfo contains leaked credentials from the ServiceCredentials schema.
type CredentialsInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Key      string `json:"key"`
	Raw      []byte `json:"raw"`
	NoAuth   bool   `json:"noauth"`
}

// SoftwareInfo represents the identified software from the ServiceSoftware schema.
type SoftwareInfo struct {
	Name        string           `json:"name"`
	Version     string           `json:"version"`
	OS          string           `json:"os"`
	Fingerprint string           `json:"fingerprint"`
	Modules     []SoftwareModule `json:"modules"`
}

// SoftwareModule represents a single software component detected alongside the main service.
type SoftwareModule struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Fingerprint string `json:"fingerprint"`
}

// NetworkInfo contains ASN and organizational data.
type NetworkInfo struct {
	OrganizationName string `json:"organization_name"`
	Network          string `json:"network"`
	ASN              int    `json:"asn"`
}

// GeoIPInfo contains geographical location data.
type GeoIPInfo struct {
	Location       *GeoLocation `json:"location"`
	ContinentName  string       `json:"continent_name"`
	CountryName    string       `json:"country_name"`
	CountryISOCode string       `json:"country_iso_code"`
	CityName       string       `json:"city_name"`
	RegionName     string       `json:"region_name"`
}

// GeoLocation contains latitude and longitude.
type GeoLocation struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// LeakInfo contains details about a discovered leak from the L9LeakEvent schema.
type LeakInfo struct {
	Dataset  *DatasetInfo `json:"dataset"`
	Stage    string       `json:"stage"`
	Type     string       `json:"type"`
	Severity string       `json:"severity"`
}

// DatasetInfo provides statistics about the leaked data from the L9Dataset schema.
type DatasetInfo struct {
	RansomNotes []string `json:"ransom_notes"`
	Rows        int64    `json:"rows"`
	Files       int64    `json:"files"`
	Size        int64    `json:"size"`
	Collections int64    `json:"collections"`
	Infected    bool     `json:"infected"`
}

// SubdomainResponse represents a single subdomain finding from LeakIX.
type SubdomainResponse struct {
	LastSeen    string `json:"last_seen"`
	Subdomain   string `json:"subdomain"`
	DistinctIPs int    `json:"distinct_ips"`
}

// SSHInfo contains SSH specific properties from the L9SSHEvent schema.
type SSHInfo struct {
	Fingerprint string `json:"fingerprint"`
	Banner      string `json:"banner"`
	Motd        string `json:"motd"`
	Version     int    `json:"version"`
}

type eventGroup struct {
	sslDomains  map[string]struct{}
	latest      *ServiceEvent
	credentials []credentialRecord
	leaks       []leakRecord
	summaries   []summaryRecord
}

type credentialRecord struct {
	creds *CredentialsInfo
	seen  time.Time
}

type leakRecord struct {
	leak *LeakInfo
	seen time.Time
}

type groupKey struct {
	ip, port, protocol, host string
}

type summaryRecord struct {
	text   string
	source string
}
