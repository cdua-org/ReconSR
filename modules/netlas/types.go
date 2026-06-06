package netlas

import (
	"encoding/json"
)

type netlasResponse struct {
	DNS                 *netlasDNS         `json:"dns"`
	Whois               *netlasWhoisDomain `json:"whois"`
	Geo                 *netlasGeo         `json:"geo"`
	Privacy             *netlasPrivacy     `json:"privacy"`
	Type                string             `json:"type"`
	Domain              string             `json:"domain"`
	IP                  string             `json:"ip"`
	Organization        string             `json:"organization"`
	Ports               []netlasPort       `json:"ports"`
	Software            []netlasSoftware   `json:"software"`
	IoC                 []netlasIoC        `json:"ioc"`
	PTR                 []string           `json:"ptr"`
	Domains             []string           `json:"domains"`
	RelatedDomains      []string           `json:"related_domains"`
	DomainsCount        int                `json:"domains_count"`
	RelatedDomainsCount int                `json:"related_domains_count"`
}

type netlasPort struct {
	Protocol string `json:"protocol"`
	Prot4    string `json:"prot4"`
	Prot7    string `json:"prot7"`
	Port     int    `json:"port"`
}

type netlasSoftware struct {
	URI  string              `json:"uri"`
	CVE  []netlasCVE         `json:"cve"`
	Tags []netlasSoftwareTag `json:"tag"`
}

type netlasCVE struct {
	Severity              any      `json:"severity"`
	BaseScore             any      `json:"base_score"`
	ConfidentialityImpact string   `json:"confidentiality_impact"`
	IntegrityImpact       string   `json:"integrity_impact"`
	AttackVector          string   `json:"attack_vector"`
	AttackComplexity      string   `json:"attack_complexity"`
	PrivilegesRequired    string   `json:"privileges_required"`
	UserInteraction       string   `json:"user_interaction"`
	Name                  string   `json:"name"`
	MatchProduct          string   `json:"match_product"`
	AvailabilityImpact    string   `json:"availability_impact"`
	Published             string   `json:"published"`
	Description           string   `json:"description"`
	MatchType             string   `json:"match_type"`
	ExploitLinks          []string `json:"exploit_links"`
	HasExploit            bool     `json:"has_exploit"`
}

type netlasSoftwareTag struct {
	Name        string   `json:"name"`
	FullName    string   `json:"fullname"`
	Description string   `json:"description"`
	Version     string   `json:"-"`
	CPE         []string `json:"cpe"`
	Category    []string `json:"category"`
}

func (t *netlasSoftwareTag) UnmarshalJSON(data []byte) error {
	type Alias netlasSoftwareTag
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(t),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var raw map[string]json.RawMessage
	err := json.Unmarshal(data, &raw)
	if err == nil && t.Name != "" {
		if b, ok := raw[t.Name]; ok {
			var versionData struct {
				Version string `json:"version"`
			}
			if err := json.Unmarshal(b, &versionData); err == nil {
				t.Version = versionData.Version
			}
		}
	}

	return nil
}

type netlasIoC struct {
	Score     *netlasScore `json:"score"`
	FP        *netlasFP    `json:"fp"`
	IP        string       `json:"ip"`
	Domain    string       `json:"domain"`
	URL       string       `json:"url"`
	ISP       string       `json:"isp"`
	Timestamp string       `json:"@timestamp"`
	FirstSeen string       `json:"fseen"`
	LastSeen  string       `json:"lseen"`
	Tags      []string     `json:"tags"`
	Threat    []string     `json:"threat"`
	Ports     []int        `json:"ports"`
	ASN       int          `json:"asn"`
}

type netlasScore struct {
	Total     float64 `json:"total"`
	Src       float64 `json:"src"`
	Tags      float64 `json:"tags"`
	Frequency float64 `json:"frequency"`
}

type netlasFP struct {
	Alarm string `json:"alarm"`
	Descr string `json:"descr"`
}

type netlasGeo struct {
	Location          *netlasLocation `json:"location"`
	Continent         string          `json:"continent"`
	Country           string          `json:"country"`
	City              string          `json:"city"`
	TZ                string          `json:"tz"`
	RegisteredCountry string          `json:"registered_country"`
	Subdivisions      []string        `json:"subdivisions"`
	Accuracy          int             `json:"accuracy"`
}

type netlasLocation struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type netlasPrivacy struct {
	IsVPN   bool `json:"is_vpn"`
	IsProxy bool `json:"is_proxy"`
	IsTor   bool `json:"is_tor"`
}

type netlasWhoisDomain struct {
	Registrar      *netlasWhoisContact `json:"registrar"`
	Administrative *netlasWhoisContact `json:"administrative"`
	Technical      *netlasWhoisContact `json:"technical"`
	Registrant     *netlasWhoisContact `json:"registrant"`
	Server         string              `json:"server"`
	Status         []string            `json:"status"`
	CreatedDate    string              `json:"created_date"`
	UpdatedDate    string              `json:"updated_date"`
	ExpirationDate string              `json:"expiration_date"`
	NameServers    []string            `json:"name_servers"`
}

type netlasWhoisContact struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Fax          string `json:"fax"`
	Street       string `json:"street"`
	City         string `json:"city"`
	Province     string `json:"province"`
	PostalCode   string `json:"postal_code"`
	Country      string `json:"country"`
}

type netlasDNS struct {
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME []string `json:"cname"`
	MX    []string `json:"mx"`
	NS    []string `json:"ns"`
	TXT   []string `json:"txt"`
}

type netlasWhoisIP struct {
	Net         *netlasWhoisIPNet  `json:"net"`
	ASN         *netlasWhoisASN    `json:"asn"`
	RelatedNets []netlasWhoisIPNet `json:"related_nets"`
}

type netlasWhoisIPNet struct {
	Contacts     *netlasWhoisIPContacts `json:"contacts"`
	Name         string                 `json:"name"`
	Organization string                 `json:"organization"`
	Handle       string                 `json:"handle"`
	Address      string                 `json:"address"`
	Description  string                 `json:"description"`
	Country      string                 `json:"country"`
	City         string                 `json:"city"`
	State        string                 `json:"state"`
	PostalCode   string                 `json:"postal_code"`
	Created      string                 `json:"created"`
	Updated      string                 `json:"updated"`
	CIDR         []string               `json:"cidr"`
}

type netlasWhoisIPContacts struct {
	Emails  []string `json:"emails"`
	Persons []string `json:"persons"`
	Phones  []string `json:"phones"`
}

type netlasWhoisASN struct {
	Name     string   `json:"name"`
	Country  string   `json:"country"`
	CIDR     string   `json:"cidr"`
	Registry string   `json:"registry"`
	Updated  string   `json:"updated"`
	Number   []string `json:"number"`
}

func (r *netlasResponse) UnmarshalJSON(data []byte) error {
	type Alias netlasResponse
	aux := &struct {
		*Alias
		DNS      json.RawMessage `json:"dns"`
		Whois    json.RawMessage `json:"whois"`
		Geo      json.RawMessage `json:"geo"`
		Privacy  json.RawMessage `json:"privacy"`
		Ports    json.RawMessage `json:"ports"`
		Software json.RawMessage `json:"software"`
		IoC      json.RawMessage `json:"ioc"`
		PTR      json.RawMessage `json:"ptr"`
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	unmarshalIfObject := func(raw json.RawMessage, target any) error {
		if len(raw) > 0 && raw[0] == '{' {
			return json.Unmarshal(raw, target)
		}
		return nil
	}
	unmarshalIfArray := func(raw json.RawMessage, target any) error {
		if len(raw) > 0 && raw[0] == '[' {
			return json.Unmarshal(raw, target)
		}
		return nil
	}

	for _, err := range []error{
		unmarshalIfObject(aux.DNS, &r.DNS),
		unmarshalIfObject(aux.Geo, &r.Geo),
		unmarshalIfObject(aux.Privacy, &r.Privacy),
		unmarshalIfArray(aux.Ports, &r.Ports),
		unmarshalIfArray(aux.Software, &r.Software),
		unmarshalIfArray(aux.IoC, &r.IoC),
		unmarshalIfArray(aux.PTR, &r.PTR),
	} {
		if err != nil {
			return err
		}
	}

	if len(aux.Whois) > 0 && aux.Whois[0] == '{' && r.Type == "domain" {
		var w netlasWhoisDomain
		if err := json.Unmarshal(aux.Whois, &w); err != nil {
			return err
		}
		r.Whois = &w
	}

	return nil
}

type netlasIPResponse struct {
	Whois *netlasWhoisIP `json:"whois"`
	netlasResponse
}

func (r *netlasIPResponse) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &r.netlasResponse); err != nil {
		return err
	}

	var w struct {
		Whois json.RawMessage `json:"whois"`
	}
	if err := json.Unmarshal(data, &w); err == nil {
		if len(w.Whois) > 0 && w.Whois[0] == '{' {
			var whoisIP netlasWhoisIP
			if err := json.Unmarshal(w.Whois, &whoisIP); err == nil {
				r.Whois = &whoisIP
			}
		}
	}
	return nil
}
