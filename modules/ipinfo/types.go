package ipinfo

type ipinfoResponse struct {
	Geo *struct {
		City        string  `json:"city"`
		Region      string  `json:"region"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		PostalCode  string  `json:"postal_code"`
		Timezone    string  `json:"timezone"`
		LastChanged string  `json:"last_changed"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
	} `json:"geo"`
	As *struct {
		ASN         string `json:"asn"`
		Name        string `json:"name"`
		Domain      string `json:"domain"`
		Type        string `json:"type"`
		LastChanged string `json:"last_changed"`
	} `json:"as"`
	Mobile *struct {
		Name string `json:"name"`
		Mcc  string `json:"mcc"`
		Mnc  string `json:"mnc"`
	} `json:"mobile"`
	Anonymous *struct {
		Name       string `json:"name"`
		LastSeen   string `json:"last_seen"`
		IsProxy    bool   `json:"is_proxy"`
		IsRelay    bool   `json:"is_relay"`
		IsTor      bool   `json:"is_tor"`
		IsVpn      bool   `json:"is_vpn"`
		IsResProxy bool   `json:"is_res_proxy"`
	} `json:"anonymous"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	Asn         string `json:"asn"`
	AsName      string `json:"as_name"`
	AsDomain    string `json:"as_domain"`
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	City        string `json:"city"`
	Region      string `json:"region"`
	Loc         string `json:"loc"`
	Postal      string `json:"postal"`
	Timezone    string `json:"timezone"`
	IsAnonymous bool   `json:"is_anonymous"`
	IsAnycast   bool   `json:"is_anycast"`
	IsHosting   bool   `json:"is_hosting"`
	IsMobile    bool   `json:"is_mobile"`
	IsSatellite bool   `json:"is_satellite"`
}
