package maxmind

import (
	"strings"

	"github.com/oschwald/geoip2-golang"
)

func writeRaw(b *strings.Builder, key, val string) {
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(val)
}

// ParsedGeo aggregates spatial data to facilitate consistent rendering across diverse module outputs.
type ParsedGeo struct {
	CityName              string
	RegionName            string
	CountryName           string
	CountryIso            string
	TimeZone              string
	PostalCode            string
	ContinentName         string
	ContinentCode         string
	RegisteredCountryName string
	RegisteredCountryIso  string
	Latitude              float64
	Longitude             float64
	AccuracyRadius        uint16
}

// ParseGeo normalizes heterogeneous MaxMind City and Enterprise structures into a unified format for downstream presentation.
func ParseGeo(record any) *ParsedGeo {
	var cityNames, countryNames, continentNames, regCountryNames map[string]string
	var subNames map[string]string
	var iso, tz, postal, continentCode, regCountryIso string
	var lat, lon float64
	var accuracyRadius uint16

	switch v := record.(type) {
	case *geoip2.Enterprise:
		cityNames = v.City.Names
		countryNames = v.Country.Names
		continentNames = v.Continent.Names
		regCountryNames = v.RegisteredCountry.Names
		iso = v.Country.IsoCode
		continentCode = v.Continent.Code
		regCountryIso = v.RegisteredCountry.IsoCode
		lat = v.Location.Latitude
		lon = v.Location.Longitude
		accuracyRadius = v.Location.AccuracyRadius
		tz = v.Location.TimeZone
		postal = v.Postal.Code
		if len(v.Subdivisions) > 0 {
			subNames = v.Subdivisions[0].Names
		}
	case *geoip2.City:
		cityNames = v.City.Names
		countryNames = v.Country.Names
		continentNames = v.Continent.Names
		regCountryNames = v.RegisteredCountry.Names
		iso = v.Country.IsoCode
		continentCode = v.Continent.Code
		regCountryIso = v.RegisteredCountry.IsoCode
		lat = v.Location.Latitude
		lon = v.Location.Longitude
		accuracyRadius = v.Location.AccuracyRadius
		tz = v.Location.TimeZone
		postal = v.Postal.Code
		if len(v.Subdivisions) > 0 {
			subNames = v.Subdivisions[0].Names
		}
	default:
		return nil
	}

	var geo ParsedGeo
	var hasData bool
	if name, ok := cityNames["en"]; ok {
		geo.CityName = name
		hasData = true
	}
	if name, ok := subNames["en"]; ok {
		geo.RegionName = name
		hasData = true
	}
	if name, ok := countryNames["en"]; ok {
		geo.CountryName = name
		hasData = true
	}
	if name, ok := continentNames["en"]; ok {
		geo.ContinentName = name
		hasData = true
	}
	if name, ok := regCountryNames["en"]; ok {
		geo.RegisteredCountryName = name
		hasData = true
	}
	geo.CountryIso = iso
	geo.ContinentCode = continentCode
	geo.RegisteredCountryIso = regCountryIso
	geo.Latitude = lat
	geo.Longitude = lon
	geo.AccuracyRadius = accuracyRadius
	geo.TimeZone = tz
	geo.PostalCode = postal
	if geo.Latitude != 0 || geo.Longitude != 0 || geo.AccuracyRadius != 0 {
		hasData = true
	}

	if hasData {
		return &geo
	}
	return nil
}

// ParsedConfidence isolates statistical accuracy metrics to allow consumers to filter or weight results dynamically.
type ParsedConfidence struct {
	CityConf    uint16
	CountryConf uint16
	RegionConf  uint16
	PostalConf  uint16
}

// ParseConfidence abstracts the proprietary Enterprise statistical structure for system-wide consumption.
func ParseConfidence(record any) *ParsedConfidence {
	var conf ParsedConfidence
	var hasData bool

	if v, ok := record.(*geoip2.Enterprise); ok {
		conf.CityConf = uint16(v.City.Confidence)
		conf.CountryConf = uint16(v.Country.Confidence)
		conf.PostalConf = uint16(v.Postal.Confidence)
		if len(v.Subdivisions) > 0 {
			conf.RegionConf = uint16(v.Subdivisions[0].Confidence)
		}
		if conf.CityConf > 0 || conf.CountryConf > 0 || conf.RegionConf > 0 || conf.PostalConf > 0 {
			hasData = true
		}
	}

	if hasData {
		return &conf
	}
	return nil
}

// ParsedASN encapsulates Autonomous System routing metrics to map network ownership perimeters.
type ParsedASN struct {
	ASNOrg string
	ASN    uint
}

// ParseASN homogenizes distinct ASN, ISP, and Enterprise schema variations into a standard entity representation.
func ParseASN(record any) *ParsedASN {
	var asn ParsedASN
	var hasData bool

	switch v := record.(type) {
	case *geoip2.Enterprise:
		asn.ASN = v.Traits.AutonomousSystemNumber
		asn.ASNOrg = v.Traits.AutonomousSystemOrganization
	case *geoip2.ISP:
		asn.ASN = v.AutonomousSystemNumber
		asn.ASNOrg = v.AutonomousSystemOrganization
	case *geoip2.ASN:
		asn.ASN = v.AutonomousSystemNumber
		asn.ASNOrg = v.AutonomousSystemOrganization
	}

	if asn.ASN > 0 || asn.ASNOrg != "" {
		hasData = true
	}

	if hasData {
		return &asn
	}
	return nil
}

// ParsedISP segregates commercial provider data from technical routing layers to expose organizational hierarchies.
type ParsedISP struct {
	ISP               string
	Organization      string
	MobileCountryCode string
	MobileNetworkCode string
}

// ParseISP aligns ISP and Enterprise structures to prevent duplicate parsing logic during intelligence extraction.
func ParseISP(record any) *ParsedISP {
	var isp ParsedISP
	var hasData bool

	switch v := record.(type) {
	case *geoip2.Enterprise:
		isp.ISP = v.Traits.ISP
		isp.Organization = v.Traits.Organization
		isp.MobileCountryCode = v.Traits.MobileCountryCode
		isp.MobileNetworkCode = v.Traits.MobileNetworkCode
	case *geoip2.ISP:
		isp.ISP = v.ISP
		isp.Organization = v.Organization
		isp.MobileCountryCode = v.MobileCountryCode
		isp.MobileNetworkCode = v.MobileNetworkCode
	}

	if isp.ISP != "" || isp.Organization != "" || isp.MobileCountryCode != "" {
		hasData = true
	}

	if hasData {
		return &isp
	}
	return nil
}

// ParsedTraits aggregates behavioral connection metadata to identify VPNs, corporate gateways, or proxy usage.
type ParsedTraits struct {
	Domain         string
	ConnectionType string
	UserType       string
	StaticIPScore  float64
}

// ParseTraits isolates deep connection analytics specific to the Enterprise tier for advanced threat modeling.
func ParseTraits(record any) *ParsedTraits {
	var traits ParsedTraits
	var hasData bool

	if v, ok := record.(*geoip2.Enterprise); ok {
		traits.Domain = v.Traits.Domain
		traits.ConnectionType = v.Traits.ConnectionType
		traits.UserType = v.Traits.UserType
		traits.StaticIPScore = v.Traits.StaticIPScore
	}

	if traits.Domain != "" || traits.ConnectionType != "" || traits.UserType != "" || traits.StaticIPScore > 0 {
		hasData = true
	}

	if hasData {
		return &traits
	}
	return nil
}
