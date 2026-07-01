package ip2location

import (
	"github.com/ip2location/ip2location-go/v9"
	"github.com/ip2location/ip2proxy-go/v4"
)

var mockGeoRecord = &ip2location.IP2Locationrecord{
	Country_short: "EX",
	Country_long:  "Exampleland",
	Region:        "Exampleshire",
	City:          "Exampleville",
	Latitude:      51.509865,
	Longitude:     -0.118092,
	Zipcode:       "EX1 2AB",
	Timezone:      "+00:00",
	Isp:           "Example ISP Ltd",
	Domain:        "example.net",
	Netspeed:      "DSL",
	Iddcode:       "44",
	Areacode:      "020",
	Mcc:           "234",
	Mnc:           "15",
	Mobilebrand:   "Example Telecom",
	Elevation:     15,
	Usagetype:     "ISP/MOB",
	Addresstype:   "U",
	Category:      "IAB19",
	District:      "Example District",
}

var mockGeoRecordLite = &ip2location.IP2Locationrecord{
	Country_short: "-",
	Country_long:  "This parameter is unavailable for selected data file. Please upgrade the data file.",
	Region:        "-",
	City:          "This parameter is unavailable",
	Latitude:      0.0,
	Longitude:     0.0,
	Elevation:     0.0,
}

var mockASNRecord = &ip2location.IP2Locationrecord{
	Asn:         "12345",
	As:          "Example Org",
	Asdomain:    "example.org",
	Asusagetype: "ORG",
	Ascidr:      "192.0.2.0/24",
}

var mockProxyRecord = &ip2proxy.IP2ProxyRecord{
	IsProxy:      1,
	ProxyType:    "VPN",
	Threat:       "SCANNER/SPAM",
	FraudScore:   "99",
	LastSeen:     "14",
	Provider:     "Example VPN Provider",
	CountryShort: "EX",
	CountryLong:  "Exampleland",
	Region:       "Exampleshire",
	City:         "Exampleville",
	Isp:          "Example ISP Ltd",
	Domain:       "example.net",
	UsageType:    "EDU",
	Asn:          "AS12345",
	As:           "Example Hosting",
}
