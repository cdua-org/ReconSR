package ip2location

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ip2location/ip2location-go/v9"
	"github.com/ip2location/ip2proxy-go/v4"
)

var (
	geoOnce  sync.Once
	geoDB    *ip2location.DB
	errGeoDB error

	asnOnce  sync.Once
	asnDB    *ip2location.DB
	errAsnDB error

	proxyOnce  sync.Once
	proxyDB    *ip2proxy.DB
	errProxyDB error
)

var defaultGeoQuery = func(dbPath, ip string) (*ip2location.IP2Locationrecord, error) {
	geoOnce.Do(func() {
		geoDB, errGeoDB = ip2location.OpenDB(dbPath)
	})
	if errGeoDB != nil {
		return nil, fmt.Errorf("open geo db: %w", errGeoDB)
	}
	res, err := geoDB.Get_all(ip)
	if err != nil {
		return nil, fmt.Errorf("get geo db: %w", err)
	}
	return &res, nil
}

var defaultASNQuery = func(dbPath, ip string) (*ip2location.IP2Locationrecord, error) {
	asnOnce.Do(func() {
		asnDB, errAsnDB = ip2location.OpenDB(dbPath)
	})
	if errAsnDB != nil {
		return nil, fmt.Errorf("open asn db: %w", errAsnDB)
	}
	res, err := asnDB.Get_all(ip)
	if err != nil {
		return nil, fmt.Errorf("get asn db: %w", err)
	}
	return &res, nil
}

var defaultProxyQuery = func(dbPath, ip string) (*ip2proxy.IP2ProxyRecord, error) {
	proxyOnce.Do(func() {
		proxyDB, errProxyDB = ip2proxy.OpenDB(dbPath)
	})
	if errProxyDB != nil {
		return nil, fmt.Errorf("open proxy db: %w", errProxyDB)
	}
	res, err := proxyDB.GetAll(ip)
	if err != nil {
		return nil, fmt.Errorf("get proxy db: %w", err)
	}
	return &res, nil
}

var (
	geoQueryFunc   = defaultGeoQuery
	asnQueryFunc   = defaultASNQuery
	proxyQueryFunc = defaultProxyQuery
)

var dataDir = filepath.Join("data", "ip2location")

var checkFileExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func resolveDBPath(premium, lite string) string {
	premiumPath := filepath.Join(dataDir, premium)
	if checkFileExists(premiumPath) {
		return premiumPath
	}

	litePath := filepath.Join(dataDir, lite)
	if checkFileExists(litePath) {
		return litePath
	}

	return ""
}

func isUnavailable(val string) bool {
	if val == "" || val == "-" {
		return true
	}
	if strings.HasPrefix(val, "This parameter is unavailable") {
		return true
	}
	return false
}

func isUnavailableFloat(val float32) bool {
	return val == 0.0
}

var usageTypeMap = map[string]string{
	"COM":     "Commercial",
	"ORG":     "Organization",
	"GOV":     "Government",
	"MIL":     "Military",
	"EDU":     "University/College/School",
	"LIB":     "Library",
	"CDN":     "Content Delivery Network",
	"ISP":     "Fixed Line ISP",
	"MOB":     "Mobile ISP",
	"ISP/MOB": "Fixed Line or Mobile ISP",
	"DCH":     "Data Center/Web Hosting/Transit",
	"SES":     "Search Engine Spider",
	"AIC":     "AI Crawlers",
	"SES/AIC": "Search Engine Spider/AI Crawlers",
	"RSV":     "Reserved",
}

// ParseUsageType expands IP2Location abbreviations into human-readable strings.
func ParseUsageType(val string) string {
	if isUnavailable(val) {
		return val
	}

	if mapped, ok := usageTypeMap[val]; ok {
		return mapped
	}

	parts := strings.Split(val, "/")
	var expanded []string
	for _, p := range parts {
		if mapped, ok := usageTypeMap[p]; ok {
			expanded = append(expanded, mapped)
		} else {
			expanded = append(expanded, p)
		}
	}
	return strings.Join(expanded, " / ")
}
