package maxmind

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

var (
	entOnce  sync.Once
	entDB    *geoip2.Reader
	errEntDB error

	cityOnce  sync.Once
	cityDB    *geoip2.Reader
	errCityDB error

	asnOnce  sync.Once
	asnDB    *geoip2.Reader
	errAsnDB error

	proxyOnce  sync.Once
	proxyDB    *maxminddb.Reader
	errProxyDB error
)

func defaultGeoQueryImpl(dbPath, ipStr string) (*geoip2.City, error) {
	cityOnce.Do(func() {
		cityDB, errCityDB = geoip2.Open(dbPath)
	})
	if errCityDB != nil {
		return nil, fmt.Errorf("open geo db: %w", errCityDB)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip: %s", ipStr)
	}

	res, err := cityDB.City(ip)
	if err != nil {
		return nil, fmt.Errorf("get city db: %w", err)
	}
	return res, nil
}

func defaultEnterpriseQueryImpl(dbPath, ipStr string) (*geoip2.Enterprise, error) {
	entOnce.Do(func() {
		entDB, errEntDB = geoip2.Open(dbPath)
	})
	if errEntDB != nil {
		return nil, fmt.Errorf("open enterprise db: %w", errEntDB)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip: %s", ipStr)
	}

	res, err := entDB.Enterprise(ip)
	if err != nil {
		return nil, fmt.Errorf("get enterprise db: %w", err)
	}
	return res, nil
}

func defaultASNQueryImpl(dbPath, ipStr string) (*geoip2.ISP, *geoip2.ASN, error) {
	asnOnce.Do(func() {
		asnDB, errAsnDB = geoip2.Open(dbPath)
	})
	if errAsnDB != nil {
		return nil, nil, fmt.Errorf("open asn db: %w", errAsnDB)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid ip: %s", ipStr)
	}

	if filepath.Base(dbPath) == "GeoIP2-ISP.mmdb" {
		res, err := asnDB.ISP(ip)
		if err != nil {
			return nil, nil, fmt.Errorf("get isp db: %w", err)
		}
		return res, nil, nil
	}

	res, err := asnDB.ASN(ip)
	if err != nil {
		return nil, nil, fmt.Errorf("get asn db: %w", err)
	}
	return nil, res, nil
}

func defaultProxyQueryImpl(dbPath, ipStr string) (*AnonymousPlusIP, error) {
	proxyOnce.Do(func() {
		proxyDB, errProxyDB = maxminddb.Open(dbPath)
	})
	if errProxyDB != nil {
		return nil, fmt.Errorf("open proxy db: %w", errProxyDB)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip: %s", ipStr)
	}

	var res AnonymousPlusIP
	err := proxyDB.Lookup(ip, &res)
	if err != nil {
		return nil, fmt.Errorf("get proxy db: %w", err)
	}
	return &res, nil
}

var (
	defaultEnterpriseQuery = defaultEnterpriseQueryImpl
	defaultGeoQuery        = defaultGeoQueryImpl
	defaultASNQuery        = defaultASNQueryImpl
	defaultProxyQuery      = defaultProxyQueryImpl
)

var (
	entQueryFunc   = defaultEnterpriseQuery
	geoQueryFunc   = defaultGeoQuery
	asnQueryFunc   = defaultASNQuery
	proxyQueryFunc = defaultProxyQuery
)

var dataDir = filepath.Join("data", "maxmind")

func checkFileExistsImpl(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

var checkFileExists = checkFileExistsImpl

func resolveDBPath(names ...string) string {
	for _, name := range names {
		path := filepath.Join(dataDir, name)
		if checkFileExists(path) {
			return path
		}
	}
	return ""
}
