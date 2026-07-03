package maxmind

import (
	"strings"
	"sync"
	"testing"
)

func TestCheckFileExistsImpl(t *testing.T) {
	if !checkFileExistsImpl("testdata/geo.mmdb") {
		t.Errorf("expected testdata/geo.mmdb to exist")
	}

	if checkFileExistsImpl("this_file_does_not_exist_12345.bin") {
		t.Errorf("expected file not to exist")
	}
}

func TestResolveDBPath(t *testing.T) {
	originalCheck := checkFileExists
	defer func() { checkFileExists = originalCheck }()

	checkFileExists = func(path string) bool {
		return strings.HasSuffix(path, "GeoIP2-City.mmdb")
	}
	res := resolveDBPath("GeoIP2-Enterprise.mmdb", "GeoIP2-City.mmdb")
	if !strings.HasSuffix(res, "GeoIP2-City.mmdb") {
		t.Errorf("expected city path, got %q", res)
	}

	checkFileExists = func(_ string) bool {
		return false
	}
	res = resolveDBPath("GeoIP2-Enterprise.mmdb", "GeoIP2-City.mmdb")
	if res != "" {
		t.Errorf("expected empty path, got %q", res)
	}
}

func TestDefaultQueryImpls_Error(t *testing.T) {
	_, err := defaultGeoQueryImpl("dummy_non_existent.mmdb", "1.2.3.4")
	if err == nil {
		t.Errorf("expected error from defaultGeoQueryImpl, got nil")
	}

	_, err = defaultEnterpriseQueryImpl("dummy_non_existent.mmdb", "1.2.3.4")
	if err == nil {
		t.Errorf("expected error from defaultEnterpriseQueryImpl, got nil")
	}

	_, _, err = defaultASNQueryImpl("dummy_non_existent.mmdb", "1.2.3.4")
	if err == nil {
		t.Errorf("expected error from defaultASNQueryImpl, got nil")
	}

	_, err = defaultProxyQueryImpl("dummy_non_existent.mmdb", "1.2.3.4")
	if err == nil {
		t.Errorf("expected error from defaultProxyQueryImpl, got nil")
	}
}

func TestDefaultQueryImpls_Success_Geo(t *testing.T) {
	cityOnce = sync.Once{}
	if _, err := defaultGeoQueryImpl("testdata/geo.mmdb", "not-an-ip"); err == nil {
		t.Errorf("expected invalid ip error")
	}
	if _, err := defaultGeoQueryImpl("testdata/geo.mmdb", "192.0.2.1"); err != nil {
		t.Errorf("unexpected error from defaultGeoQueryImpl: %v", err)
	}
	if err := cityDB.Close(); err != nil {
		t.Fatalf("failed to close cityDB: %v", err)
	}
	if _, err := defaultGeoQueryImpl("testdata/geo.mmdb", "192.0.2.1"); err == nil {
		t.Errorf("expected error from defaultGeoQueryImpl with closed DB")
	}
}

func TestDefaultQueryImpls_Success_Enterprise(t *testing.T) {
	entOnce = sync.Once{}
	if _, err := defaultEnterpriseQueryImpl("testdata/ent.mmdb", "not-an-ip"); err == nil {
		t.Errorf("expected invalid ip error")
	}
	if _, err := defaultEnterpriseQueryImpl("testdata/ent.mmdb", "192.0.2.1"); err != nil {
		t.Errorf("unexpected error from defaultEnterpriseQueryImpl: %v", err)
	}
	if err := entDB.Close(); err != nil {
		t.Fatalf("failed to close entDB: %v", err)
	}
	if _, err := defaultEnterpriseQueryImpl("testdata/ent.mmdb", "192.0.2.1"); err == nil {
		t.Errorf("expected error from defaultEnterpriseQueryImpl with closed DB")
	}
}

func TestDefaultQueryImpls_Success_ASN(t *testing.T) {
	asnOnce = sync.Once{}
	if _, _, err := defaultASNQueryImpl("testdata/asn.mmdb", "not-an-ip"); err == nil {
		t.Errorf("expected invalid ip error")
	}
	if _, _, err := defaultASNQueryImpl("testdata/GeoIP2-ISP.mmdb", "192.0.2.1"); err != nil {
		t.Errorf("unexpected error from defaultASNQueryImpl ISP: %v", err)
	}
	if err := asnDB.Close(); err != nil {
		t.Fatalf("failed to close asnDB: %v", err)
	}
	if _, _, err := defaultASNQueryImpl("testdata/GeoIP2-ISP.mmdb", "192.0.2.1"); err == nil {
		t.Errorf("expected error from defaultASNQueryImpl ISP with closed DB")
	}

	asnOnce = sync.Once{}
	if _, _, err := defaultASNQueryImpl("testdata/asn.mmdb", "192.0.2.1"); err != nil {
		t.Errorf("unexpected error from defaultASNQueryImpl ASN: %v", err)
	}
	if err := asnDB.Close(); err != nil {
		t.Fatalf("failed to close asnDB: %v", err)
	}
	if _, _, err := defaultASNQueryImpl("testdata/asn.mmdb", "192.0.2.1"); err == nil {
		t.Errorf("expected error from defaultASNQueryImpl ASN with closed DB")
	}
}

func TestDefaultQueryImpls_Success_Proxy(t *testing.T) {
	proxyOnce = sync.Once{}
	if _, err := defaultProxyQueryImpl("testdata/proxy.mmdb", "not-an-ip"); err == nil {
		t.Errorf("expected invalid ip error")
	}
	if _, err := defaultProxyQueryImpl("testdata/proxy.mmdb", "192.0.2.1"); err != nil {
		t.Errorf("unexpected error from defaultProxyQueryImpl: %v", err)
	}
	if err := proxyDB.Close(); err != nil {
		t.Fatalf("failed to close proxyDB: %v", err)
	}
	if _, err := defaultProxyQueryImpl("testdata/proxy.mmdb", "192.0.2.1"); err == nil {
		t.Errorf("expected error from defaultProxyQueryImpl with closed DB")
	}
}
