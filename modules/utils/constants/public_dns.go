package constants

// DNSResolverDoHCloudflare and related constants define canonical public DNS fallback endpoints and resolver addresses so networking utilities can reuse the embedded default resolver set without duplicating literals.
const (
	DNSResolverDoHCloudflare        = "https://dns.cloudflare.com/dns-query"
	DNSResolverDoHGoogle            = "https://dns.google/resolve"
	DNSResolverDoHAdGuard           = "https://unfiltered.adguard-dns.com/resolve"
	DNSResolverDoHMozillaCloudflare = "https://mozilla.cloudflare-dns.com/dns-query"
	DNSResolverDoHSB                = "https://doh.dns.sb/dns-query"

	DNSResolverCloudflarePrimary    = "1.1.1.1"
	DNSResolverGooglePrimary        = "8.8.8.8"
	DNSResolverQuad9Primary         = "9.9.9.10"
	DNSResolverAdGuardPrimary       = "94.140.14.140"
	DNSResolverDNSWatchPrimary      = "84.200.69.80"
	DNSResolverResolver19318398154  = "193.183.98.154"
	DNSResolverLevel3Primary        = "4.2.2.1"
	DNSResolverCloudflareSecondary  = "1.0.0.1"
	DNSResolverGoogleSecondary      = "8.8.4.4"
	DNSResolverQuad9Secondary       = "149.112.112.10"
	DNSResolverAdGuardSecondary     = "94.140.14.141"
	DNSResolverDNSWatchSecondary    = "84.200.70.40"
	DNSResolverResolver185121177177 = "185.121.177.177"
	DNSResolverLevel3Secondary      = "4.2.2.2"
)
