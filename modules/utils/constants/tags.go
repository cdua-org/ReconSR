package constants

// TagSpamBotnet and related constants define standardized tag values used by modules to report findings and routing prerequisites consistently.
const (
	TagSpamBotnet  = "spam_botnet"
	TagTorExit     = "tor_exit"
	TagDNSOK       = "dns_ok"
	TagDNSBad      = "dns_bad"
	TagWhitelisted = "whitelisted"
	TagPublicIP    = "public_ip"
	TagSuspicious  = "suspicious"
	TagMalicious   = "malicious"
	TagSpam        = "spam"
	TagDDoS        = "ddos"
	TagBruteforce  = "bruteforce"
	TagScanner     = "scanner"
)
