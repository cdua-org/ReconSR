package vuln_lookup

// CIRCLCVEResponse models the root structure of the CIRCL Vulnerability API
// response for a single CVE record conforming to the cvelistV5 standard.
type CIRCLCVEResponse struct {
	VulnLookupMeta *VulnLookupMeta `json:"vulnerability-lookup:meta"`
	DataType       string          `json:"dataType"`
	DataVersion    string          `json:"dataVersion"`
	CVEMetadata    CVEMetadata     `json:"cveMetadata"`
	Containers     Containers      `json:"containers"`
}

// CVEMetadata extracts the core identification and lifecycle states
// of the vulnerability, enabling downstream prioritization by recency.
type CVEMetadata struct {
	CVEId         string `json:"cveId"`
	State         string `json:"state"`
	DatePublished string `json:"datePublished"`
	DateUpdated   string `json:"dateUpdated"`
}

// Containers separates the primary advisory data from third-party
// enrichments to maintain data provenance between CNA and ADP sources.
type Containers struct {
	CNA CNA   `json:"cna"`
	ADP []ADP `json:"adp"`
}

// CNA encapsulates the core vulnerability details provided by the
// CVE Numbering Authority, serving as the primary source of truth.
type CNA struct {
	Title            string             `json:"title"`
	Descriptions     []Description      `json:"descriptions"`
	Metrics          []Metric           `json:"metrics"`
	ProblemTypes     []ProblemType      `json:"problemTypes"`
	CpeApplicability []CpeApplicability `json:"cpeApplicability"`
}

// CpeApplicability holds lists of nodes matching CPE criteria.
type CpeApplicability struct {
	Nodes []CpeNode `json:"nodes"`
}

// CpeNode contains CPE matching criteria.
type CpeNode struct {
	CpeMatch []CpeMatch `json:"cpeMatch"`
}

// CpeMatch holds the actual CPE string criteria.
type CpeMatch struct {
	Criteria string `json:"criteria"`
}

// ProblemType represents the CWE information.
type ProblemType struct {
	Descriptions []ProblemDescription `json:"descriptions"`
}

// ProblemDescription holds the actual CWE details.
type ProblemDescription struct {
	CWEId       string `json:"cweId"`
	Description string `json:"description"`
	Type        string `json:"type"`
}

// ADP handles auxiliary data from Authorized Data Publishers, capturing
// supplementary scoring such as CISA Vulnrichment SSVC or updated CVSS.
type ADP struct {
	Title        string        `json:"title"`
	Metrics      []Metric      `json:"metrics"`
	ProblemTypes []ProblemType `json:"problemTypes"`
}

// Description standardizes localized text blocks within the CVE record.
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metric consolidates various scoring formats under a unified structure,
// guaranteeing all available CVSS versions can be parsed without type assertions.
type Metric struct {
	CVSSV31 *CVSSV3      `json:"cvssV3_1"`
	CVSSV30 *CVSSV3      `json:"cvssV3_0"`
	CVSSV40 *CVSSV4      `json:"cvssV4_0"`
	Other   *OtherMetric `json:"other"`
	Format  string       `json:"format"`
}

// OtherMetric extracts alternative metric structures like SSVC or KEV.
type OtherMetric struct {
	Type    string `json:"type"`
	Content struct {
		DateAdded string `json:"dateAdded"`
		Options   []struct {
			Exploitation    string `json:"Exploitation"`
			Automatable     string `json:"Automatable"`
			TechnicalImpact string `json:"Technical Impact"`
		} `json:"options"`
	} `json:"content"`
}

// CVSSV3 maps the Common Vulnerability Scoring System version 3 schema,
// extracting the vector string alongside the base score for impact analysis.
type CVSSV3 struct {
	VectorString string  `json:"vectorString"`
	BaseSeverity string  `json:"baseSeverity"`
	BaseScore    float64 `json:"baseScore"`
}

// CVSSV4 maps the Common Vulnerability Scoring System version 4 schema,
// reflecting structural updates for accurate parsing of newer disclosures.
type CVSSV4 struct {
	VectorString string  `json:"vectorString"`
	BaseSeverity string  `json:"baseSeverity"`
	BaseScore    float64 `json:"baseScore"`
}

// VulnLookupMeta holds enrichment data from the vulnerability-lookup
// platform, providing NVD metrics and EPSS scores absent from the CNA record.
type VulnLookupMeta struct {
	EPSS *EPSSData `json:"epss"`
	NVD  string    `json:"nvd"`
}

// EPSSData represents the Exploit Prediction Scoring System data,
// quantifying the probability that a vulnerability will be exploited.
type EPSSData struct {
	CVE        string `json:"cve"`
	Date       string `json:"date"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
}

// NVDWrapper is the top-level envelope for the string-encoded NVD JSON
// embedded within the vulnerability-lookup:meta field.
type NVDWrapper struct {
	CVE NVDCVEData `json:"cve"`
}

// NVDCVEData holds the NVD-specific scoring and weakness classification,
// used as a fallback when the CNA record lacks native CVSS metrics.
type NVDCVEData struct {
	Metrics    NVDMetrics    `json:"metrics"`
	Weaknesses []NVDWeakness `json:"weaknesses"`
}

// NVDMetrics aggregates all CVSS version entries published by NVD.
type NVDMetrics struct {
	CVSSV40 []NVDCVSSEntry   `json:"cvssMetricV40"`
	CVSSV31 []NVDCVSSEntry   `json:"cvssMetricV31"`
	CVSSV30 []NVDCVSSEntry   `json:"cvssMetricV30"`
	CVSSV2  []NVDCVSSEntryV2 `json:"cvssMetricV2"`
}

// NVDCVSSEntry represents a single NVD CVSS v3.x or v4.0 metric entry
// where baseSeverity resides inside the cvssData object.
type NVDCVSSEntry struct {
	CVSSData NVDCVSSData `json:"cvssData"`
}

// NVDCVSSEntryV2 represents a single NVD CVSS v2 metric entry where
// baseSeverity is at the outer level rather than inside cvssData.
type NVDCVSSEntryV2 struct {
	BaseSeverity string      `json:"baseSeverity"`
	CVSSData     NVDCVSSData `json:"cvssData"`
}

// NVDCVSSData holds the version-agnostic CVSS score fields from NVD.
type NVDCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseSeverity string  `json:"baseSeverity"`
	BaseScore    float64 `json:"baseScore"`
}

// NVDWeakness holds a CWE classification entry from the NVD dataset.
type NVDWeakness struct {
	Description []NVDWeaknessDesc `json:"description"`
}

// NVDWeaknessDesc holds the actual CWE identifier string from NVD.
type NVDWeaknessDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}
