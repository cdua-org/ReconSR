package vuln_lookup

import (
	"encoding/json"
	"strconv"
	"strings"
)

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

// UniversalCVSS is a dynamic unified struct for all CVSS versions (V2, V3, V4, V5+).
type UniversalCVSS struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseSeverity string  `json:"baseSeverity"`
	BaseScore    float64 `json:"baseScore"`
}

// Metric consolidates scoring formats dynamically via a custom JSON unmarshaler.
type Metric struct {
	Other           *OtherMetric
	BestCVSS        *UniversalCVSS
	Format          string
	BestCVSSVersion float64
}

// UnmarshalJSON implements custom JSON parsing to dynamically select the highest CVSS metric.
func (m *Metric) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if other, ok := raw["other"]; ok {
		var om OtherMetric
		if err := json.Unmarshal(other, &om); err == nil {
			m.Other = &om
		}
	}
	if format, ok := raw["format"]; ok {
		if err := json.Unmarshal(format, &m.Format); err != nil {
			m.Format = ""
		}
	}
	for k, v := range raw {
		m.processRawKey(k, v)
	}
	return nil
}

func (m *Metric) processRawKey(k string, v json.RawMessage) {
	if !strings.HasPrefix(k, "cvssV") {
		return
	}
	var cvss UniversalCVSS
	if err := json.Unmarshal(v, &cvss); err != nil {
		return
	}
	verStr := cvss.Version
	if verStr == "" {
		verStr = strings.ReplaceAll(strings.TrimPrefix(k, "cvssV"), "_", ".")
	}
	if ver, err := strconv.ParseFloat(verStr, 64); err == nil && ver > m.BestCVSSVersion {
		m.BestCVSSVersion = ver
		m.BestCVSS = &cvss
	}
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

// NVDMetrics aggregates all CVSS version entries dynamically.
type NVDMetrics struct {
	BestCVSS        *UniversalCVSS
	BestCVSSVersion float64
}

// UnmarshalJSON implements custom JSON parsing to dynamically select the highest CVSS metric from NVD array formats.
func (n *NVDMetrics) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		n.processRawKey(k, v)
	}
	return nil
}

func (n *NVDMetrics) processRawKey(k string, v json.RawMessage) {
	if !strings.HasPrefix(k, "cvssMetricV") {
		return
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(v, &entries); err != nil || len(entries) == 0 {
		return
	}
	first := entries[0]
	var cvss UniversalCVSS
	if cvssData, ok := first["cvssData"]; ok {
		if err := json.Unmarshal(cvssData, &cvss); err != nil {
			cvss = UniversalCVSS{}
		}
	}
	if bsRaw, ok := first["baseSeverity"]; ok && cvss.BaseSeverity == "" {
		var bs string
		if json.Unmarshal(bsRaw, &bs) == nil {
			cvss.BaseSeverity = bs
		}
	}
	verStr := cvss.Version
	if verStr == "" {
		verStr = strings.TrimPrefix(k, "cvssMetricV")
		if len(verStr) == 2 {
			verStr = verStr[0:1] + "." + verStr[1:2]
		} else if len(verStr) == 1 {
			verStr += ".0"
		}
	}
	if ver, err := strconv.ParseFloat(verStr, 64); err == nil && ver > n.BestCVSSVersion {
		n.BestCVSSVersion = ver
		n.BestCVSS = &cvss
	}
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
