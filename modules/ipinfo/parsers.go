package ipinfo

import (
	"fmt"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func populateResults(exec *schema.ModuleExecution, resp *ipinfoResponse, gen *modutil.LocalIDGenerator) {
	parseGeo(exec, resp, gen)

	if resp.Hostname != "" {
		validated, err := validator.Validate(constants.TypeDomain, resp.Hostname)
		if err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     validated.Type,
				Category: constants.CategoryNode,
				Value:    validated.Value,
				Tags:     []string{constants.TagReverseIP},
				LocalID:  gen.NextID(),
			})
		}
	}

	parseASN(exec, resp, gen)

	addFlagTag(exec, resp.IsAnycast, "anycast", gen)
	addFlagTag(exec, resp.IsHosting, "hosting", gen)
	addFlagTag(exec, resp.IsSatellite, "satellite", gen)

	parseAnonymous(exec, resp, gen)

	parseMobile(exec, resp, gen)
}

func parseASN(exec *schema.ModuleExecution, resp *ipinfoResponse, gen *modutil.LocalIDGenerator) {
	asnVal := resp.Asn
	asName := resp.AsName
	asDomain := resp.AsDomain
	asType := ""

	if resp.As != nil && resp.As.ASN != "" {
		asnVal = resp.As.ASN
		asName = resp.As.Name
		asDomain = resp.As.Domain
		asType = resp.As.Type
	}

	if asnVal == "" {
		return
	}

	asnID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeASN,
		Category: constants.CategoryNode,
		Value:    asnVal,
		LocalID:  asnID,
	})

	var asLastChanged string
	if resp.As != nil {
		asLastChanged = resp.As.LastChanged
	}
	if asLastChanged != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Last Changed: " + asLastChanged,
			LocalID:  gen.NextID(),
			Source: &schema.EntityRef{
				Type:    constants.TypeASN,
				Value:   asnVal,
				LocalID: asnID,
			},
		})
	}

	if asName != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeNetName,
			Category: constants.CategoryProperty,
			Value:    asName,
			LocalID:  gen.NextID(),
			Source: &schema.EntityRef{
				Type:    constants.TypeASN,
				Value:   asnVal,
				LocalID: asnID,
			},
		})
	}
	if asType != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeUsageType,
			Category: constants.CategoryProperty,
			Value:    asType,
			LocalID:  gen.NextID(),
			Source: &schema.EntityRef{
				Type:    constants.TypeASN,
				Value:   asnVal,
				LocalID: asnID,
			},
		})
	}
	if asDomain != "" {
		validated, err := validator.Validate(constants.TypeDomain, asDomain)
		if err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     validated.Type,
				Category: constants.CategoryNode,
				Value:    validated.Value,
				LocalID:  gen.NextID(),
				Source: &schema.EntityRef{
					Type:    constants.TypeASN,
					Value:   asnVal,
					LocalID: asnID,
				},
			})
		}
	}
}

func parseMobile(exec *schema.ModuleExecution, resp *ipinfoResponse, gen *modutil.LocalIDGenerator) {
	if !resp.IsMobile && resp.Mobile == nil {
		return
	}

	mobileID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeTag,
		Category: constants.CategoryProperty,
		Value:    "mobile",
		LocalID:  mobileID,
	})

	if resp.Mobile == nil {
		return
	}
	var mobileParts []string
	if resp.Mobile.Name != "" {
		mobileParts = append(mobileParts, resp.Mobile.Name)
	}
	var mccMnc []string
	if resp.Mobile.Mcc != "" {
		mccMnc = append(mccMnc, "MCC: "+resp.Mobile.Mcc)
	}
	if resp.Mobile.Mnc != "" {
		mccMnc = append(mccMnc, "MNC: "+resp.Mobile.Mnc)
	}
	if len(mccMnc) > 0 {
		if len(mobileParts) > 0 {
			mobileParts[0] += " (" + strings.Join(mccMnc, ", ") + ")"
		} else {
			mobileParts = append(mobileParts, strings.Join(mccMnc, ", "))
		}
	}
	if len(mobileParts) > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    mobileParts[0],
			Context:  "Mobile Network",
			LocalID:  gen.NextID(),
			Source: &schema.EntityRef{
				Type:    constants.TypeTag,
				Value:   "mobile",
				LocalID: mobileID,
			},
		})
	}
}

func parseGeo(exec *schema.ModuleExecution, resp *ipinfoResponse, gen *modutil.LocalIDGenerator) {
	var geoParts []string

	if resp.Geo != nil {
		parseGeoNested(resp, &geoParts)
	} else {
		parseGeoFlat(resp, &geoParts)
	}

	if len(geoParts) > 0 {
		geoID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeGeo,
			Category: constants.CategoryProperty,
			Value:    strings.Join(geoParts, " | "),
			Context:  "Geo Location",
			LocalID:  geoID,
		})

		if resp.Geo != nil && resp.Geo.LastChanged != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeDate,
				Category: constants.CategoryProperty,
				Value:    "Last Changed: " + resp.Geo.LastChanged,
				LocalID:  gen.NextID(),
				Source: &schema.EntityRef{
					Type:    constants.TypeGeo,
					Value:   strings.Join(geoParts, " | "),
					LocalID: geoID,
				},
			})
		}
	}
}

func parseGeoNested(resp *ipinfoResponse, geoParts *[]string) {
	if resp.Geo.City != "" {
		*geoParts = append(*geoParts, "City: "+resp.Geo.City)
	}
	if resp.Geo.Region != "" {
		*geoParts = append(*geoParts, "Region: "+resp.Geo.Region)
	}
	if resp.Geo.Country != "" {
		countryStr := resp.Geo.Country
		if resp.Geo.CountryCode != "" {
			countryStr += " (" + resp.Geo.CountryCode + ")"
		}
		*geoParts = append(*geoParts, "Country: "+countryStr)
	} else if resp.Geo.CountryCode != "" {
		*geoParts = append(*geoParts, "Country: "+resp.Geo.CountryCode)
	}
	if resp.Geo.Latitude != 0 || resp.Geo.Longitude != 0 {
		*geoParts = append(*geoParts, fmt.Sprintf("Lat/Lon: %f, %f", resp.Geo.Latitude, resp.Geo.Longitude))
	}
	if resp.Geo.PostalCode != "" {
		*geoParts = append(*geoParts, "Zip: "+resp.Geo.PostalCode)
	}
	if resp.Geo.Timezone != "" {
		*geoParts = append(*geoParts, "TZ: "+resp.Geo.Timezone)
	}
}

func parseGeoFlat(resp *ipinfoResponse, geoParts *[]string) {
	if resp.City != "" {
		*geoParts = append(*geoParts, "City: "+resp.City)
	}
	if resp.Region != "" {
		*geoParts = append(*geoParts, "Region: "+resp.Region)
	}
	if resp.Country != "" {
		countryStr := resp.Country
		if resp.CountryCode != "" {
			countryStr += " (" + resp.CountryCode + ")"
		}
		*geoParts = append(*geoParts, "Country: "+countryStr)
	} else if resp.CountryCode != "" {
		*geoParts = append(*geoParts, "Country: "+resp.CountryCode)
	}
	if resp.Loc != "" {
		*geoParts = append(*geoParts, "Lat/Lon: "+resp.Loc)
	}
	if resp.Postal != "" {
		*geoParts = append(*geoParts, "Zip: "+resp.Postal)
	}
	if resp.Timezone != "" {
		*geoParts = append(*geoParts, "TZ: "+resp.Timezone)
	}
}

func addFlagTag(exec *schema.ModuleExecution, flag bool, tagValue string, gen *modutil.LocalIDGenerator) {
	if flag {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    tagValue,
			LocalID:  gen.NextID(),
		})
	}
}

func addFlagTagWithSource(exec *schema.ModuleExecution, flag bool, tagValue string, src *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if flag {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    tagValue,
			LocalID:  gen.NextID(),
			Source:   src,
		})
	}
}

func parseAnonymous(exec *schema.ModuleExecution, resp *ipinfoResponse, gen *modutil.LocalIDGenerator) {
	if !resp.IsAnonymous && resp.Anonymous == nil {
		return
	}

	anonID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeTag,
		Category: constants.CategoryProperty,
		Value:    "anonymous",
		LocalID:  anonID,
	})

	if resp.Anonymous == nil {
		return
	}

	anonRef := &schema.EntityRef{
		Type:    constants.TypeTag,
		Value:   "anonymous",
		LocalID: anonID,
	}

	addFlagTagWithSource(exec, resp.Anonymous.IsProxy, constants.TagProxy, anonRef, gen)
	addFlagTagWithSource(exec, resp.Anonymous.IsRelay, "relay", anonRef, gen)
	addFlagTagWithSource(exec, resp.Anonymous.IsTor, constants.TagTorExit, anonRef, gen)
	addFlagTagWithSource(exec, resp.Anonymous.IsVpn, constants.TagVPN, anonRef, gen)
	addFlagTagWithSource(exec, resp.Anonymous.IsResProxy, constants.TagResidentialProxy, anonRef, gen)

	if resp.Anonymous.Name != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    resp.Anonymous.Name,
			Context:  "Privacy Service Name",
			LocalID:  gen.NextID(),
			Source:   anonRef,
		})
	}
	if resp.Anonymous.LastSeen != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Last Seen: " + resp.Anonymous.LastSeen,
			Context:  "Privacy",
			LocalID:  gen.NextID(),
			Source:   anonRef,
		})
	}
}
