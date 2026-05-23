package maxmind

import (
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func getEnterpriseData(target, dbPath string) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncGetMMEnterpriseData)
	dbg.Printf("%s target=%q", constants.FuncGetMMEnterpriseData, target)

	entRes, err := entQueryFunc(dbPath, target)
	if err != nil {
		errMsg := fmt.Errorf("maxmind enterprise error: %w", err).Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=lookup err=%v", constants.FuncGetMMEnterpriseData, target, err)
		return execution
	}

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	gen := modutil.NewLocalIDGenerator()

	if entRes == nil {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetMMEnterpriseData, target)
		return execution
	}

	if geo := ParseGeo(entRes); geo != nil {
		formatEnterpriseGeo(geo, &execution, &rawBuffer, gen)
	}
	if conf := ParseConfidence(entRes); conf != nil {
		formatEnterpriseConfidence(conf, &execution, &rawBuffer, gen)
	}
	if traits := ParseTraits(entRes); traits != nil {
		formatEnterpriseTraits(traits, &execution, &rawBuffer, gen)
	}
	if asn := ParseASN(entRes); asn != nil {
		formatEnterpriseASN(asn, &execution, &rawBuffer, gen)
	}
	if isp := ParseISP(entRes); isp != nil {
		formatEnterpriseISP(isp, &execution, &rawBuffer, gen)
	}

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q results=%d", constants.FuncGetMMEnterpriseData, target, len(execution.Results))
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetMMEnterpriseData, target)
	}

	return execution
}

func formatEnterpriseGeo(geo *ParsedGeo, execution *schema.ModuleExecution, rawBuffer *strings.Builder, gen *modutil.LocalIDGenerator) {
	var geoParts []string

	if geo.CityName != "" {
		geoParts = append(geoParts, "City: "+geo.CityName)
		writeRaw(rawBuffer, "City", geo.CityName)
	}
	if geo.RegionName != "" {
		geoParts = append(geoParts, "Region: "+geo.RegionName)
		writeRaw(rawBuffer, "Region", geo.RegionName)
	}
	if geo.ContinentName != "" {
		continentStr := geo.ContinentName
		if geo.ContinentCode != "" {
			continentStr += " (" + geo.ContinentCode + ")"
			writeRaw(rawBuffer, "ContinentCode", geo.ContinentCode)
		}
		geoParts = append(geoParts, "Continent: "+continentStr)
		writeRaw(rawBuffer, "Continent", geo.ContinentName)
	}
	if geo.CountryName != "" {
		countryStr := geo.CountryName
		if geo.CountryIso != "" {
			countryStr += " (" + geo.CountryIso + ")"
			writeRaw(rawBuffer, "CountryIso", geo.CountryIso)
		}
		geoParts = append(geoParts, "Country: "+countryStr)
		writeRaw(rawBuffer, "Country", geo.CountryName)
	}
	if geo.RegisteredCountryName != "" {
		regCountryStr := geo.RegisteredCountryName
		if geo.RegisteredCountryIso != "" {
			regCountryStr += " (" + geo.RegisteredCountryIso + ")"
			writeRaw(rawBuffer, "RegisteredCountryIso", geo.RegisteredCountryIso)
		}
		geoParts = append(geoParts, "RegisteredCountry: "+regCountryStr)
		writeRaw(rawBuffer, "RegisteredCountry", geo.RegisteredCountryName)
	}
	if geo.Latitude != 0 || geo.Longitude != 0 {
		geoParts = append(geoParts, fmt.Sprintf("Lat/Lon: %f, %f", geo.Latitude, geo.Longitude))
		writeRaw(rawBuffer, "Latitude", fmt.Sprintf("%f", geo.Latitude))
		writeRaw(rawBuffer, "Longitude", fmt.Sprintf("%f", geo.Longitude))
	}
	if geo.AccuracyRadius > 0 {
		accStr := strconv.FormatUint(uint64(geo.AccuracyRadius), 10)
		geoParts = append(geoParts, "AccuracyRadius: "+accStr+"km")
		writeRaw(rawBuffer, "AccuracyRadius", accStr)
	}
	if geo.TimeZone != "" {
		geoParts = append(geoParts, "TZ: "+geo.TimeZone)
		writeRaw(rawBuffer, "TimeZone", geo.TimeZone)
	}
	if geo.PostalCode != "" {
		geoParts = append(geoParts, "Zip: "+geo.PostalCode)
		writeRaw(rawBuffer, "PostalCode", geo.PostalCode)
	}

	if len(geoParts) > 0 {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeGeo,
			Category: constants.CategoryProperty,
			Value:    strings.Join(geoParts, " | "),
			Context:  "Geo Location",
			LocalID:  gen.NextID(),
		})
	}
}

func formatEnterpriseConfidence(conf *ParsedConfidence, execution *schema.ModuleExecution, rawBuffer *strings.Builder, gen *modutil.LocalIDGenerator) {
	if conf.CityConf > 0 {
		confStr := strconv.FormatUint(uint64(conf.CityConf), 10)
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeConfidenceScore,
			Category: constants.CategoryProperty,
			Value:    confStr,
			Context:  "City Confidence",
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "CityConfidence", confStr)
	}
	if conf.CountryConf > 0 {
		confStr := strconv.FormatUint(uint64(conf.CountryConf), 10)
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeConfidenceScore,
			Category: constants.CategoryProperty,
			Value:    confStr,
			Context:  "Country Confidence",
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "CountryConfidence", confStr)
	}
	if conf.PostalConf > 0 {
		confStr := strconv.FormatUint(uint64(conf.PostalConf), 10)
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeConfidenceScore,
			Category: constants.CategoryProperty,
			Value:    confStr,
			Context:  "Postal Confidence",
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "PostalConfidence", confStr)
	}
	if conf.RegionConf > 0 {
		confStr := strconv.FormatUint(uint64(conf.RegionConf), 10)
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeConfidenceScore,
			Category: constants.CategoryProperty,
			Value:    confStr,
			Context:  "Region Confidence",
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "RegionConfidence", confStr)
	}
}

func formatEnterpriseTraits(traits *ParsedTraits, execution *schema.ModuleExecution, rawBuffer *strings.Builder, gen *modutil.LocalIDGenerator) {
	if traits.Domain != "" {
		if val, err := validator.Validate(constants.TypeDomain, traits.Domain); err == nil {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     val.Type,
				Category: constants.CategoryNode,
				Value:    val.Value,
				Tags:     []string{constants.TagReverseIP},
				LocalID:  gen.NextID(),
			})
		}
		writeRaw(rawBuffer, "Domain", traits.Domain)
	}
	if traits.ConnectionType != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    "Connection Type: " + traits.ConnectionType,
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "ConnectionType", traits.ConnectionType)
	}
	if traits.UserType != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeUsageType,
			Category: constants.CategoryProperty,
			Value:    traits.UserType,
			Context:  "User Type",
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "UserType", traits.UserType)
	}
	if traits.StaticIPScore > 0 {
		scoreStr := fmt.Sprintf("%.2f", traits.StaticIPScore)
		desc := "Static"
		if traits.StaticIPScore < 30.0 {
			desc = "Highly Dynamic"
		} else if traits.StaticIPScore < 70.0 {
			desc = "Dynamic"
		}

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    fmt.Sprintf("Static IP Score: %s (%s)", scoreStr, desc),
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "StaticIPScore", scoreStr)
	}
}

func formatEnterpriseASN(asn *ParsedASN, execution *schema.ModuleExecution, rawBuffer *strings.Builder, gen *modutil.LocalIDGenerator) {
	if asn.ASNOrg != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeOrganization,
			Category: constants.CategoryProperty,
			Value:    asn.ASNOrg,
			Context:  "ASN Organization",
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "AutonomousSystemOrganization", asn.ASNOrg)
	}
	if asn.ASN > 0 {
		asnVal := "AS" + strconv.FormatUint(uint64(asn.ASN), 10)
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeASN,
			Category: constants.CategoryNode,
			Value:    asnVal,
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "AutonomousSystemNumber", asnVal)
	}
}

func formatEnterpriseISP(isp *ParsedISP, execution *schema.ModuleExecution, rawBuffer *strings.Builder, gen *modutil.LocalIDGenerator) {
	if isp.ISP != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeISP,
			Category: constants.CategoryProperty,
			Value:    isp.ISP,
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "ISP", isp.ISP)
	}
	if isp.Organization != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeOrganization,
			Category: constants.CategoryProperty,
			Value:    isp.Organization,
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "Organization", isp.Organization)
	}
	if isp.MobileCountryCode != "" {
		writeRaw(rawBuffer, "MobileCountryCode", isp.MobileCountryCode)
	}
	if isp.MobileNetworkCode != "" {
		writeRaw(rawBuffer, "MobileNetworkCode", isp.MobileNetworkCode)
	}
}
