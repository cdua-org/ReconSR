package ip2location

import (
	"fmt"
	"strings"

	"github.com/ip2location/ip2location-go/v9"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func getGeoIP(target, dbPath string) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncGetGeoIP)
	dbg.Printf("%s target=%q", constants.FuncGetGeoIP, target)

	res, err := geoQueryFunc(dbPath, target)
	if err != nil {
		errMsg := fmt.Errorf("ip2location db11 error: %w", err).Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=lookup err=%v", constants.FuncGetGeoIP, target, err)
		return execution
	}

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	gen := modutil.NewLocalIDGenerator()

	var geoParts []string
	parseGeoLocation(res, &geoParts, &rawBuffer)
	parseGeoInfo(res, &execution, &rawBuffer, gen)
	parseGeoMobile(res, &execution, &rawBuffer, gen)

	if len(geoParts) > 0 {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeGeo,
			Category: constants.CategoryProperty,
			Value:    strings.Join(geoParts, " | "),
			Context:  "Geo Location",
			LocalID:  gen.NextID(),
		})
	}

	if !isUnavailable(res.Iddcode) {
		writeRaw(&rawBuffer, "Iddcode", res.Iddcode)
	}
	if !isUnavailable(res.Areacode) {
		writeRaw(&rawBuffer, "Areacode", res.Areacode)
	}

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q results=%d", constants.FuncGetGeoIP, target, len(execution.Results))
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetGeoIP, target)
	}

	return execution
}

func parseGeoInfo(res *ip2location.IP2Locationrecord, exec *schema.ModuleExecution, rawBuffer *strings.Builder, gen *modutil.LocalIDGenerator) {
	if !isUnavailable(res.Isp) {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeISP,
			Category: constants.CategoryProperty,
			Value:    res.Isp,
			Context:  "ISP",
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "Isp", res.Isp)
	}

	if !isUnavailable(res.Domain) {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDomain,
			Category: constants.CategoryNode,
			Value:    res.Domain,
			Tags:     []string{constants.TagReverseIP},
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "Domain", res.Domain)
	}

	if !isUnavailable(res.Usagetype) {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeUsageType,
			Category: constants.CategoryProperty,
			Value:    ParseUsageType(res.Usagetype),
			Context:  "Usage Type",
			LocalID:  gen.NextID(),
		})
		writeRaw(rawBuffer, "Usagetype", res.Usagetype)
	}

	if !isUnavailable(res.Netspeed) {
		appendInfo(exec, "Connection Speed", res.Netspeed, gen)
		writeRaw(rawBuffer, "Netspeed", res.Netspeed)
	}
	if !isUnavailable(res.Addresstype) {
		appendInfo(exec, "Address Type", res.Addresstype, gen)
		writeRaw(rawBuffer, "Addresstype", res.Addresstype)
	}
	if !isUnavailable(res.Category) {
		appendInfo(exec, "IAB Category", res.Category, gen)
		writeRaw(rawBuffer, "Category", res.Category)
	}
}

func parseGeoLocation(res *ip2location.IP2Locationrecord, geoParts *[]string, rawBuffer *strings.Builder) {
	if !isUnavailable(res.City) {
		*geoParts = append(*geoParts, "City: "+res.City)
		writeRaw(rawBuffer, "City", res.City)
	}
	if !isUnavailable(res.District) {
		*geoParts = append(*geoParts, "District: "+res.District)
		writeRaw(rawBuffer, "District", res.District)
	}
	if !isUnavailable(res.Region) {
		*geoParts = append(*geoParts, "Region: "+res.Region)
		writeRaw(rawBuffer, "Region", res.Region)
	}
	if !isUnavailable(res.Country_long) {
		countryStr := res.Country_long
		if !isUnavailable(res.Country_short) {
			countryStr += " (" + res.Country_short + ")"
			writeRaw(rawBuffer, "Country_short", res.Country_short)
		}
		*geoParts = append(*geoParts, "Country: "+countryStr)
		writeRaw(rawBuffer, "Country_long", res.Country_long)
	}
	if !isUnavailableFloat(res.Latitude) || !isUnavailableFloat(res.Longitude) {
		*geoParts = append(*geoParts, fmt.Sprintf("Lat/Lon: %f, %f", res.Latitude, res.Longitude))
		writeRaw(rawBuffer, "Latitude", fmt.Sprintf("%f", res.Latitude))
		writeRaw(rawBuffer, "Longitude", fmt.Sprintf("%f", res.Longitude))
	}
	if !isUnavailable(res.Zipcode) {
		*geoParts = append(*geoParts, "Zip: "+res.Zipcode)
		writeRaw(rawBuffer, "Zipcode", res.Zipcode)
	}
	if !isUnavailable(res.Timezone) {
		*geoParts = append(*geoParts, "TZ: "+res.Timezone)
		writeRaw(rawBuffer, "Timezone", res.Timezone)
	}
	if !isUnavailableFloat(res.Elevation) {
		*geoParts = append(*geoParts, fmt.Sprintf("Elevation: %.0fm", res.Elevation))
		writeRaw(rawBuffer, "Elevation", fmt.Sprintf("%.0f", res.Elevation))
	}
}

func parseGeoMobile(res *ip2location.IP2Locationrecord, exec *schema.ModuleExecution, rawBuffer *strings.Builder, gen *modutil.LocalIDGenerator) {
	var mobileParts []string
	if !isUnavailable(res.Mobilebrand) {
		mobileParts = append(mobileParts, res.Mobilebrand)
		writeRaw(rawBuffer, "Mobilebrand", res.Mobilebrand)
	}
	var mccMnc []string
	if !isUnavailable(res.Mcc) {
		mccMnc = append(mccMnc, "MCC: "+res.Mcc)
		writeRaw(rawBuffer, "Mcc", res.Mcc)
	}
	if !isUnavailable(res.Mnc) {
		mccMnc = append(mccMnc, "MNC: "+res.Mnc)
		writeRaw(rawBuffer, "Mnc", res.Mnc)
	}
	if len(mccMnc) > 0 {
		if len(mobileParts) > 0 {
			mobileParts[0] += " (" + strings.Join(mccMnc, ", ") + ")"
		} else {
			mobileParts = append(mobileParts, strings.Join(mccMnc, ", "))
		}
	}
	if len(mobileParts) > 0 {
		appendInfo(exec, "Mobile Network", mobileParts[0], gen)
	}
}

func writeRaw(b *strings.Builder, key, val string) {
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(val)
}

func appendInfo(exec *schema.ModuleExecution, contextStr, value string, gen *modutil.LocalIDGenerator) {
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    value,
		Context:  contextStr,
		LocalID:  gen.NextID(),
	})
}
