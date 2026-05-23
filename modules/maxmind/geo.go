package maxmind

import (
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func getGeoIP(target, cityPath string) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncGetGeoIP)
	dbg.Printf("%s target=%q", constants.FuncGetGeoIP, target)

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	gen := modutil.NewLocalIDGenerator()

	if cityPath == "" {
		return execution
	}

	cityRes, err := geoQueryFunc(cityPath, target)
	if err != nil {
		errMsg := fmt.Errorf("maxmind geo error: %w", err).Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=lookup err=%v", constants.FuncGetGeoIP, target, err)
		return execution
	}

	if cityRes == nil {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetGeoIP, target)
		return execution
	}

	geo := ParseGeo(cityRes)
	if geo != nil {
		formatGeoResult(geo, &execution, &rawBuffer, gen)
	}

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q results=%d", constants.FuncGetGeoIP, target, len(execution.Results))
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetGeoIP, target)
	}

	return execution
}

func formatGeoResult(geo *ParsedGeo, execution *schema.ModuleExecution, rawBuffer *strings.Builder, gen *modutil.LocalIDGenerator) {
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
