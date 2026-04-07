package dns

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

// parseLOC decodes RFC 3597 "unknown RR" wire representation (\# 16 <hex>)
// back into human-readable RFC 1876 representation for LOC entries, if needed.
func parseLOC(raw string) string {
	if !strings.HasPrefix(raw, "\\# 16 ") {
		return raw
	}

	hexPart := strings.TrimSpace(raw[5:])
	data, err := hex.DecodeString(hexPart)
	if err != nil || len(data) != 16 {
		return raw
	}

	if data[0] != 0 {
		return raw // Only version 0 supported
	}

	decodeSize := func(b byte) string {
		m := b >> 4
		e := b & 0x0F
		valCm := float64(m) * math.Pow10(int(e))
		return fmt.Sprintf("%.2fm", valCm/100.0)
	}

	decodeCoord := func(val uint32, pos, neg string) string {
		offset := uint32(2147483648)
		var dir string
		var diff uint32
		if val >= offset {
			dir = pos
			diff = val - offset
		} else {
			dir = neg
			diff = offset - val
		}

		secThousandths := diff % 1000
		totalSecs := diff / 1000
		sec := totalSecs % 60
		totalMins := totalSecs / 60
		mins := totalMins % 60
		deg := totalMins / 60

		return fmt.Sprintf("%d %d %.3f %s", deg, mins, float64(sec)+float64(secThousandths)/1000.0, dir)
	}

	size := decodeSize(data[1])
	horiz := decodeSize(data[2])
	vert := decodeSize(data[3])

	latVal := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
	lonVal := uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11])
	altVal := uint32(data[12])<<24 | uint32(data[13])<<16 | uint32(data[14])<<8 | uint32(data[15])

	lat := decodeCoord(latVal, "N", "S")
	lon := decodeCoord(lonVal, "E", "W")
	alt := (float64(altVal) - 10000000.0) / 100.0

	return fmt.Sprintf("%s %s %.2fm %s %s %s", lat, lon, alt, size, horiz, vert)
}

func getLOCData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_loc",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 29, nil) // 29 is QTYPE for LOC
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   parseLOC(rec),
			Context: "Geographic Location",
		})
	}

	return execution
}
