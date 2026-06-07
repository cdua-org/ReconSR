// Package dateutil normalizes raw timestamps and keeps the latest calendar day
// per caller-defined logical entity key so modules can emit compact graph dates.
package dateutil

import (
	"sort"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

var supportedLayouts = []string{
	time.DateOnly,
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	"2006/01/02 15:04:05",
	"2006/01/02",
	"02.01.2006 15:04:05",
	"02.01.2006",
}

// LatestDate keeps the latest normalized day for a caller-defined logical key
// while preserving the source entity chosen by the caller for graph linkage.
type LatestDate struct {
	Key    string
	Source *schema.EntityRef
	Day    string
}

// Collector deduplicates multiple raw timestamps for the same logical key and
// keeps only the latest normalized calendar day.
type Collector struct {
	items map[string]LatestDate
}

// NewCollector creates a collector for caller-defined date deduplication.
func NewCollector() *Collector {
	return &Collector{
		items: make(map[string]LatestDate),
	}
}

// NormalizeDay converts supported date or datetime strings to YYYY-MM-DD.
// It returns false when the input cannot be safely normalized.
func NormalizeDay(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	if len(raw) >= len(time.DateOnly) {
		candidate := raw[:len(time.DateOnly)]
		if _, err := time.Parse(time.DateOnly, candidate); err == nil {
			return candidate, true
		}
	}

	for _, layout := range supportedLayouts {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed.Format(time.DateOnly), true
		}
	}

	return "", false
}

// Add normalizes raw and updates key with the latest available day. The caller
// controls the deduplication scope through key and the graph linkage through
// source.
func (c *Collector) Add(key string, source *schema.EntityRef, raw string) {
	if c == nil {
		return
	}

	key = strings.TrimSpace(key)
	if key == "" {
		return
	}

	day, ok := NormalizeDay(raw)
	if !ok {
		return
	}

	current, exists := c.items[key]
	if !exists {
		c.items[key] = LatestDate{
			Key:    key,
			Source: cloneEntityRef(source),
			Day:    day,
		}
		return
	}

	if current.Source == nil && source != nil {
		current.Source = cloneEntityRef(source)
	}
	if day > current.Day {
		current.Day = day
	}

	c.items[key] = current
}

// Items returns the deduplicated latest dates in deterministic key order so
// callers can emit stable graph properties.
func (c *Collector) Items() []LatestDate {
	if c == nil || len(c.items) == 0 {
		return nil
	}

	keys := make([]string, 0, len(c.items))
	for key := range c.items {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	items := make([]LatestDate, 0, len(keys))
	for _, key := range keys {
		item := c.items[key]
		item.Source = cloneEntityRef(item.Source)
		items = append(items, item)
	}

	return items
}

func cloneEntityRef(source *schema.EntityRef) *schema.EntityRef {
	if source == nil {
		return nil
	}

	cloned := *source
	return &cloned
}
