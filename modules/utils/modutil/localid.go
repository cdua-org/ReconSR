package modutil

import (
	"fmt"

	"cdua-org/ReconSR/schema"
)

// BuildLocalID generates a hierarchical LocalID for conflict-free graph chaining.
// It uses the "|" delimiter to separate the parent's LocalID from the current entity's type and value.
func BuildLocalID(source *schema.EntityRef, entityType, value string) string {
	if source != nil && source.LocalID != "" {
		return fmt.Sprintf("%s|%s|%s", source.LocalID, entityType, value)
	}
	return fmt.Sprintf("%s|%s", entityType, value)
}
