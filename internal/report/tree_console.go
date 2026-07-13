package report

import (
	"cdua-org/ReconSR/internal/i18n"
	"strconv"
	"strings"
)

// ConsoleTreeFormatter formats tree output for the terminal using ANSI colors.
type ConsoleTreeFormatter struct{}

// FormatNoRelations returns the message when graph has no edges.
func (c *ConsoleTreeFormatter) FormatNoRelations() string {
	return colorYellow + i18n.T["MSG_NO_RELATIONS_FOUND"] + colorReset
}

// FormatHeader returns the formatted project header.
func (c *ConsoleTreeFormatter) FormatHeader(projectName string) string {
	return "\n" + colorCyan + colorBold + "--- " + i18n.T["LBL_RESULTS_FOR"] + ": " + projectName + " ---" + colorReset
}

// FormatTotalEntities returns the total entities count string.
func (c *ConsoleTreeFormatter) FormatTotalEntities(count int) string {
	return colorCyan + i18n.T["LBL_TOTAL_ENTITIES"] + ": " + strconv.Itoa(count) + colorReset
}

// FormatCategoryHeader returns the header for an entity category.
func (c *ConsoleTreeFormatter) FormatCategoryHeader(category string, total int) string {
	return "\n" + colorCyan + category + ": " + strconv.Itoa(total) + colorReset
}

// FormatCategoryStat returns a single statistic line.
func (c *ConsoleTreeFormatter) FormatCategoryStat(itemType string, count int) string {
	return "  - " + itemType + ": " + strconv.Itoa(count)
}

// FormatCategoryFooter returns the footer for an entity category.
func (c *ConsoleTreeFormatter) FormatCategoryFooter() string {
	return ""
}

// FormatNode formats a standard entity node.
func (c *ConsoleTreeFormatter) FormatNode(prefix, marker, nodeType string, subtypes []string, value, connInfo string, isOutOfScope, isLimitReached, isSeen bool) string {
	var b strings.Builder

	b.WriteString(prefix)

	if marker != "" {
		b.WriteString(marker)
		b.WriteByte(' ')
	}

	if nodeType != "" {
		if nodeType == "invalid" {
			b.WriteString("[" + colorRed + i18n.T["LBL_INVALID"] + colorReset + "] ")
		} else {
			b.WriteString("[" + colorCyan + strings.ToUpper(nodeType) + colorReset + "]")
			for _, st := range subtypes {
				b.WriteByte('[')
				b.WriteString(colorCyan)
				b.WriteString(strings.ToUpper(st))
				b.WriteString(colorReset)
				b.WriteByte(']')
			}
			b.WriteByte(' ')
		}
	}

	nodeColor := colorGreen + colorBold
	if isOutOfScope {
		nodeColor = colorBlue
	} else if isLimitReached {
		nodeColor = colorYellow + colorBold
	} else if isSeen {
		nodeColor = colorYellow
	}

	b.WriteString(nodeColor)
	b.WriteString(value)
	b.WriteString(colorReset)

	if connInfo != "" {
		b.WriteString(" (" + colorMagenta + connInfo + colorReset + ")")
	}

	if isOutOfScope {
		b.WriteString(" " + colorBlue + i18n.T["LBL_OUT_OF_SCOPE"] + colorReset)
	} else if isLimitReached {
		b.WriteString(" " + colorYellow + i18n.T["LBL_LIMIT_REACHED"] + colorReset)
	}

	if isSeen {
		b.WriteString(" " + colorCyan + "(" + i18n.T["LBL_SEEN"] + ")" + colorReset)
	}

	return b.String()
}

// FormatProperty formats an entity property node.
func (c *ConsoleTreeFormatter) FormatProperty(basePrefix, startChar, propIndent, propType string, subtypes []string, value, connInfo string, isOutOfScope, isSeen bool) string {
	var b strings.Builder

	b.WriteString(basePrefix)
	b.WriteString(startChar)
	b.WriteString(propIndent)
	b.WriteString("• [")

	if propType == "invalid" {
		b.WriteString(colorRed + i18n.T["LBL_INVALID"] + colorReset + "] [")
	} else {
		b.WriteString(colorYellow + strings.ToUpper(propType) + colorReset + "]")
		for _, st := range subtypes {
			b.WriteByte('[')
			b.WriteString(colorYellow)
			b.WriteString(strings.ToUpper(st))
			b.WriteString(colorReset)
			b.WriteByte(']')
		}
		b.WriteString(" [")
	}

	if isOutOfScope {
		b.WriteString(colorBlue)
	}
	b.WriteString(value)
	b.WriteString(colorReset + "]")

	if connInfo != "" {
		b.WriteString(" (" + colorMagenta + connInfo + colorReset + ")")
	}

	if isOutOfScope {
		b.WriteString(" " + colorBlue + i18n.T["LBL_OUT_OF_SCOPE"] + colorReset)
	}

	if isSeen {
		b.WriteString(" " + colorCyan + "(" + i18n.T["LBL_SEEN"] + ")" + colorReset)
	}

	return b.String()
}
