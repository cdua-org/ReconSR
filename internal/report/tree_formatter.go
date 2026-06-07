package report

// TreeFormatter defines the strategy for formatting graph components into text.
type TreeFormatter interface {
	FormatNoRelations() string
	FormatHeader(projectName string) string
	FormatTotalEntities(count int) string
	FormatCategoryHeader(category string, total int) string
	FormatCategoryStat(itemType string, count int) string
	FormatCategoryFooter() string

	FormatNode(prefix, marker, nodeType string, subtypes []string, value, connInfo string, isOutOfScope, isLimitReached, isSeen bool) string
	FormatProperty(basePrefix, startChar, propIndent, propType, value, connInfo string, isOutOfScope, isSeen bool) string
}
