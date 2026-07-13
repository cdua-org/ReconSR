package report

import (
	"cdua-org/ReconSR/internal/i18n"
	"cdua-org/ReconSR/schema"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// HTMLTreeFormatter formats tree output into HTML with inline styles mirroring ANSI colors.
type HTMLTreeFormatter struct{}

const (
	htmlSpanCyan    = `<span style="color:#00ffff;">`
	htmlSpanCyanB   = `<span style="color:#00ffff;font-weight:bold;">`
	htmlSpanGreen   = `<span style="color:#00ff00;">`
	htmlSpanGreenB  = `<span style="color:#00ff00;font-weight:bold;">`
	htmlSpanYellow  = `<span style="color:#ffff00;">`
	htmlSpanYellowB = `<span style="color:#ffff00;font-weight:bold;">`
	htmlSpanRed     = `<span style="color:#ff0000;">`
	htmlSpanMagenta = `<span style="color:#ff00ff;">`
	htmlSpanBlue    = `<span style="color:#0000ff;">`
	htmlSpanEnd     = `</span>`
)

// GenerateTreeHTML creates an HTML file containing the text tree representation of the graph,
// saving it to the standard reports directory.
func GenerateTreeHTML(graph *schema.ProjectGraph) (string, error) {
	if err := os.MkdirAll("reports", 0700); err != nil {
		return "", err
	}
	root, err := os.OpenRoot("reports")
	if err != nil {
		return "", err
	}
	defer root.Close()

	targetSubDir := sanitizePath(graph.InitialTarget)
	if err := root.MkdirAll(targetSubDir, 0700); err != nil {
		return "", err
	}

	now := time.Now()
	rawFileTime := now.Format("2006-01-02_15-04-05")

	sanitizedProjectName := sanitizePath(graph.ProjectName)
	filename := fmt.Sprintf("%s_tree_%s.html", sanitizedProjectName, rawFileTime)
	relPath := filepath.Join(targetSubDir, filename)
	reportPath := filepath.Join("reports", relPath)

	f, err := root.Create(relPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	htmlTemplate := `<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>ReconSR Tree - {{PROJECT_NAME}}</title>
    <style>
        body {
            background-color: #0f172a;
            color: #e2e8f0;
            margin: 0;
            padding: 20px;
            font-family: sans-serif;
            height: 100vh;
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
        }
        .brand {
            color: #f8fafc;
            font-weight: 800;
            font-size: 1.4rem;
            letter-spacing: 0.05rem;
            margin-bottom: 2px;
            display: flex;
            align-items: center;
            flex-shrink: 0;
        }
        .brand::before {
            content: "";
            display: inline-block;
            width: 12px;
            height: 12px;
            background: #38bdf8;
            margin-right: 10px;
            border-radius: 2px;
        }
        .header-title {
            color: #38bdf8;
            margin: 0 0 5px 0;
            font-size: 1.1rem;
            font-weight: 400;
            flex-shrink: 0;
        }
        .meta {
            color: #94a3b8;
            font-size: 0.8rem;
            margin-bottom: 20px;
            flex-shrink: 0;
            line-height: 1.5;
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        .stats-details {
            display: inline-block;
            cursor: pointer;
            user-select: none;
            position: relative;
        }
        .stats-details summary {
            outline: none;
            color: #cbd5e1;
        }
        .stats-details summary:hover {
            color: #f8fafc;
        }
        .stats-dropdown {
            position: absolute;
            top: 100%;
            left: 0;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 4px;
            padding: 10px;
            margin-top: 5px;
            z-index: 10;
            min-width: 250px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            column-width: 180px;
            column-gap: 8px;
        }
        .stat-item {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            color: #cbd5e1;
            background: #0f172a;
            padding: 4px 8px;
            border-radius: 4px;
            break-inside: avoid-column;
            page-break-inside: avoid;
            margin-bottom: 8px;
        }
        .stat-count {
            color: #38bdf8;
            font-weight: bold;
        }
        .tree-container {
            background-color: #1e293b;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #334155;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: auto;
            width: 100%;
            box-sizing: border-box;
            flex-grow: 1;
        }
        pre {
            margin: 0;
            font-family: monospace;
            line-height: 1.3;
            font-size: 0.95rem;
            white-space: pre;
        }
    </style>
</head>
<body>
    <div class="brand">ReconSR</div>
    	<h1 class="header-title">{{LBL_PROJECT}}: {{PROJECT_NAME}}</h1>
        <div class="meta">
            <div>{{LBL_GENERATED}}: {{TIMESTAMP}}</div>
            <div style="display: flex; gap: 15px;">
                <details class="stats-details">
                    <summary>{{LBL_NODES}}: {{NODES_COUNT}}</summary>
                    <div class="stats-dropdown" style="width: 400px;">
                        {{NODES_LIST}}
                    </div>
                </details>
                <details class="stats-details">
                    <summary>{{LBL_PROPERTIES}}: {{PROPS_COUNT}}</summary>
                <div class="stats-dropdown" style="width: 400px;">
                    {{PROPS_LIST}}
                </div>
            </details>
        </div>
    </div>

    <div class="tree-container">
<pre>
`
	timestamp := now.Format("2006-01-02 15:04:05")

	propsCount := 0
	propStats := make(map[string]int)

	for _, n := range graph.Nodes {
		if n.Category == "property" {
			propsCount++
			propStats[n.Type]++
		}
	}

	nodesMap := make(map[string]bool, len(graph.Nodes))
	nodeStatsFiltered := make(map[string]int)

	for _, edge := range graph.Edges {
		srcNode := graph.Nodes[edge.SourceID]
		dstNode := graph.Nodes[edge.TargetID]

		if srcNode.Category != "" && srcNode.Category != "property" && !nodesMap[edge.SourceID] {
			nodesMap[edge.SourceID] = true
			nodeStatsFiltered[srcNode.Type]++
		}

		if dstNode.Category != "" && dstNode.Category != "property" && !nodesMap[edge.TargetID] {
			nodesMap[edge.TargetID] = true
			nodeStatsFiltered[dstNode.Type]++
		}
	}

	for id, n := range graph.Nodes {
		if n.Category != "property" && !nodesMap[id] {
			nodesMap[id] = true
			nodeStatsFiltered[n.Type]++
		}
	}

	nodesCount := len(nodesMap)

	nodeKeys := make([]string, 0, len(nodeStatsFiltered))
	hasInvalidNode := false
	for t := range nodeStatsFiltered {
		if t == "invalid" {
			hasInvalidNode = true
		} else {
			nodeKeys = append(nodeKeys, t)
		}
	}
	slices.Sort(nodeKeys)
	if hasInvalidNode {
		nodeKeys = append(nodeKeys, "invalid")
	}

	var nodesListBuilder strings.Builder
	for _, t := range nodeKeys {
		count := nodeStatsFiltered[t]
		fmt.Fprintf(&nodesListBuilder, `<div class="stat-item"><span style="text-transform: capitalize;">%s</span><span class="stat-count">%d</span></div>`, html.EscapeString(t), count)
	}

	propKeys := make([]string, 0, len(propStats))
	hasInvalidProp := false
	for t := range propStats {
		if t == "invalid" {
			hasInvalidProp = true
		} else {
			propKeys = append(propKeys, t)
		}
	}
	slices.Sort(propKeys)
	if hasInvalidProp {
		propKeys = append(propKeys, "invalid")
	}

	var propsListBuilder strings.Builder
	for _, t := range propKeys {
		count := propStats[t]
		fmt.Fprintf(&propsListBuilder, `<div class="stat-item"><span style="text-transform: capitalize;">%s</span><span class="stat-count">%d</span></div>`, html.EscapeString(t), count)
	}

	replacer := strings.NewReplacer(
		"{{LBL_PROJECT}}", i18n.T["LBL_PROJECT"],
		"{{LBL_GENERATED}}", i18n.T["LBL_GENERATED"],
		"{{LBL_NODES}}", i18n.T["LBL_NODES"],
		"{{LBL_PROPERTIES}}", i18n.T["LBL_PROPERTIES"],
		"{{PROJECT_NAME}}", html.EscapeString(graph.ProjectName),
		"{{TIMESTAMP}}", timestamp,
		"{{NODES_COUNT}}", strconv.Itoa(nodesCount),
		"{{PROPS_COUNT}}", strconv.Itoa(propsCount),
		"{{NODES_LIST}}", nodesListBuilder.String(),
		"{{PROPS_LIST}}", propsListBuilder.String(),
	)

	fmt.Fprint(f, replacer.Replace(htmlTemplate))

	RenderResultsTree(f, graph, &HTMLTreeFormatter{})

	fmt.Fprint(f, "</pre>\n    </div>\n    <script>\n        document.addEventListener('click', function(e) {\n            const clicked = e.target.closest('details.stats-details');\n            document.querySelectorAll('details.stats-details').forEach(d => {\n                if (d !== clicked) d.removeAttribute('open');\n            });\n        });\n    </script>\n</body>\n</html>\n")

	return reportPath, nil
}

// FormatNoRelations returns the message when graph has no edges.
func (h *HTMLTreeFormatter) FormatNoRelations() string {
	return htmlSpanYellow + i18n.T["MSG_NO_RELATIONS_FOUND"] + htmlSpanEnd
}

// FormatHeader returns the formatted project header.
func (h *HTMLTreeFormatter) FormatHeader(projectName string) string {
	return ""
}

// FormatTotalEntities returns the total entities count string.
func (h *HTMLTreeFormatter) FormatTotalEntities(count int) string {
	return ""
}

// FormatCategoryHeader returns the header for an entity category.
func (h *HTMLTreeFormatter) FormatCategoryHeader(category string, total int) string {
	return ""
}

// FormatCategoryStat returns a single statistic line.
func (h *HTMLTreeFormatter) FormatCategoryStat(itemType string, count int) string {
	return ""
}

// FormatCategoryFooter returns the footer for an entity category.
func (h *HTMLTreeFormatter) FormatCategoryFooter() string {
	return ""
}

// FormatNode formats a standard entity node.
func (h *HTMLTreeFormatter) FormatNode(prefix, marker, nodeType string, subtypes []string, value, connInfo string, isOutOfScope, isLimitReached, isSeen bool) string {
	var b strings.Builder

	b.WriteString(prefix)

	if marker != "" {
		b.WriteString(marker)
		b.WriteByte(' ')
	}

	if nodeType != "" {
		if nodeType == "invalid" {
			b.WriteString("[" + htmlSpanRed + i18n.T["LBL_INVALID"] + htmlSpanEnd + "] ")
		} else {
			b.WriteString("[" + htmlSpanCyan + strings.ToUpper(html.EscapeString(nodeType)) + htmlSpanEnd + "]")
			for _, st := range subtypes {
				b.WriteByte('[')
				b.WriteString(htmlSpanCyan)
				b.WriteString(strings.ToUpper(html.EscapeString(st)))
				b.WriteString(htmlSpanEnd)
				b.WriteByte(']')
			}
			b.WriteByte(' ')
		}
	}

	nodeColor := htmlSpanGreenB
	if isOutOfScope {
		nodeColor = htmlSpanBlue
	} else if isLimitReached {
		nodeColor = htmlSpanYellowB
	} else if isSeen {
		nodeColor = htmlSpanYellow
	}

	b.WriteString(nodeColor)
	b.WriteString(html.EscapeString(value))
	b.WriteString(htmlSpanEnd)

	if connInfo != "" {
		b.WriteString(" (" + htmlSpanMagenta + html.EscapeString(connInfo) + htmlSpanEnd + ")")
	}

	if isOutOfScope {
		b.WriteString(" " + htmlSpanBlue + i18n.T["LBL_OUT_OF_SCOPE"] + htmlSpanEnd)
	} else if isLimitReached {
		b.WriteString(" " + htmlSpanYellow + i18n.T["LBL_LIMIT_REACHED"] + htmlSpanEnd)
	}

	if isSeen {
		b.WriteString(" " + htmlSpanCyan + "(" + i18n.T["LBL_SEEN"] + ")" + htmlSpanEnd)
	}

	return b.String()
}

// FormatProperty formats an entity property node.
func (h *HTMLTreeFormatter) FormatProperty(basePrefix, startChar, propIndent, propType string, subtypes []string, value, connInfo string, isOutOfScope, isSeen bool) string {
	var b strings.Builder

	b.WriteString(basePrefix)
	b.WriteString(startChar)
	b.WriteString(propIndent)
	b.WriteString("• [")

	if propType == "invalid" {
		b.WriteString(htmlSpanRed + i18n.T["LBL_INVALID"] + htmlSpanEnd + "] [")
	} else {
		b.WriteString(htmlSpanYellow + strings.ToUpper(html.EscapeString(propType)) + htmlSpanEnd + "]")
		for _, st := range subtypes {
			b.WriteByte('[')
			b.WriteString(htmlSpanYellow)
			b.WriteString(strings.ToUpper(html.EscapeString(st)))
			b.WriteString(htmlSpanEnd)
			b.WriteByte(']')
		}
		b.WriteString(" [")
	}

	if isOutOfScope {
		b.WriteString(htmlSpanBlue)
	}
	b.WriteString(html.EscapeString(value))
	if isOutOfScope {
		b.WriteString(htmlSpanEnd)
	}
	b.WriteString("]")

	if connInfo != "" {
		b.WriteString(" (" + htmlSpanMagenta + html.EscapeString(connInfo) + htmlSpanEnd + ")")
	}

	if isOutOfScope {
		b.WriteString(" " + htmlSpanBlue + i18n.T["LBL_OUT_OF_SCOPE"] + htmlSpanEnd)
	}

	if isSeen {
		b.WriteString(" " + htmlSpanCyan + "(" + i18n.T["LBL_SEEN"] + ")" + htmlSpanEnd)
	}

	return b.String()
}
