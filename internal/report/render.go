package report

import (
	"cdua-org/ReconSR/internal/i18n"
	"cdua-org/ReconSR/schema"
	"fmt"
)

// RenderResultsTree draws an ASCII representation of the project findings.
func RenderResultsTree(graph *schema.ProjectGraph) {
	if len(graph.Edges) == 0 {
		fmt.Println(colorYellow + "No relations found." + colorReset)
		return
	}

	nodes := make(map[string]bool)
	stats := make(map[string]int)
	for _, edge := range graph.Edges {
		src := edge.Source.Type + ":" + edge.Source.Value
		dst := edge.Target.Type + ":" + edge.Target.Value
		if !nodes[src] {
			nodes[src] = true
			stats[edge.Source.Type]++
		}
		if !nodes[dst] {
			nodes[dst] = true
			stats[edge.Target.Type]++
		}
	}

	fmt.Printf("\n"+colorCyan+colorBold+"--- %s: %s ---"+colorReset+"\n", i18n.T["LBL_RESULTS_FOR"], graph.ProjectName)
	if len(nodes) > 0 {
		fmt.Printf(colorCyan+"Total entities: %d"+colorReset+"\n", len(nodes))
		for t, count := range stats {
			fmt.Printf("  - %s: %d\n", t, count)
		}
	}
	fmt.Println()

	// 1. Build adjacency map and group contexts chronologically
	adj := make(map[string][]schema.GraphEdge)

	type contextGroup struct {
		context   string
		firstSeen string
		lastSeen  string
	}
	type edgeKey struct {
		src string
		dst string
		mod string
		fn  string
	}
	edgeGroups := make(map[edgeKey][]contextGroup)
	edgeBase := make(map[edgeKey]schema.GraphEdge)

	for _, edge := range graph.Edges {
		key := edgeKey{
			src: edge.Source.Value,
			dst: edge.Target.Value,
			mod: edge.ModuleName,
			fn:  edge.FunctionName,
		}

		if _, exists := edgeBase[key]; !exists {
			edgeBase[key] = edge
		}

		dateStr := edge.CreatedAt
		if len(dateStr) >= 10 {
			dateStr = dateStr[:10] // Extract YYYY-MM-DD
		}

		groups := edgeGroups[key]
		if len(groups) > 0 && groups[len(groups)-1].context == edge.Context {
			// Same context as the last one, update lastSeen
			groups[len(groups)-1].lastSeen = dateStr
		} else {
			// New context or first time seeing this edge
			groups = append(groups, contextGroup{
				context:   edge.Context,
				firstSeen: dateStr,
				lastSeen:  dateStr,
			})
		}
		edgeGroups[key] = groups
	}

	for key, groups := range edgeGroups {
		baseEdge := edgeBase[key]

		var formattedContexts []string
		for _, g := range groups {
			timeStr := fmt.Sprintf("[%s]", g.firstSeen)
			if g.firstSeen != g.lastSeen {
				timeStr = fmt.Sprintf("[%s - %s]", g.firstSeen, g.lastSeen)
			}

			if g.context != "" {
				formattedContexts = append(formattedContexts, fmt.Sprintf("%s %s", timeStr, g.context))
			} else {
				formattedContexts = append(formattedContexts, timeStr) // No context, just time
			}
		}

		// Re-use existing separator for backwards compatibility in UI, but now with time
		finalContext := ""
		for i, fc := range formattedContexts {
			if i > 0 {
				finalContext += " | "
			}
			finalContext += fc
		}
		baseEdge.Context = finalContext
		adj[baseEdge.Source.Value] = append(adj[baseEdge.Source.Value], baseEdge)
	}

	// 2. Start recursion from initial target
	visited := make(map[string]bool)
	printNode(graph.InitialTarget, false, "", true, adj, visited)
}

func printNode(value string, isOutOfScope bool, prefix string, isLast bool, adj map[string][]schema.GraphEdge, visited map[string]bool) {
	nodeColor := colorGreen + colorBold
	suffix := ""
	if isOutOfScope {
		nodeColor = colorBlue
		suffix = " " + i18n.T["LBL_OUT_OF_SCOPE"]
	}
	fmt.Println(nodeColor + value + colorReset + suffix)
	visited[value] = true

	children := adj[value]
	for i, child := range children {
		isChildLast := i == len(children)-1

		marker := "├──"
		if isChildLast {
			marker = "└──"
		}

		connInfo := child.FunctionName
		if child.Context != "" {
			connInfo = fmt.Sprintf("%s, %s", child.Context, child.FunctionName)
		}

		fmt.Printf("%s%s (%s)\n", prefix, marker, colorMagenta+connInfo+colorReset)

		target := child.Target.Value
		targetPrefix := prefix
		if !isChildLast {
			targetPrefix += "│   "
		} else {
			targetPrefix += "    "
		}

		if child.TargetOutOfScope {
			fmt.Printf("%s└── ➔ %s %s\n", targetPrefix, colorBlue+target+colorReset, i18n.T["LBL_OUT_OF_SCOPE"])
		} else if visited[target] {
			fmt.Printf("%s└── ➔ %s (seen)\n", targetPrefix, colorYellow+target+colorReset)
		} else {
			fmt.Printf("%s└── ➔ ", targetPrefix)
			printNode(target, child.TargetOutOfScope, targetPrefix+"      ", isChildLast, adj, visited)
		}
	}
	if prefix == "" {
		fmt.Println() // Space after root groups
	}
}
