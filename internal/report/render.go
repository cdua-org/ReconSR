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

	// 1. Build adjacency map
	adj := make(map[string][]schema.GraphEdge)
	edgeMap := make(map[string]*schema.GraphEdge)

	for _, edge := range graph.Edges {
		edgeKey := fmt.Sprintf("%s|%s|%s|%s", edge.Source.Value, edge.Target.Value, edge.ModuleName, edge.FunctionName)

		if existing, ok := edgeMap[edgeKey]; ok {
			if edge.Context != "" && existing.Context != "" {
				if existing.Context != edge.Context {
					existing.Context = existing.Context + " | " + edge.Context
				}
			} else if edge.Context != "" {
				existing.Context = edge.Context
			}
		} else {
			newEdge := edge
			edgeMap[edgeKey] = &newEdge
		}
	}

	for _, edgePtr := range edgeMap {
		adj[edgePtr.Source.Value] = append(adj[edgePtr.Source.Value], *edgePtr)
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
