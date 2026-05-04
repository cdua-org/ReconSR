package report

import (
	"cdua-org/ReconSR/internal/i18n"
	"cdua-org/ReconSR/schema"
	"fmt"
	"sort"
	"strings"
)

type propertyInfo struct {
	Type       string
	Value      string
	Context    string
	OutOfScope bool
}

// RenderResultsTree draws an ASCII representation of the project findings.
func RenderResultsTree(graph *schema.ProjectGraph) {
	if len(graph.Edges) == 0 {
		fmt.Println(colorYellow + "No relations found." + colorReset)
		return
	}

	type contextGroup struct {
		context   string
		firstSeen string
		lastSeen  string
	}

	propToParent := make(map[string]string)

	type propKey struct {
		parent string
		pType  string
		pValue string
	}
	type propEdgeKey struct {
		parent string
		pType  string
		pValue string
		fn     string
	}
	propEdgeGroups := make(map[propEdgeKey][]contextGroup)
	propDetails := make(map[propKey][]string)

	for _, edge := range graph.Edges {
		if edge.Target.Category == "property" {
			propToParent[edge.Target.Value] = edge.Source.Value

			key := propEdgeKey{
				parent: edge.Source.Value,
				pType:  edge.Target.Type,
				pValue: edge.Target.Value,
				fn:     edge.FunctionName,
			}
			dateStr := edge.CreatedAt
			if len(dateStr) >= 10 {
				dateStr = dateStr[:10]
			}

			groups := propEdgeGroups[key]
			if len(groups) > 0 && groups[len(groups)-1].context == edge.Context {
				groups[len(groups)-1].lastSeen = dateStr
			} else {
				groups = append(groups, contextGroup{
					context:   edge.Context,
					firstSeen: dateStr,
					lastSeen:  dateStr,
				})
			}
			propEdgeGroups[key] = groups
		}
	}

	for key, groups := range propEdgeGroups {
		timeGroups := make(map[string][]string)
		var timeOrder []string

		for _, g := range groups {
			timeStr := fmt.Sprintf("[%s]", g.firstSeen)
			if g.firstSeen != g.lastSeen {
				timeStr = fmt.Sprintf("[%s - %s]", g.firstSeen, g.lastSeen)
			}
			if _, exists := timeGroups[timeStr]; !exists {
				timeOrder = append(timeOrder, timeStr)
			}
			if g.context != "" {
				ctxExists := false
				for _, existingCtx := range timeGroups[timeStr] {
					if existingCtx == g.context {
						ctxExists = true
						break
					}
				}
				if !ctxExists {
					timeGroups[timeStr] = append(timeGroups[timeStr], g.context)
				}
			}
		}

		var formattedContexts []string
		for _, tStr := range timeOrder {
			ctxs := timeGroups[tStr]
			if len(ctxs) > 0 {
				formattedContexts = append(formattedContexts, fmt.Sprintf("%s %s, %s", tStr, strings.Join(ctxs, " | "), key.fn))
			} else {
				formattedContexts = append(formattedContexts, fmt.Sprintf("%s %s", tStr, key.fn))
			}
		}

		pk := propKey{parent: key.parent, pType: key.pType, pValue: key.pValue}
		propDetails[pk] = append(propDetails[pk], formattedContexts...)
	}

	nodeProperties := make(map[string][]propertyInfo)
	addedProps := make(map[propKey]bool)

	for _, edge := range graph.Edges {
		if edge.Target.Category == "property" {
			pk := propKey{parent: edge.Source.Value, pType: edge.Target.Type, pValue: edge.Target.Value}
			if !addedProps[pk] {
				addedProps[pk] = true
				details := propDetails[pk]
				nodeProperties[edge.Source.Value] = append(nodeProperties[edge.Source.Value], propertyInfo{
					Type:       edge.Target.Type,
					Value:      edge.Target.Value,
					Context:    strings.Join(details, " | "),
					OutOfScope: edge.TargetOutOfScope,
				})
			}
		}
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

	adj := make(map[string][]schema.GraphEdge)

	type nodeEdgeKey struct {
		src string
		dst string
	}
	type nodeEdgeGroupKey struct {
		src string
		dst string
		fn  string
	}
	nodeEdgeGroups := make(map[nodeEdgeGroupKey][]contextGroup)
	edgeBase := make(map[nodeEdgeKey]schema.GraphEdge)

	for _, edge := range graph.Edges {
		if edge.Target.Category == "property" {
			continue
		}

		for {
			if parentVal, isProp := propToParent[edge.Source.Value]; isProp {
				edge.Source.Value = parentVal
			} else {
				break
			}
		}

		key := nodeEdgeGroupKey{
			src: edge.Source.Value,
			dst: edge.Target.Value,
			fn:  edge.FunctionName,
		}

		nk := nodeEdgeKey{src: key.src, dst: key.dst}
		if _, exists := edgeBase[nk]; !exists {
			edgeBase[nk] = edge
		}

		dateStr := edge.CreatedAt
		if len(dateStr) >= 10 {
			dateStr = dateStr[:10]
		}

		groups := nodeEdgeGroups[key]
		if len(groups) > 0 && groups[len(groups)-1].context == edge.Context {
			groups[len(groups)-1].lastSeen = dateStr
		} else {
			groups = append(groups, contextGroup{
				context:   edge.Context,
				firstSeen: dateStr,
				lastSeen:  dateStr,
			})
		}
		nodeEdgeGroups[key] = groups
	}

	nodeEdgeDetails := make(map[nodeEdgeKey][]string)

	for key, groups := range nodeEdgeGroups {
		timeGroups := make(map[string][]string)
		var timeOrder []string

		for _, g := range groups {
			timeStr := fmt.Sprintf("[%s]", g.firstSeen)
			if g.firstSeen != g.lastSeen {
				timeStr = fmt.Sprintf("[%s - %s]", g.firstSeen, g.lastSeen)
			}
			if _, exists := timeGroups[timeStr]; !exists {
				timeOrder = append(timeOrder, timeStr)
			}
			if g.context != "" {
				ctxExists := false
				for _, existingCtx := range timeGroups[timeStr] {
					if existingCtx == g.context {
						ctxExists = true
						break
					}
				}
				if !ctxExists {
					timeGroups[timeStr] = append(timeGroups[timeStr], g.context)
				}
			}
		}

		var formattedContexts []string
		for _, tStr := range timeOrder {
			ctxs := timeGroups[tStr]
			if len(ctxs) > 0 {
				formattedContexts = append(formattedContexts, fmt.Sprintf("%s %s, %s", tStr, strings.Join(ctxs, " | "), key.fn))
			} else {
				formattedContexts = append(formattedContexts, fmt.Sprintf("%s %s", tStr, key.fn))
			}
		}

		nk := nodeEdgeKey{src: key.src, dst: key.dst}
		nodeEdgeDetails[nk] = append(nodeEdgeDetails[nk], formattedContexts...)
	}

	addedEdges := make(map[nodeEdgeKey]bool)
	for _, edge := range graph.Edges {
		if edge.Target.Category == "property" {
			continue
		}

		for {
			if parentVal, isProp := propToParent[edge.Source.Value]; isProp {
				edge.Source.Value = parentVal
			} else {
				break
			}
		}

		nk := nodeEdgeKey{src: edge.Source.Value, dst: edge.Target.Value}
		if !addedEdges[nk] {
			addedEdges[nk] = true
			baseEdge := edgeBase[nk]
			baseEdge.Context = strings.Join(nodeEdgeDetails[nk], " | ")
			adj[nk.src] = append(adj[nk.src], baseEdge)
		}
	}

	nodeTypes := make(map[string]string)
	for _, edge := range graph.Edges {
		nodeTypes[edge.Source.Value] = edge.Source.Type
		nodeTypes[edge.Target.Value] = edge.Target.Type
	}

	visited := make(map[string]bool)
	printNode(graph.InitialTarget, nodeTypes[graph.InitialTarget], false, "", "", "", true, adj, visited, nodeProperties)
}

func printNode(value string, nodeType string, isOutOfScope bool, prefix string, marker string, connInfo string, isLast bool, adj map[string][]schema.GraphEdge, visited map[string]bool, nodeProperties map[string][]propertyInfo) {
	nodeColor := colorGreen + colorBold
	suffix := ""
	if isOutOfScope {
		nodeColor = colorBlue
		suffix = " " + i18n.T["LBL_OUT_OF_SCOPE"]
	}

	formattedConn := ""
	if connInfo != "" {
		formattedConn = fmt.Sprintf(" (%s%s%s)", colorMagenta, connInfo, colorReset)
	}

	typeStr := ""
	if nodeType != "" {
		if nodeType == "invalid" {
			typeStr = fmt.Sprintf("[%s%s%s] ", colorRed, strings.ToUpper(nodeType), colorReset)
		} else {
			typeStr = fmt.Sprintf("[%s%s%s] ", colorCyan, strings.ToUpper(nodeType), colorReset)
		}
	}

	if marker != "" {
		fmt.Printf("%s%s %s%s%s%s\n", prefix, marker, typeStr, nodeColor+value+colorReset, formattedConn, suffix)
	} else {
		// Root node
		fmt.Printf("%s%s%s%s%s\n", prefix, typeStr, nodeColor+value+colorReset, formattedConn, suffix)
	}

	childPrefix := prefix
	if marker != "" {
		if !isLast {
			childPrefix += "│   "
		} else {
			childPrefix += "    "
		}
	}

	children := adj[value]
	hasChildren := len(children) > 0

	printProperties(value, childPrefix, hasChildren, "", nodeProperties)

	visited[value] = true

	sort.Slice(children, func(i, j int) bool {
		if !children[i].TargetOutOfScope && children[j].TargetOutOfScope {
			return true
		}
		if children[i].TargetOutOfScope && !children[j].TargetOutOfScope {
			return false
		}
		return children[i].Target.Value < children[j].Target.Value
	})

	for i, child := range children {
		isChildLast := i == len(children)-1

		childMarker := "├──"
		if isChildLast {
			childMarker = "└──"
		}

		target := child.Target.Value
		targetType := child.Target.Type

		targetTypeStr := ""
		if targetType != "" {
			if targetType == "invalid" {
				targetTypeStr = fmt.Sprintf("[%s%s%s] ", colorRed, strings.ToUpper(targetType), colorReset)
			} else {
				targetTypeStr = fmt.Sprintf("[%s%s%s] ", colorCyan, strings.ToUpper(targetType), colorReset)
			}
		}

		if child.TargetOutOfScope {
			childConn := child.Context
			formattedChildConn := ""
			if childConn != "" {
				formattedChildConn = fmt.Sprintf(" (%s%s%s)", colorMagenta, childConn, colorReset)
			}
			fmt.Printf("%s%s %s%s%s %s\n", childPrefix, childMarker, targetTypeStr, colorBlue+target+colorReset, formattedChildConn, i18n.T["LBL_OUT_OF_SCOPE"])
		} else if visited[target] {
			childConn := child.Context
			formattedChildConn := ""
			if childConn != "" {
				formattedChildConn = fmt.Sprintf(" (%s%s%s)", colorMagenta, childConn, colorReset)
			}
			fmt.Printf("%s%s %s%s%s (seen)\n", childPrefix, childMarker, targetTypeStr, colorYellow+target+colorReset, formattedChildConn)
		} else {
			printNode(target, targetType, child.TargetOutOfScope, childPrefix, childMarker, child.Context, isChildLast, adj, visited, nodeProperties)
		}
	}
	if prefix == "" && marker == "" {
		fmt.Println()
	}
}

func printProperties(value string, basePrefix string, hasChildren bool, propIndent string, nodeProperties map[string][]propertyInfo) {
	props := nodeProperties[value]
	if len(props) > 1 {
		sort.Slice(props, func(i, j int) bool {
			if !props[i].OutOfScope && props[j].OutOfScope {
				return true
			}
			if props[i].OutOfScope && !props[j].OutOfScope {
				return false
			}
			return props[i].Type+props[i].Value < props[j].Type+props[j].Value
		})
	}

	for _, prop := range props {
		contextStr := ""
		if prop.Context != "" {
			contextStr = fmt.Sprintf(" (%s%s%s)", colorMagenta, prop.Context, colorReset)
		}

		startChar := "  "
		if hasChildren {
			startChar = "│ "
		}

		valColor := ""
		suffix := ""
		if prop.OutOfScope {
			valColor = colorBlue
			suffix = " " + i18n.T["LBL_OUT_OF_SCOPE"]
		}

		typeColor := colorYellow
		if prop.Type == "invalid" {
			typeColor = colorRed
		}

		fmt.Printf("%s%s%s• [%s%s%s] [%s%s%s]%s%s\n", basePrefix, startChar, propIndent, typeColor, strings.ToUpper(prop.Type), colorReset, valColor, prop.Value, colorReset, contextStr, suffix)
		printProperties(prop.Value, basePrefix, hasChildren, propIndent+"  ", nodeProperties)
	}
}
