package report

import (
	"cdua-org/ReconSR/internal/i18n"
	"cdua-org/ReconSR/schema"
	"fmt"
	"sort"
	"strings"
)

type propertyInfo struct {
	ID         string
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

	type propKey struct {
		parentID string
		propID   string
	}
	type propEdgeKey struct {
		parentID string
		propID   string
		fn       string
	}
	propEdgeGroups := make(map[propEdgeKey][]contextGroup)
	propDetails := make(map[propKey][]string)

	for _, edge := range graph.Edges {
		if edge.Target.Category == "property" {
			srcID := edge.Source.Type + ":" + edge.Source.Value
			dstID := edge.Target.Type + ":" + edge.Target.Value

			key := propEdgeKey{
				parentID: srcID,
				propID:   dstID,
				fn:       edge.FunctionName,
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

		pk := propKey{parentID: key.parentID, propID: key.propID}
		propDetails[pk] = append(propDetails[pk], formattedContexts...)
	}

	nodeProperties := make(map[string][]propertyInfo)
	addedProps := make(map[propKey]bool)

	for _, edge := range graph.Edges {
		if edge.Target.Category == "property" {
			srcID := edge.Source.Type + ":" + edge.Source.Value
			dstID := edge.Target.Type + ":" + edge.Target.Value
			pk := propKey{parentID: srcID, propID: dstID}
			if !addedProps[pk] {
				addedProps[pk] = true
				details := propDetails[pk]
				nodeProperties[srcID] = append(nodeProperties[srcID], propertyInfo{
					ID:         dstID,
					Type:       edge.Target.Type,
					Value:      edge.Target.Value,
					Context:    strings.Join(details, " | "),
					OutOfScope: edge.TargetOutOfScope,
				})
			}
		}
	}

	nodes := make(map[string]bool)
	statsByCat := make(map[string]map[string]int)
	totalsByCat := make(map[string]int)

	for _, edge := range graph.Edges {
		src := edge.Source.Type + ":" + edge.Source.Value
		dst := edge.Target.Type + ":" + edge.Target.Value

		processEntity := func(id, eType, category string) {
			if !nodes[id] {
				nodes[id] = true
				if statsByCat[category] == nil {
					statsByCat[category] = make(map[string]int)
				}
				statsByCat[category][eType]++
				totalsByCat[category]++
			}
		}

		processEntity(src, edge.Source.Type, edge.Source.Category)
		processEntity(dst, edge.Target.Type, edge.Target.Category)
	}

	fmt.Printf("\n"+colorCyan+colorBold+"--- %s: %s ---"+colorReset+"\n", i18n.T["LBL_RESULTS_FOR"], graph.ProjectName)
	if len(nodes) > 0 {
		fmt.Printf(colorCyan+"Total entities: %d"+colorReset+"\n", len(nodes))

		var catKeys []string
		for cat := range statsByCat {
			catKeys = append(catKeys, cat)
		}
		sort.Strings(catKeys)

		for _, cat := range catKeys {
			stats := statsByCat[cat]
			if len(stats) == 0 {
				continue
			}

			catTotal := totalsByCat[cat]
			var keys []string
			hasInvalid := false
			for t := range stats {
				if t == "invalid" {
					hasInvalid = true
				} else {
					keys = append(keys, t)
				}
			}
			sort.Strings(keys)
			if hasInvalid {
				keys = append(keys, "invalid")
			}

			displayCat := strings.ToUpper(cat)
			fmt.Printf("\n"+colorCyan+"%s: %d"+colorReset+"\n", displayCat, catTotal)
			for _, t := range keys {
				fmt.Printf("  - %s: %d\n", t, stats[t])
			}
		}
	}
	fmt.Println()
	adj := make(map[string][]schema.GraphEdge)

	type nodeEdgeKey struct {
		srcID string
		dstID string
	}
	type nodeEdgeGroupKey struct {
		srcID string
		dstID string
		fn    string
	}
	nodeEdgeGroups := make(map[nodeEdgeGroupKey][]contextGroup)
	edgeBase := make(map[nodeEdgeKey]schema.GraphEdge)

	for _, edge := range graph.Edges {
		if edge.Target.Category == "property" {
			continue
		}

		srcID := edge.Source.Type + ":" + edge.Source.Value
		dstID := edge.Target.Type + ":" + edge.Target.Value

		key := nodeEdgeGroupKey{
			srcID: srcID,
			dstID: dstID,
			fn:    edge.FunctionName,
		}

		nk := nodeEdgeKey{srcID: key.srcID, dstID: key.dstID}
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

		nk := nodeEdgeKey{srcID: key.srcID, dstID: key.dstID}
		nodeEdgeDetails[nk] = append(nodeEdgeDetails[nk], formattedContexts...)
	}

	addedEdges := make(map[nodeEdgeKey]bool)
	for _, edge := range graph.Edges {
		if edge.Target.Category == "property" {
			continue
		}

		srcID := edge.Source.Type + ":" + edge.Source.Value
		dstID := edge.Target.Type + ":" + edge.Target.Value

		nk := nodeEdgeKey{srcID: srcID, dstID: dstID}
		if !addedEdges[nk] {
			addedEdges[nk] = true
			baseEdge := edgeBase[nk]
			baseEdge.Context = strings.Join(nodeEdgeDetails[nk], " | ")
			adj[nk.srcID] = append(adj[nk.srcID], baseEdge)
		}
	}

	var initialTargetID string
	var initialTargetType string
	for _, edge := range graph.Edges {
		if edge.Source.Value == graph.InitialTarget {
			initialTargetID = edge.Source.Type + ":" + edge.Source.Value
			initialTargetType = edge.Source.Type
			break
		}
	}

	if initialTargetID == "" {
		initialTargetID = "unknown:" + graph.InitialTarget
		initialTargetType = "unknown"
	}

	visited := make(map[string]bool)
	printNode(initialTargetID, graph.InitialTarget, initialTargetType, false, false, "", "", "", true, adj, visited, nodeProperties)
}

func printNode(nodeID string, value string, nodeType string, isOutOfScope bool, isLimitReached bool, prefix string, marker string, connInfo string, isLast bool, adj map[string][]schema.GraphEdge, visited map[string]bool, nodeProperties map[string][]propertyInfo) {
	nodeColor := colorGreen + colorBold
	suffix := ""
	if isOutOfScope {
		nodeColor = colorBlue
		suffix = " " + colorBlue + i18n.T["LBL_OUT_OF_SCOPE"] + colorReset
	} else if isLimitReached {
		nodeColor = colorYellow + colorBold
		suffix = " " + colorYellow + i18n.T["LBL_LIMIT_REACHED"] + colorReset
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

	children := adj[nodeID]
	hasChildren := len(children) > 0

	printProperties(nodeID, childPrefix, hasChildren, "", nodeProperties, adj, visited)

	visited[nodeID] = true

	printChildren(children, childPrefix, adj, visited, nodeProperties)

	if prefix == "" && marker == "" {
		fmt.Println()
	}
}

func printProperties(nodeID string, basePrefix string, hasChildren bool, propIndent string, nodeProperties map[string][]propertyInfo, adj map[string][]schema.GraphEdge, visited map[string]bool) {
	props := nodeProperties[nodeID]
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
			suffix = " " + colorBlue + i18n.T["LBL_OUT_OF_SCOPE"] + colorReset
		}

		typeColor := colorYellow
		if prop.Type == "invalid" {
			typeColor = colorRed
		}

		fmt.Printf("%s%s%s• [%s%s%s] [%s%s%s]%s%s\n", basePrefix, startChar, propIndent, typeColor, strings.ToUpper(prop.Type), colorReset, valColor, prop.Value, colorReset, contextStr, suffix)

		propChildren := adj[prop.ID]
		nextPropIndent := propIndent + "  "
		if len(propChildren) > 0 {
			nextPropIndent = propIndent + "  │ "
		}

		printProperties(prop.ID, basePrefix, hasChildren, nextPropIndent, nodeProperties, adj, visited)

		if len(propChildren) > 0 {
			propChildPrefix := basePrefix + startChar + propIndent + "  "
			printChildren(propChildren, propChildPrefix, adj, visited, nodeProperties)
		}
	}
}

func printChildren(children []schema.GraphEdge, childPrefix string, adj map[string][]schema.GraphEdge, visited map[string]bool, nodeProperties map[string][]propertyInfo) {
	if len(children) == 0 {
		return
	}

	sort.Slice(children, func(i, j int) bool {
		score := func(child schema.GraphEdge) int {
			if child.TargetOutOfScope {
				return 3
			}
			targetID := child.Target.Type + ":" + child.Target.Value
			if visited[targetID] {
				return 2
			}
			if child.TargetDepthLimitReached {
				return 1
			}
			return 0
		}
		scoreI := score(children[i])
		scoreJ := score(children[j])
		if scoreI != scoreJ {
			return scoreI < scoreJ
		}
		return children[i].Target.Value < children[j].Target.Value
	})

	for i, child := range children {
		isChildLast := i == len(children)-1

		childMarker := "├──"
		if isChildLast {
			childMarker = "└──"
		}

		targetValue := child.Target.Value
		targetType := child.Target.Type
		targetID := targetType + ":" + targetValue

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
			fmt.Printf("%s%s %s%s%s %s\n", childPrefix, childMarker, targetTypeStr, colorBlue+targetValue+colorReset, formattedChildConn, colorBlue+i18n.T["LBL_OUT_OF_SCOPE"]+colorReset)
		} else if child.TargetDepthLimitReached {
			childConn := child.Context
			formattedChildConn := ""
			if childConn != "" {
				formattedChildConn = fmt.Sprintf(" (%s%s%s)", colorMagenta, childConn, colorReset)
			}
			fmt.Printf("%s%s %s%s%s %s\n", childPrefix, childMarker, targetTypeStr, colorYellow+colorBold+targetValue+colorReset, formattedChildConn, colorYellow+i18n.T["LBL_LIMIT_REACHED"]+colorReset)
		} else if visited[targetID] {
			childConn := child.Context
			formattedChildConn := ""
			if childConn != "" {
				formattedChildConn = fmt.Sprintf(" (%s%s%s)", colorMagenta, childConn, colorReset)
			}
			fmt.Printf("%s%s %s%s%s %s\n", childPrefix, childMarker, targetTypeStr, colorYellow+targetValue+colorReset, formattedChildConn, colorCyan+"(seen)"+colorReset)
		} else {
			printNode(targetID, targetValue, targetType, child.TargetOutOfScope, child.TargetDepthLimitReached, childPrefix, childMarker, child.Context, isChildLast, adj, visited, nodeProperties)
		}
	}
}
