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
		targetNode := graph.Nodes[edge.TargetID]
		if targetNode.Category == "property" {
			srcID := edge.SourceID
			dstID := edge.TargetID

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
		targetNode := graph.Nodes[edge.TargetID]
		if targetNode.Category == "property" {
			srcID := edge.SourceID
			dstID := edge.TargetID
			pk := propKey{parentID: srcID, propID: dstID}
			if !addedProps[pk] {
				addedProps[pk] = true
				details := propDetails[pk]
				nodeProperties[srcID] = append(nodeProperties[srcID], propertyInfo{
					ID:         dstID,
					Type:       targetNode.Type,
					Value:      targetNode.Value,
					Context:    strings.Join(details, " | "),
					OutOfScope: targetNode.OutOfScope,
				})
			}
		}
	}

	nodes := make(map[string]bool)
	statsByCat := make(map[string]map[string]int)
	totalsByCat := make(map[string]int)

	for _, edge := range graph.Edges {
		src := edge.SourceID
		dst := edge.TargetID

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

		srcNode := graph.Nodes[src]
		dstNode := graph.Nodes[dst]
		processEntity(src, srcNode.Type, srcNode.Category)
		processEntity(dst, dstNode.Type, dstNode.Category)
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
	adj := make(map[string][]schema.EdgeData)

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
	edgeBase := make(map[nodeEdgeKey]schema.EdgeData)

	for _, edge := range graph.Edges {
		targetNode := graph.Nodes[edge.TargetID]
		if targetNode.Category == "property" {
			continue
		}

		srcID := edge.SourceID
		dstID := edge.TargetID

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
		targetNode := graph.Nodes[edge.TargetID]
		if targetNode.Category == "property" {
			continue
		}

		srcID := edge.SourceID
		dstID := edge.TargetID

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
		srcNode := graph.Nodes[edge.SourceID]
		if srcNode.Value == graph.InitialTarget {
			initialTargetID = edge.SourceID
			initialTargetType = srcNode.Type
			break
		}
	}

	if initialTargetID == "" {
		initialTargetID = "unknown:" + graph.InitialTarget
		initialTargetType = "unknown"
	}

	initialOutOfScope := false
	initialLimitReached := false
	if n, ok := graph.Nodes[initialTargetID]; ok {
		initialOutOfScope = n.OutOfScope
		d := n.DepthRelaxed
		if graph.StrictDepth {
			d = n.DepthStrict
		}
		initialLimitReached = d > graph.MaxDepth
	}

	visited := make(map[string]bool)
	printNode(initialTargetID, graph.InitialTarget, initialTargetType, initialOutOfScope, initialLimitReached, "", "", "", true, adj, visited, nodeProperties, graph)
}

func printNode(nodeID string, value string, nodeType string, isOutOfScope bool, isLimitReached bool, prefix string, marker string, connInfo string, isLast bool, adj map[string][]schema.EdgeData, visited map[string]bool, nodeProperties map[string][]propertyInfo, graph *schema.ProjectGraph) {
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

	printProperties(nodeID, childPrefix, hasChildren, "", nodeProperties, adj, visited, graph)

	visited[nodeID] = true

	printChildren(children, childPrefix, adj, visited, nodeProperties, graph)

	if prefix == "" && marker == "" {
		fmt.Println()
	}
}

func printProperties(nodeID string, basePrefix string, hasChildren bool, propIndent string, nodeProperties map[string][]propertyInfo, adj map[string][]schema.EdgeData, visited map[string]bool, graph *schema.ProjectGraph) {
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

		printProperties(prop.ID, basePrefix, hasChildren, nextPropIndent, nodeProperties, adj, visited, graph)

		if len(propChildren) > 0 {
			propChildPrefix := basePrefix + startChar + propIndent + "  "
			printChildren(propChildren, propChildPrefix, adj, visited, nodeProperties, graph)
		}
	}
}

func printChildren(children []schema.EdgeData, childPrefix string, adj map[string][]schema.EdgeData, visited map[string]bool, nodeProperties map[string][]propertyInfo, graph *schema.ProjectGraph) {
	if len(children) == 0 {
		return
	}

	isLimitReached := func(id string) bool {
		n, exists := graph.Nodes[id]
		if !exists {
			return false
		}
		d := n.DepthRelaxed
		if graph.StrictDepth {
			d = n.DepthStrict
		}
		return d > graph.MaxDepth
	}

	sort.Slice(children, func(i, j int) bool {
		score := func(child schema.EdgeData) int {
			targetNode := graph.Nodes[child.TargetID]
			if targetNode.OutOfScope {
				return 3
			}
			targetID := child.TargetID
			if visited[targetID] {
				return 2
			}
			if isLimitReached(targetID) {
				return 1
			}
			return 0
		}
		scoreI := score(children[i])
		scoreJ := score(children[j])
		if scoreI != scoreJ {
			return scoreI < scoreJ
		}
		return graph.Nodes[children[i].TargetID].Value < graph.Nodes[children[j].TargetID].Value
	})

	for i, child := range children {
		isChildLast := i == len(children)-1

		childMarker := "├──"
		if isChildLast {
			childMarker = "└──"
		}

		targetNode := graph.Nodes[child.TargetID]
		targetValue := targetNode.Value
		targetType := targetNode.Type
		targetID := child.TargetID

		targetTypeStr := ""
		if targetType != "" {
			if targetType == "invalid" {
				targetTypeStr = fmt.Sprintf("[%s%s%s] ", colorRed, strings.ToUpper(targetType), colorReset)
			} else {
				targetTypeStr = fmt.Sprintf("[%s%s%s] ", colorCyan, strings.ToUpper(targetType), colorReset)
			}
		}

		if visited[targetID] {
			childConn := child.Context
			formattedChildConn := ""
			if childConn != "" {
				formattedChildConn = fmt.Sprintf(" (%s%s%s)", colorMagenta, childConn, colorReset)
			}
			nodeColor := colorYellow
			suffix := ""
			if targetNode.OutOfScope {
				nodeColor = colorBlue
				suffix = " " + colorBlue + i18n.T["LBL_OUT_OF_SCOPE"] + colorReset
			} else if isLimitReached(targetID) {
				nodeColor = colorYellow + colorBold
				suffix = " " + colorYellow + i18n.T["LBL_LIMIT_REACHED"] + colorReset
			}
			suffix += " " + colorCyan + "(seen)" + colorReset
			fmt.Printf("%s%s %s%s%s%s\n", childPrefix, childMarker, targetTypeStr, nodeColor+targetValue+colorReset, formattedChildConn, suffix)
		} else {
			printNode(targetID, targetValue, targetType, targetNode.OutOfScope, isLimitReached(targetID), childPrefix, childMarker, child.Context, isChildLast, adj, visited, nodeProperties, graph)
		}
	}
}
