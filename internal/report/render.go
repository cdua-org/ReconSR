package report

import (
	"cdua-org/ReconSR/schema"
	"fmt"
	"io"
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

type contextGroup struct {
	context   string
	firstSeen string
	lastSeen  string
}

// RenderResultsTree draws an ASCII representation of the project findings.
func RenderResultsTree(out io.Writer, graph *schema.ProjectGraph, f TreeFormatter) {
	if len(graph.Edges) == 0 {
		fmt.Fprintln(out, f.FormatNoRelations())
		return
	}

	type edgeKey struct {
		parentID string
		childID  string
	}
	type edgeGroupKey struct {
		parentID string
		childID  string
		fn       string
	}

	propEdgeGroups := make(map[edgeGroupKey][]contextGroup)
	nodeEdgeGroups := make(map[edgeGroupKey][]contextGroup)
	edgeBase := make(map[edgeKey]schema.EdgeData)

	nodes := make(map[string]bool)
	statsByCat := make(map[string]map[string]int)
	totalsByCat := make(map[string]int)

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

	addGroup := func(groups map[edgeGroupKey][]contextGroup, key edgeGroupKey, edge schema.EdgeData) {
		dateStr := edge.CreatedAt
		if len(dateStr) >= 10 {
			dateStr = dateStr[:10]
		}
		list := groups[key]
		if len(list) > 0 && list[len(list)-1].context == edge.Context {
			list[len(list)-1].lastSeen = dateStr
		} else {
			list = append(list, contextGroup{
				context:   edge.Context,
				firstSeen: dateStr,
				lastSeen:  dateStr,
			})
		}
		groups[key] = list
	}

	for _, edge := range graph.Edges {
		srcID := edge.SourceID
		dstID := edge.TargetID
		targetNode := graph.Nodes[dstID]
		srcNode := graph.Nodes[srcID]

		processEntity(srcID, srcNode.Type, srcNode.Category)
		processEntity(dstID, targetNode.Type, targetNode.Category)

		key := edgeGroupKey{
			parentID: srcID,
			childID:  dstID,
			fn:       edge.FunctionName,
		}

		if targetNode.Category == "property" {
			addGroup(propEdgeGroups, key, edge)
		} else {
			addGroup(nodeEdgeGroups, key, edge)
			nk := edgeKey{parentID: srcID, childID: dstID}
			if _, exists := edgeBase[nk]; !exists {
				edgeBase[nk] = edge
			}
		}
	}

	for id, n := range graph.Nodes {
		if n.Category != "property" {
			processEntity(id, n.Type, n.Category)
		}
	}

	propDetails := make(map[edgeKey][]string)
	for key, groups := range propEdgeGroups {
		pk := edgeKey{parentID: key.parentID, childID: key.childID}
		propDetails[pk] = append(propDetails[pk], formatContextGroups(groups, key.fn)...)
	}

	nodeEdgeDetails := make(map[edgeKey][]string)
	for key, groups := range nodeEdgeGroups {
		nk := edgeKey{parentID: key.parentID, childID: key.childID}
		nodeEdgeDetails[nk] = append(nodeEdgeDetails[nk], formatContextGroups(groups, key.fn)...)
	}

	nodeProperties := make(map[string][]propertyInfo)
	addedProps := make(map[edgeKey]bool)
	adj := make(map[string][]schema.EdgeData)
	addedEdges := make(map[edgeKey]bool)

	for _, edge := range graph.Edges {
		srcID := edge.SourceID
		dstID := edge.TargetID
		targetNode := graph.Nodes[dstID]
		ek := edgeKey{parentID: srcID, childID: dstID}

		if targetNode.Category == "property" {
			if !addedProps[ek] {
				addedProps[ek] = true
				details := propDetails[ek]
				nodeProperties[srcID] = append(nodeProperties[srcID], propertyInfo{
					ID:         dstID,
					Type:       targetNode.Type,
					Value:      targetNode.Value,
					Context:    strings.Join(details, " | "),
					OutOfScope: targetNode.OutOfScope,
				})
			}
		} else {
			if !addedEdges[ek] {
				addedEdges[ek] = true
				baseEdge := edgeBase[ek]
				baseEdge.Context = strings.Join(nodeEdgeDetails[ek], " | ")
				adj[srcID] = append(adj[srcID], baseEdge)
			}
		}
	}

	if header := f.FormatHeader(graph.ProjectName); header != "" {
		fmt.Fprintln(out, header)
	}

	if len(nodes) > 0 {
		if total := f.FormatTotalEntities(len(nodes)); total != "" {
			fmt.Fprintln(out, total)
		}

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
			if catHeader := f.FormatCategoryHeader(displayCat, catTotal); catHeader != "" {
				fmt.Fprintln(out, catHeader)
			}
			for _, t := range keys {
				if statLine := f.FormatCategoryStat(t, stats[t]); statLine != "" {
					fmt.Fprintln(out, statLine)
				}
			}
			if catFooter := f.FormatCategoryFooter(); catFooter != "" {
				fmt.Fprintln(out, catFooter)
			}
		}
	}

	if f.FormatTotalEntities(1) != "" {
		fmt.Fprintln(out)
	}

	var initialTargetID, initialTargetType string
	for id, n := range graph.Nodes {
		if n.Value == graph.InitialTarget && n.Category != "property" {
			initialTargetID = id
			initialTargetType = n.Type
			break
		}
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
	printNode(out, f, initialTargetID, graph.InitialTarget, initialTargetType, initialOutOfScope, initialLimitReached, "", "", "", true, adj, visited, nodeProperties, graph)

	inDegree := make(map[string]int)
	for _, edges := range adj {
		for _, edge := range edges {
			inDegree[edge.TargetID]++
		}
	}

	for {
		var candidates []string
		for id, n := range graph.Nodes {
			if !visited[id] && n.Category != "property" {
				candidates = append(candidates, id)
			}
		}
		if len(candidates) == 0 {
			break
		}

		sort.Slice(candidates, func(i, j int) bool {
			degI := inDegree[candidates[i]]
			degJ := inDegree[candidates[j]]
			if degI != degJ {
				return degI < degJ
			}
			return graph.Nodes[candidates[i]].Value < graph.Nodes[candidates[j]].Value
		})

		rootID := candidates[0]
		n := graph.Nodes[rootID]
		d := n.DepthRelaxed
		if graph.StrictDepth {
			d = n.DepthStrict
		}

		fmt.Fprintln(out)
		printNode(out, f, rootID, n.Value, n.Type, n.OutOfScope, d > graph.MaxDepth, "", "", "", true, adj, visited, nodeProperties, graph)
	}
}

func formatContextGroups(groups []contextGroup, fn string) []string {
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
			formattedContexts = append(formattedContexts, fmt.Sprintf("%s %s, %s", tStr, strings.Join(ctxs, " | "), fn))
		} else {
			formattedContexts = append(formattedContexts, fmt.Sprintf("%s %s", tStr, fn))
		}
	}
	return formattedContexts
}

func printNode(out io.Writer, f TreeFormatter, nodeID string, value string, nodeType string, isOutOfScope bool, isLimitReached bool, prefix string, marker string, connInfo string, isLast bool, adj map[string][]schema.EdgeData, visited map[string]bool, nodeProperties map[string][]propertyInfo, graph *schema.ProjectGraph) {
	var subtypes []string
	if n, ok := graph.Nodes[nodeID]; ok {
		subtypes = n.Subtypes
	}

	formatted := f.FormatNode(prefix, marker, nodeType, subtypes, value, connInfo, isOutOfScope, isLimitReached, false)
	fmt.Fprintln(out, formatted)

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

	printProperties(out, f, nodeID, childPrefix, hasChildren, "", nodeProperties, adj, visited, graph)

	visited[nodeID] = true

	printChildren(out, f, children, childPrefix, adj, visited, nodeProperties, graph)

	if prefix == "" && marker == "" {
		fmt.Fprintln(out)
	}
}

func printProperties(out io.Writer, f TreeFormatter, nodeID string, basePrefix string, hasChildren bool, propIndent string, nodeProperties map[string][]propertyInfo, adj map[string][]schema.EdgeData, visited map[string]bool, graph *schema.ProjectGraph) {
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
		startChar := "  "
		if hasChildren {
			startChar = "│ "
		}

		isSeen := visited[prop.ID]
		visited[prop.ID] = true

		formatted := f.FormatProperty(basePrefix, startChar, propIndent, prop.Type, prop.Value, prop.Context, prop.OutOfScope, isSeen)
		fmt.Fprintln(out, formatted)

		if isSeen {
			continue
		}

		propChildren := adj[prop.ID]
		nextPropIndent := propIndent + "  "
		if len(propChildren) > 0 {
			nextPropIndent = propIndent + "  │ "
		}

		printProperties(out, f, prop.ID, basePrefix, hasChildren, nextPropIndent, nodeProperties, adj, visited, graph)

		if len(propChildren) > 0 {
			propChildPrefix := basePrefix + startChar + propIndent + "  "
			printChildren(out, f, propChildren, propChildPrefix, adj, visited, nodeProperties, graph)
		}
	}
}

func printChildren(out io.Writer, f TreeFormatter, children []schema.EdgeData, childPrefix string, adj map[string][]schema.EdgeData, visited map[string]bool, nodeProperties map[string][]propertyInfo, graph *schema.ProjectGraph) {
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

		if visited[targetID] {
			formatted := f.FormatNode(childPrefix, childMarker, targetType, targetNode.Subtypes, targetValue, child.Context, targetNode.OutOfScope, isLimitReached(targetID), true)
			fmt.Fprintln(out, formatted)
		} else {
			printNode(out, f, targetID, targetValue, targetType, targetNode.OutOfScope, isLimitReached(targetID), childPrefix, childMarker, child.Context, isChildLast, adj, visited, nodeProperties, graph)
		}
	}
}
