package report

import (
	"bufio"
	"cdua-org/ReconSR/schema"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

// Layout tuning parameters
const (
	layoutIdealDistance     = 50.0 // Base spring length (k)
	layoutRootRadius        = 45.0 // Collision radius for the root node
	layoutMaxHubRadius      = 45.0 // Maximum allowed collision radius for any hub
	layoutBaseNodeRadius    = 15.0 // Base collision radius for standard nodes
	layoutPhysicsIterations = 350  // Number of main physics iterations
	layoutCollisionPasses   = 350  // Number of collision resolution passes
	layoutParallelThreshold = 80   // Minimum node count to engage parallel repulsion
	layoutApproxRepulsionDistSq = 40000.0 // Threshold squared distance (200*200) to use fast repulsion approximation
)

//go:embed templates/html/graph.go.html
var graphTemplateContent string

var graphTemplate *template.Template

func init() {
	graphTemplate = template.Must(template.New("graph").Parse(graphTemplateContent))
}

type statItem struct {
	Type     string
	Count    int
	Subtypes []statItem
}

type reportTemplateData struct {
	ProjectName         string
	Timestamp           string
	NodesCount          int
	OutOfScopeCount     int
	LimitReachedCount   int
	PropertiesCount     int
	EdgesCount          int
	Stats               []statItem
	RawDataRegistryJSON string
	AllProperties       string
	InitialTargetID     int64
	RootType            string
	RootSubtypes        []string
}

func sanitizePath(name string) string {
	sanitized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, name)
	return strings.Trim(sanitized, "_")
}

type graphProperty struct {
	ID         int64    `json:"id"`
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Properties []int64  `json:"properties,omitempty"`
	Contexts   []string `json:"contexts,omitempty"`
	Module     string   `json:"module,omitempty"`
	Function   string   `json:"function,omitempty"`
	FirstSeen  int64    `json:"firstSeen,omitempty"`
	LastSeen   int64    `json:"lastSeen,omitempty"`
	RawDataID  int64    `json:"rawDataId,omitempty"`
	Executions map[string]int64 `json:"executions,omitempty"`
}

type graphNode struct {
	ID                int64             `json:"id"`
	Label             string            `json:"label"`
	Group             string            `json:"group"`
	Properties        []int64           `json:"properties,omitempty"`
	Executions        map[string]int64  `json:"executions,omitempty"`
	OutOfScope        bool              `json:"outOfScope"`
	DepthLimitReached bool              `json:"depthLimitReached"`
	Color             map[string]string `json:"color,omitempty"`
	BorderWidth       int               `json:"borderWidth,omitempty"`
	Subtypes          []string          `json:"subtypes,omitempty"`
	X                 int               `json:"x"`
	Y                 int               `json:"y"`
}

type graphEdge struct {
	ID        int64    `json:"id"`
	From      int64    `json:"from"`
	To        int64    `json:"to"`
	Label     string   `json:"label"`
	Contexts  []string `json:"contexts,omitempty"`
	Module    string   `json:"module"`
	Function  string   `json:"function"`
	FirstSeen int64    `json:"firstSeen"`
	LastSeen  int64    `json:"lastSeen"`
}

type edgeKey struct {
	From     int64
	To       int64
	Function string
}

type highlightedNode struct {
	graphNode
	Shape string            `json:"shape"`
	Size  int               `json:"size"`
	Color map[string]string `json:"color"`
}

// GenerateHTML creates an interactive HTML graph report.
func GenerateHTML(ctx context.Context, graph *schema.ProjectGraph) (string, error) {
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
	timestamp := now.Format("2006-01-02 15:04:05")
	rawFileTime := now.Format("2006-01-02_15-04-05")

	sanitizedProjectName := sanitizePath(graph.ProjectName)
	filename := fmt.Sprintf("%s_%s.html", sanitizedProjectName, rawFileTime)
	relPath := filepath.Join(targetSubDir, filename)
	reportPath := filepath.Join("reports", relPath)

	nodesMap := make(map[int64]graphNode)
	edgesMap := make(map[edgeKey]*graphEdge)
	edgeIDCounter := int64(1)

	allProps := make(map[int64]*graphProperty)
	propToParent := make(map[int64]int64)
	nodeProperties := make(map[int64][]int64)
	nodeExecutions := make(map[int64]map[string]int64)

	rawDataRegistry := make(map[int64]string)
	rawDataToID := make(map[string]int64)
	rawDataCounter := int64(1)

	asInt := func(s string) int64 {
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0
		}
		return i
	}

	parseTime := func(timeStr string) (int64, error) {
		layouts := []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05Z", time.RFC3339}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, timeStr); err == nil {
				return t.Truncate(time.Minute).UnixMilli(), nil
			}
		}
		return 0, errors.New("invalid time format")
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

	type propLink struct {
		parent int64
		child  int64
	}
	var propLinks []propLink
	seenLinks := make(map[propLink]bool)

	for _, edge := range graph.Edges {
		targetNode := graph.Nodes[edge.TargetID]
		if targetNode.Category == "property" {
			srcID := asInt(edge.SourceID)
			dstID := asInt(edge.TargetID)
			propToParent[dstID] = srcID

			link := propLink{parent: srcID, child: dstID}
			if !seenLinks[link] {
				seenLinks[link] = true
				propLinks = append(propLinks, link)
			}
		}
	}

	for _, edge := range graph.Edges {
		srcID := asInt(edge.SourceID)
		dstID := asInt(edge.TargetID)
		sourceNode := graph.Nodes[edge.SourceID]
		targetNode := graph.Nodes[edge.TargetID]

		rootID := srcID
		for {
			if parentID, ok := propToParent[rootID]; ok {
				rootID = parentID
			} else {
				break
			}
		}

		var dataID int64
		if edge.RawData != "" {
			var ok bool
			dataID, ok = rawDataToID[edge.RawData]
			if !ok {
				dataID = rawDataCounter
				rawDataCounter++
				rawDataToID[edge.RawData] = dataID
				if dbID, err := strconv.ParseInt(edge.RawData, 10, 64); err == nil {
					if content, ok := graph.RawDataRegistry[dbID]; ok {
						rawDataRegistry[dataID] = content
					}
				}
			}

			if sourceNode.Category == "property" {
				if p, ok := allProps[srcID]; ok {
					if p.Executions == nil {
						p.Executions = make(map[string]int64)
					}
					p.Executions[edge.FunctionName] = dataID
				} else {
					allProps[srcID] = &graphProperty{
						ID:         srcID,
						Executions: map[string]int64{edge.FunctionName: dataID},
					}
				}
			} else {
				if nodeExecutions[rootID] == nil {
					nodeExecutions[rootID] = make(map[string]int64)
				}
				nodeExecutions[rootID][edge.FunctionName] = dataID
			}
		}

		if targetNode.Category == "property" {
			edgeTime, err := parseTime(edge.CreatedAt)
			if err != nil {
				return "", err
			}

			if p, ok := allProps[dstID]; ok {
				if p.Type == "" {
					p.Type = targetNode.Type
					p.Value = targetNode.Value
					p.Module = edge.ModuleName
					p.Function = edge.FunctionName
					p.FirstSeen = edgeTime
					p.LastSeen = edgeTime
				} else {
					if edgeTime < p.FirstSeen {
						p.FirstSeen = edgeTime
					}
					if edgeTime > p.LastSeen {
						p.LastSeen = edgeTime
					}
				}
				if edge.Context != "" && !slices.Contains(p.Contexts, edge.Context) {
					p.Contexts = append(p.Contexts, edge.Context)
				}
				if dataID != 0 {
					p.RawDataID = dataID
				}
			} else {
				var contexts []string
				if edge.Context != "" {
					contexts = append(contexts, edge.Context)
				}
				allProps[dstID] = &graphProperty{
					ID:        dstID,
					Type:      targetNode.Type,
					Value:     targetNode.Value,
					Module:    edge.ModuleName,
					Function:  edge.FunctionName,
					FirstSeen: edgeTime,
					LastSeen:  edgeTime,
					Contexts:  contexts,
					RawDataID:  dataID,
				}
			}
		}
	}

	for _, link := range propLinks {
		srcID := link.parent
		dstID := link.child
		if parentProp, ok := allProps[srcID]; ok {
			parentProp.Properties = append(parentProp.Properties, dstID)
		} else {
			nodeProperties[srcID] = append(nodeProperties[srcID], dstID)
		}
	}

	for _, edge := range graph.Edges {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		srcID := asInt(edge.SourceID)
		dstID := asInt(edge.TargetID)
		targetNode := graph.Nodes[edge.TargetID]

		for {
			if parentID, ok := propToParent[srcID]; ok {
				srcID = parentID
			} else {
				break
			}
		}

		if targetNode.Category == "property" {
			continue
		}

		if _, exists := nodesMap[srcID]; !exists {
			srcNode := graph.Nodes[edge.SourceID]
			var borderWidth int = 2
			srcLimitReached := isLimitReached(edge.SourceID)
			node := graphNode{
				ID:                srcID,
				Label:             srcNode.Value,
				Group:             srcNode.Type,
				Properties:        nodeProperties[srcID],
				Executions:        nodeExecutions[srcID],
				OutOfScope:        srcNode.OutOfScope,
				DepthLimitReached: srcLimitReached,
				BorderWidth:       borderWidth,
				Subtypes:          srcNode.Subtypes,
			}
			nodesMap[srcID] = node
		}
		if _, exists := nodesMap[dstID]; !exists {
			var borderWidth int = 2
			targetLimitReached := isLimitReached(edge.TargetID)
			node := graphNode{
				ID:                dstID,
				Label:             targetNode.Value,
				Group:             targetNode.Type,
				Properties:        nodeProperties[dstID],
				Executions:        nodeExecutions[dstID],
				OutOfScope:        targetNode.OutOfScope,
				DepthLimitReached: targetLimitReached,
				BorderWidth:       borderWidth,
				Subtypes:          targetNode.Subtypes,
			}
			nodesMap[dstID] = node
		}

		edgeTime, err := parseTime(edge.CreatedAt)
		if err != nil {
			return "", err
		}

		key := edgeKey{From: srcID, To: dstID, Function: edge.FunctionName}
		if existingEdge, exists := edgesMap[key]; exists {
			if edgeTime < existingEdge.FirstSeen {
				existingEdge.FirstSeen = edgeTime
			}
			if edgeTime > existingEdge.LastSeen {
				existingEdge.LastSeen = edgeTime
			}
			if edge.Context != "" {
				if !slices.Contains(existingEdge.Contexts, edge.Context) {
					existingEdge.Contexts = append(existingEdge.Contexts, edge.Context)
				}
			}
		} else {
			var contexts []string
			if edge.Context != "" {
				contexts = append(contexts, edge.Context)
			}
			newEdge := &graphEdge{
				ID:        edgeIDCounter,
				From:      srcID,
				To:        dstID,
				Contexts:  contexts,
				Module:    edge.ModuleName,
				Function:  edge.FunctionName,
				FirstSeen: edgeTime,
				LastSeen:  edgeTime,
			}
			edgesMap[key] = newEdge
			edgeIDCounter++
		}
	}

	graphEdges := make([]graphEdge, 0, len(edgesMap))
	for _, e := range edgesMap {
		if len(e.Contexts) == 0 {
			e.Label = e.Function
		} else if len(e.Contexts) == 1 {
			e.Label = e.Contexts[0]
		} else if len(e.Contexts) == 2 {
			e.Label = fmt.Sprintf("%s | %s", e.Contexts[0], e.Contexts[1])
		} else {
			e.Label = fmt.Sprintf("%s(+%d)", e.Contexts[0], len(e.Contexts)-1)
		}

		graphEdges = append(graphEdges, *e)
	}

	for id, n := range graph.Nodes {
		if n.Category == "property" {
			continue
		}
		nid := asInt(id)
		if _, exists := nodesMap[nid]; !exists {
			var borderWidth int = 2
			limitReached := isLimitReached(id)
			nodesMap[nid] = graphNode{
				ID:                nid,
				Label:             n.Value,
				Group:             n.Type,
				Properties:        nodeProperties[nid],
				Executions:        nodeExecutions[nid],
				OutOfScope:        n.OutOfScope,
				DepthLimitReached: limitReached,
				BorderWidth:       borderWidth,
				Subtypes:          n.Subtypes,
			}
		}
	}

	var initialTargetID int64
	var rootType string
	var rootSubtypes []string
	for id, n := range graph.Nodes {
		if n.Value == graph.InitialTarget && n.Category != "property" {
			initialTargetID = asInt(id)
			rootType = n.Type
			rootSubtypes = n.Subtypes
			break
		}
	}

	if err := applyForceLayout(ctx, nodesMap, edgesMap, initialTargetID); err != nil {
		return "", err
	}

	type typeStats struct {
		Count    int
		Subtypes map[string]int
	}

	graphNodes := make([]any, 0, len(nodesMap))
	statsMap := make(map[string]*typeStats)
	outOfScopeCount := 0
	limitReachedCount := 0
	for _, n := range nodesMap {
		if n.OutOfScope {
			outOfScopeCount++
		}
		if n.DepthLimitReached {
			limitReachedCount++
		}

		isInitial := false
		if initialTargetID != 0 {
			isInitial = n.ID == initialTargetID
		} else {
			isInitial = n.Label == graph.InitialTarget
		}

		if isInitial {
			n.Group = "root"
			graphNodes = append(graphNodes, highlightedNode{
				graphNode: n,
				Shape:   "diamond",
				Size:    35,
				Color: map[string]string{
					"border":     "#fbbf24",
					"background": "#d97706",
				},
			})
		} else {
			ts, ok := statsMap[n.Group]
			if !ok {
				ts = &typeStats{Subtypes: make(map[string]int)}
				statsMap[n.Group] = ts
			}
			ts.Count++
			for _, st := range n.Subtypes {
				ts.Subtypes[st]++
			}
			graphNodes = append(graphNodes, n)
		}
	}

	var stats []statItem
	for t, ts := range statsMap {
		var subItems []statItem
		for st, count := range ts.Subtypes {
			subItems = append(subItems, statItem{
				Type:  html.EscapeString(st),
				Count: count,
			})
		}
		slices.SortFunc(subItems, func(a, b statItem) int {
			return strings.Compare(a.Type, b.Type)
		})

		stats = append(stats, statItem{
			Type:     html.EscapeString(t),
			Count:    ts.Count,
			Subtypes: subItems,
		})
	}
	slices.SortFunc(stats, func(a, b statItem) int {
		if a.Type == "invalid" {
			return 1
		}
		if b.Type == "invalid" {
			return -1
		}
		return strings.Compare(a.Type, b.Type)
	})

	rawDataJSON, err := json.Marshal(rawDataRegistry)
	if err != nil {
		return "", err
	}

	allPropsJSON, err := json.Marshal(allProps)
	if err != nil {
		return "", err
	}

	data := reportTemplateData{
		ProjectName:         html.EscapeString(graph.ProjectName),
		Timestamp:           timestamp,
		NodesCount:          len(graphNodes),
		OutOfScopeCount:     outOfScopeCount,
		LimitReachedCount:   limitReachedCount,
		PropertiesCount:     len(allProps),
		EdgesCount:          len(graphEdges),
		Stats:               stats,
		RawDataRegistryJSON: string(rawDataJSON),
		AllProperties:       string(allPropsJSON),
		InitialTargetID:     initialTargetID,
		RootType:            rootType,
		RootSubtypes:        rootSubtypes,
	}

	f, err := root.Create(relPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := bufio.NewWriter(f)

	// Stream data directly to file to prevent excessive memory allocation
	if err := graphTemplate.ExecuteTemplate(buf, "header", data); err != nil {
		return "", err
	}

	enc := json.NewEncoder(buf)
	for i, node := range graphNodes {
		if i > 0 {
			if _, err := buf.WriteString(","); err != nil {
				return "", err
			}
		}
		if err := enc.Encode(node); err != nil {
			return "", err
		}
	}

	if err := graphTemplate.ExecuteTemplate(buf, "middle", nil); err != nil {
		return "", err
	}

	for i, edge := range graphEdges {
		if i > 0 {
			if _, err := buf.WriteString(","); err != nil {
				return "", err
			}
		}
		if err := enc.Encode(edge); err != nil {
			return "", err
		}
	}

	if err := graphTemplate.ExecuteTemplate(buf, "footer", data); err != nil {
		return "", err
	}

	if err := buf.Flush(); err != nil {
		return "", err
	}

	return reportPath, nil
}

func applyForceLayout(ctx context.Context, nodes map[int64]graphNode, edges map[edgeKey]*graphEdge, rootID int64) error {
	nodeCount := len(nodes)
	if nodeCount == 0 {
		return nil
	}

	// Internal physics stability constants
	const (
		layoutGravityForce          = 0.2    // Central gravity pulling disconnected clusters
		layoutHubSpringMultiplier   = 1.5    // Edge length multiplier for connections to hubs
		layoutHubDegreeMultiplier   = 0.5    // Radius increase per connection
		layoutInitialTemperature    = 1000.0 // Initial movement limit
		layoutCollisionPadding      = 15.0   // Extra padding (px) applied during hard collision pass
		layoutCollisionDisplacement = 0.5    // Collision resolution aggressiveness
	)

	nodeIDs := make([]int64, 0, nodeCount)
	idxOf := make(map[int64]int, nodeCount)
	for id := range nodes {
		idxOf[id] = len(nodeIDs)
		nodeIDs = append(nodeIDs, id)
	}

	px := make([]float64, nodeCount)
	py := make([]float64, nodeCount)
	dx := make([]float64, nodeCount)
	dy := make([]float64, nodeCount)
	radii := make([]float64, nodeCount)
	// logTable[d] = log10(d+2)*0.1 keeps the exact repulsion formula
	// log10(degV+degU+2)*0.1 without a transcendental call per pair.
	logTable := make([]float64, 2*len(edges)+2)
	for d := range logTable {
		logTable[d] = math.Log10(float64(d+2)) * 0.1
	}

	degreeOf := make([]int, nodeCount)
	for _, e := range edges {
		fi, fiOk := idxOf[e.From]
		ti, tiOk := idxOf[e.To]
		if fiOk {
			degreeOf[fi]++
		}
		if tiOk {
			degreeOf[ti]++
		}
	}

	for i, id := range nodeIDs {
		deg := degreeOf[i]
		if id == rootID {
			radii[i] = layoutRootRadius
		} else {
			radii[i] = min(layoutBaseNodeRadius+float64(deg)*layoutHubDegreeMultiplier, layoutMaxHubRadius)
		}
		angle := float64(id%31) * 2.39996
		seed := id % 100
		if seed < 0 {
			seed = -seed
		}
		r := math.Sqrt(float64(seed)) * 20.0
		px[i] = r * math.Cos(angle)
		py[i] = r * math.Sin(angle)
	}

	type edgeIdx struct {
		from, to int
		localK   float64
	}
	edgeList := make([]edgeIdx, 0, len(edges))
	k := layoutIdealDistance
	for _, e := range edges {
		fi, fiOk := idxOf[e.From]
		ti, tiOk := idxOf[e.To]
		if !fiOk || !tiOk {
			continue
		}
		lk := k
		if degreeOf[fi] > 2 || degreeOf[ti] > 2 {
			lk = k * layoutHubSpringMultiplier
		}
		edgeList = append(edgeList, edgeIdx{from: fi, to: ti, localK: lk})
	}

	numWorkers := max(1, runtime.GOMAXPROCS(0)-1)
	if nodeCount < layoutParallelThreshold {
		numWorkers = 1
	}
	stride := (nodeCount + numWorkers - 1) / numWorkers

	type localAcc struct{ dx, dy []float64 }
	accs := make([]localAcc, numWorkers)
	for w := range accs {
		accs[w] = localAcc{
			dx: make([]float64, nodeCount),
			dy: make([]float64, nodeCount),
		}
	}

	// Each worker accumulates repulsion forces into its own arrays to avoid
	// shared-memory races. Results are merged into dx/dy after each iteration.
	repulse := func(w, start, end int) {
		ldx, ldy := accs[w].dx, accs[w].dy
		for i := start; i < end; i++ {
			pxi, pyi := px[i], py[i]
			ri := radii[i]
			for j := i + 1; j < nodeCount; j++ {
				dX := pxi - px[j]
				dY := pyi - py[j]
				distSq := dX*dX + dY*dY
				if distSq > layoutApproxRepulsionDistSq {
					forceMultiplier := 1.0 + logTable[degreeOf[i]+degreeOf[j]]
					coeff := (k * k) * forceMultiplier / distSq
					fx := dX * coeff
					fy := dY * coeff
					ldx[i] += fx
					ldy[i] += fy
					ldx[j] -= fx
					ldy[j] -= fy
					continue
				}
				dist := math.Sqrt(distSq)
				if dist < 0.1 {
					id := nodeIDs[i]
					jd := nodeIDs[j]
					dX = float64((id*31)%11) - 5.0
					dY = float64((jd*31)%11) - 5.0
					if dX == 0 && dY == 0 {
						dX = 1.0
					}
					dist = math.Sqrt(dX*dX + dY*dY)
				}
				sumR := ri + radii[j]
				overlap := sumR - dist
				var force float64
				if overlap > 0 {
					force = (k*k) + (overlap * 100.0)
				} else {
					sd := max(dist-sumR, 1.0)
					force = (k * k) / sd
				}
				force *= 1.0 + logTable[degreeOf[i]+degreeOf[j]]
				fx := (dX / dist) * force
				fy := (dY / dist) * force
				ldx[i] += fx
				ldy[i] += fy
				ldx[j] -= fx
				ldy[j] -= fy
			}
		}
	}

	iterations := layoutPhysicsIterations
	t := layoutInitialTemperature
	tStep := layoutInitialTemperature / float64(iterations)

	for iter := 0; iter < iterations; iter++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		for i := range dx {
			dx[i] = 0
			dy[i] = 0
		}

		for w := range accs {
			clear(accs[w].dx)
			clear(accs[w].dy)
		}
		if numWorkers == 1 {
			repulse(0, 0, nodeCount)
		} else {
			var wg sync.WaitGroup
			for w := 0; w < numWorkers; w++ {
				wg.Add(1)
				go func(w, start int) {
					defer wg.Done()
					repulse(w, start, min(start+stride, nodeCount))
				}(w, w*stride)
			}
			wg.Wait()
		}
		for w := range accs {
			for i := range dx {
				dx[i] += accs[w].dx[i]
				dy[i] += accs[w].dy[i]
			}
		}

		for _, e := range edgeList {
			dX := px[e.from] - px[e.to]
			dY := py[e.from] - py[e.to]
			dist := math.Sqrt(dX*dX + dY*dY)
			if dist < 0.1 {
				dist = 0.1
			}
			force := (dist * dist) / e.localK
			fx := (dX / dist) * force
			fy := (dY / dist) * force
			dx[e.from] -= fx
			dy[e.from] -= fy
			dx[e.to] += fx
			dy[e.to] += fy
		}

		for i := 0; i < nodeCount; i++ {
			distSq := px[i]*px[i] + py[i]*py[i]
			if distSq > 0.01 {
				dx[i] -= px[i] * layoutGravityForce
				dy[i] -= py[i] * layoutGravityForce
			}
			dispSq := dx[i]*dx[i] + dy[i]*dy[i]
			if dispSq > 0 {
				tSq := t * t
				if dispSq <= tSq {
					px[i] += dx[i]
					py[i] += dy[i]
				} else {
					disp := math.Sqrt(dispSq)
					px[i] += (dx[i] / disp) * t
					py[i] += (dy[i] / disp) * t
				}
			}
		}

		t = max(t-tStep, 0)
	}

	for iter := 0; iter < layoutCollisionPasses; iter++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		for i := 0; i < nodeCount; i++ {
			pxi, pyi := px[i], py[i]
			ri := radii[i]
			for j := i + 1; j < nodeCount; j++ {
				dX := pxi - px[j]
				dY := pyi - py[j]
				distSq := dX*dX + dY*dY
				minDist := ri + radii[j] + layoutCollisionPadding
				if distSq < minDist*minDist {
					dist := math.Sqrt(distSq)
					if dist < 0.1 {
						dist = 0.1
					}
					overlap := minDist - dist
					mx := (dX / dist) * (overlap * layoutCollisionDisplacement)
					my := (dY / dist) * (overlap * layoutCollisionDisplacement)
					pxi += mx
					pyi += my
					px[j] -= mx
					py[j] -= my
				}
			}
			px[i] = pxi
			py[i] = pyi
		}
	}

	for i, id := range nodeIDs {
		n := nodes[id]
		n.X = int(math.Round(px[i]))
		n.Y = int(math.Round(py[i]))
		nodes[id] = n
	}

	return nil
}
