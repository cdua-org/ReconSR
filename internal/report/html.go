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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/html/graph.go.html
var graphTemplateContent string

var graphTemplate *template.Template

func init() {
	graphTemplate = template.Must(template.New("graph").Parse(graphTemplateContent))
}

type statItem struct {
	Type  string
	Count int
}

type reportTemplateData struct {
	ProjectName     string
	Timestamp       string
	NodesCount      int
	OutOfScopeCount int
	PropertiesCount int
	EdgesCount      int
	Stats           []statItem
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

type visProperty struct {
	Type       string         `json:"type"`
	Value      string         `json:"value"`
	Properties []*visProperty `json:"properties,omitempty"`
	Contexts   []string       `json:"contexts,omitempty"`
	Module     string         `json:"module,omitempty"`
	Function   string         `json:"function,omitempty"`
	FirstSeen  int64          `json:"firstSeen,omitempty"`
	LastSeen   int64          `json:"lastSeen,omitempty"`
}

type visNode struct {
	ID          string            `json:"id"`
	Label       string            `json:"label"`
	Group       string            `json:"group"`
	Title       string            `json:"title"`
	Properties  []*visProperty    `json:"properties,omitempty"`
	Executions  map[string]string `json:"executions,omitempty"`
	OutOfScope  bool              `json:"outOfScope"`
	Color       map[string]string `json:"color,omitempty"`
	BorderWidth int               `json:"borderWidth,omitempty"`
}

type visEdge struct {
	ID        string   `json:"id"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	Label     string   `json:"label"`
	Title     string   `json:"title"`
	Contexts  []string `json:"contexts,omitempty"`
	Module    string   `json:"module"`
	Function  string   `json:"function"`
	FirstSeen int64    `json:"firstSeen"`
	LastSeen  int64    `json:"lastSeen"`
}

type edgeKey struct {
	From     string
	To       string
	Function string
}

type highlightedNode struct {
	visNode
	Shape string            `json:"shape"`
	Size  int               `json:"size"`
	Color map[string]string `json:"color"`
}

// GenerateHTML creates an interactive HTML graph report using Vis.js.
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

	nodesMap := make(map[string]visNode)
	edgesMap := make(map[edgeKey]*visEdge)
	edgeIDCounter := 0

	allProps := make(map[string]*visProperty)
	propToParent := make(map[string]string)
	nodeProperties := make(map[string][]*visProperty)
	nodeExecutions := make(map[string]map[string]string)

	parseTime := func(timeStr string) (int64, error) {
		layouts := []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05Z", time.RFC3339}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, timeStr); err == nil {
				return t.Truncate(time.Minute).UnixMilli(), nil
			}
		}
		return 0, errors.New("invalid time format")
	}

	type propLink struct {
		parent string
		child  string
	}
	var propLinks []propLink
	seenLinks := make(map[propLink]bool)

	for _, edge := range graph.Edges {
		if edge.Target.Category == "property" {
			srcID := fmt.Sprintf("%s:%s", edge.Source.Type, edge.Source.Value)
			dstID := fmt.Sprintf("%s:%s", edge.Target.Type, edge.Target.Value)
			propToParent[dstID] = srcID

			link := propLink{parent: srcID, child: dstID}
			if !seenLinks[link] {
				seenLinks[link] = true
				propLinks = append(propLinks, link)
			}
		}
	}

	for _, edge := range graph.Edges {
		srcID := fmt.Sprintf("%s:%s", edge.Source.Type, edge.Source.Value)
		dstID := fmt.Sprintf("%s:%s", edge.Target.Type, edge.Target.Value)

		rootID := srcID
		for {
			if parentID, ok := propToParent[rootID]; ok {
				rootID = parentID
			} else {
				break
			}
		}

		if edge.RawData != "" {
			if nodeExecutions[rootID] == nil {
				nodeExecutions[rootID] = make(map[string]string)
			}
			nodeExecutions[rootID][edge.FunctionName] = edge.RawData
		}

		if edge.Target.Category == "property" {
			edgeTime, err := parseTime(edge.CreatedAt)
			if err != nil {
				return "", err
			}

			if p, ok := allProps[dstID]; ok {
				if edgeTime < p.FirstSeen {
					p.FirstSeen = edgeTime
				}
				if edgeTime > p.LastSeen {
					p.LastSeen = edgeTime
				}
				if edge.Context != "" && !slices.Contains(p.Contexts, edge.Context) {
					p.Contexts = append(p.Contexts, edge.Context)
				}
			} else {
				var contexts []string
				if edge.Context != "" {
					contexts = append(contexts, edge.Context)
				}
				allProps[dstID] = &visProperty{
					Type:      edge.Target.Type,
					Value:     edge.Target.Value,
					Module:    edge.ModuleName,
					Function:  edge.FunctionName,
					FirstSeen: edgeTime,
					LastSeen:  edgeTime,
					Contexts:  contexts,
				}
			}
		}
	}

	for _, link := range propLinks {
		srcID := link.parent
		dstID := link.child
		if parentProp, ok := allProps[srcID]; ok {
			parentProp.Properties = append(parentProp.Properties, allProps[dstID])
		} else {
			nodeProperties[srcID] = append(nodeProperties[srcID], allProps[dstID])
		}
	}

	for _, edge := range graph.Edges {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		srcID := fmt.Sprintf("%s:%s", edge.Source.Type, edge.Source.Value)
		dstID := fmt.Sprintf("%s:%s", edge.Target.Type, edge.Target.Value)

		for {
			if parentID, ok := propToParent[srcID]; ok {
				srcID = parentID
			} else {
				break
			}
		}

		if edge.Target.Category == "property" {
			continue
		}

		if _, exists := nodesMap[srcID]; !exists {
			parts := strings.SplitN(srcID, ":", 2)
			nodeType, nodeValue := parts[0], parts[1]
			title := fmt.Sprintf("Type: %s\nValue: %s", nodeType, nodeValue)
			node := visNode{
				ID:         srcID,
				Label:      nodeValue,
				Group:      nodeType,
				Title:      title,
				Properties: nodeProperties[srcID],
				Executions: nodeExecutions[srcID],
			}
			nodesMap[srcID] = node
		}
		if _, exists := nodesMap[dstID]; !exists {
			title := fmt.Sprintf("Type: %s\nValue: %s", edge.Target.Type, edge.Target.Value)
			var borderWidth int
			if edge.TargetOutOfScope {
				title += "\nOut of Scope: Yes"
				borderWidth = 5
			}
			node := visNode{
				ID:          dstID,
				Label:       edge.Target.Value,
				Group:       edge.Target.Type,
				Title:       title,
				Properties:  nodeProperties[dstID],
				Executions:  nodeExecutions[dstID],
				OutOfScope:  edge.TargetOutOfScope,
				BorderWidth: borderWidth,
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
			newEdge := &visEdge{
				ID:        fmt.Sprintf("e_%d", edgeIDCounter),
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

	visEdges := make([]visEdge, 0, len(edgesMap))
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

		var titleParts []string
		titleParts = append(titleParts, e.Contexts...)
		titleParts = append(titleParts, fmt.Sprintf("Function: %s", e.Function))
		firstTime := time.UnixMilli(e.FirstSeen).Format("2006-01-02")
		lastTime := time.UnixMilli(e.LastSeen).Format("2006-01-02")
		if firstTime == lastTime {
			titleParts = append(titleParts, fmt.Sprintf("Seen: %s", firstTime))
		} else {
			titleParts = append(titleParts, fmt.Sprintf("Seen: %s - %s", firstTime, lastTime))
		}
		e.Title = strings.Join(titleParts, "\n")

		visEdges = append(visEdges, *e)
	}

	var initialTargetID string
	for _, edge := range graph.Edges {
		if edge.Source.Value == graph.InitialTarget {
			initialTargetID = fmt.Sprintf("%s:%s", edge.Source.Type, edge.Source.Value)
			break
		}
	}

	visNodes := make([]interface{}, 0, len(nodesMap))
	statsMap := make(map[string]int)
	outOfScopeCount := 0
	for _, n := range nodesMap {
		statsMap[n.Group]++
		if n.OutOfScope {
			outOfScopeCount++
		}

		isInitial := false
		if initialTargetID != "" {
			isInitial = n.ID == initialTargetID
		} else {
			isInitial = n.Label == graph.InitialTarget
		}

		if isInitial {
			visNodes = append(visNodes, highlightedNode{
				visNode: n,
				Shape:   "diamond",
				Size:    30,
				Color: map[string]string{
					"border":     "#fbbf24",
					"background": "#d97706",
				},
			})
		} else {
			visNodes = append(visNodes, n)
		}
	}

	var stats []statItem
	for t, count := range statsMap {
		stats = append(stats, statItem{
			Type:  html.EscapeString(t),
			Count: count,
		})
	}
	slices.SortFunc(stats, func(a, b statItem) int {
		return strings.Compare(a.Type, b.Type)
	})

	data := reportTemplateData{
		ProjectName:     html.EscapeString(graph.ProjectName),
		Timestamp:       timestamp,
		NodesCount:      len(visNodes),
		OutOfScopeCount: outOfScopeCount,
		PropertiesCount: len(allProps),
		EdgesCount:      len(visEdges),
		Stats:           stats,
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
	for i, node := range visNodes {
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

	for i, edge := range visEdges {
		if i > 0 {
			if _, err := buf.WriteString(","); err != nil {
				return "", err
			}
		}
		if err := enc.Encode(edge); err != nil {
			return "", err
		}
	}

	if err := graphTemplate.ExecuteTemplate(buf, "footer", nil); err != nil {
		return "", err
	}

	if err := buf.Flush(); err != nil {
		return "", err
	}

	return reportPath, nil
}
