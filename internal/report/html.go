package report

import (
	"cdua-org/ReconSR/schema"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func sanitizePath(name string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	sanitized := re.ReplaceAllString(name, "_")
	return strings.Trim(sanitized, "_")
}

// GenerateHTML creates an interactive HTML graph report using Vis.js.
func GenerateHTML(graph *schema.ProjectGraph) (string, error) {
	targetSubDir := sanitizePath(graph.InitialTarget)
	reportDir := filepath.Join("reports", targetSubDir)
	if err := os.MkdirAll(reportDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	rawFileTime := time.Now().Format("2006-01-02_15-04-05")

	sanitizedProjectName := sanitizePath(graph.ProjectName)
	filename := fmt.Sprintf("%s_%s.html", sanitizedProjectName, rawFileTime)
	reportPath := filepath.Join(reportDir, filename)

	type visNode struct {
		ID          string            `json:"id"`
		Label       string            `json:"label"`
		Group       string            `json:"group"`
		Title       string            `json:"title"`
		OutOfScope  bool              `json:"outOfScope"`
		Color       map[string]string `json:"color,omitempty"`
		BorderWidth int               `json:"borderWidth,omitempty"`
	}
	type visEdge struct {
		ID        string `json:"id"`
		From      string `json:"from"`
		To        string `json:"to"`
		Label     string `json:"label"`
		Title     string `json:"title"`
		RawData   string `json:"rawData,omitempty"`
		Context   string `json:"context,omitempty"`
		Module    string `json:"module"`
		Function  string `json:"function"`
		CreatedAt string `json:"createdAt"`
	}

	nodesMap := make(map[string]visNode)
	var visEdges []visEdge

	for i, edge := range graph.Edges {
		srcID := fmt.Sprintf("%s:%s", edge.Source.Type, edge.Source.Value)
		dstID := fmt.Sprintf("%s:%s", edge.Target.Type, edge.Target.Value)

		if _, exists := nodesMap[srcID]; !exists {
			node := visNode{
				ID:    srcID,
				Label: edge.Source.Value,
				Group: edge.Source.Type,
				Title: fmt.Sprintf("Type: %s\nValue: %s", edge.Source.Type, edge.Source.Value),
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
				OutOfScope:  edge.TargetOutOfScope,
				BorderWidth: borderWidth,
			}
			nodesMap[dstID] = node
		}

		label := edge.Context
		if label == "" {
			label = edge.FunctionName
		}

		visEdges = append(visEdges, visEdge{
			ID:        fmt.Sprintf("e_%d", i),
			From:      srcID,
			To:        dstID,
			Label:     label,
			Title:     "Click for details",
			RawData:   edge.RawData,
			Context:   edge.Context,
			Module:    edge.ModuleName,
			Function:  edge.FunctionName,
			CreatedAt: edge.CreatedAt,
		})
	}

	var visNodes []interface{}
	stats := make(map[string]int)
	for _, n := range nodesMap {
		stats[n.Group]++
		if n.Label == graph.InitialTarget {
			// Add special styling for the root node
			type highlightedNode struct {
				visNode
				Shape string            `json:"shape"`
				Size  int               `json:"size"`
				Color map[string]string `json:"color"`
			}
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

	var statsParts []string
	for t, count := range stats {
		statsParts = append(statsParts, fmt.Sprintf("%s: %d", t, count))
	}
	statsStr := strings.Join(statsParts, " | ")

	nodesJSON, _ := json.Marshal(visNodes)
	edgesJSON, _ := json.Marshal(visEdges)

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ReconSR Graph - %s</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body { background-color: #0f172a; color: #e2e8f0; margin: 0; padding: 0; font-family: sans-serif; overflow: hidden; }
        #mynetwork { width: 100vw; height: 100vh; background-color: #0f172a; }
        .header { position: absolute; top: 20px; left: 20px; z-index: 10; pointer-events: none; }
        .brand { color: #f8fafc; font-weight: 800; font-size: 1.4rem; letter-spacing: 0.05rem; margin-bottom: 2px; display: flex; align-items: center; }
        .brand::before { content: ''; display: inline-block; width: 12px; height: 12px; background: #38bdf8; margin-right: 10px; border-radius: 2px; }
        h1 { color: #38bdf8; margin: 0; font-size: 1.1rem; font-weight: 400; }
        .meta { color: #94a3b8; font-size: 0.8rem; margin-top: 5px; }
        
        #modal { display: none; position: fixed; right: 0; top: 0; width: 450px; height: 100vh; background: #1e293b; border-left: 2px solid #334155; padding: 25px; box-sizing: border-box; overflow-y: auto; z-index: 1000; box-shadow: -5px 0 15px rgba(0,0,0,0.3); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 10px; margin-bottom: 20px; }
        .close-btn { color: #94a3b8; cursor: pointer; font-size: 24px; }
        .close-btn:hover { color: #e2e8f0; }
        
        .detail-item { margin-bottom: 20px; }
        .detail-label { color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; font-weight: bold; margin-bottom: 5px; }
        .detail-value { color: #f1f5f9; font-size: 0.95rem; }
        .detail-value.code { color: #10b981; font-family: monospace; background: #0f172a; padding: 10px; border-radius: 4px; display: block; white-space: pre-wrap; word-break: break-all; margin-top: 8px; border: 1px solid #334155; }
        
        h3 { color: #38bdf8; margin: 0; font-size: 1.1rem; }
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">ReconSR</div>
        <h1>Project: %s</h1>
        <div class="meta">Generated: %s | Nodes: %d | Edges: %d</div>
        <div class="meta">%s</div>
    </div>
    
    <div id="modal">
        <div class="modal-header">
            <h3>Observation Details</h3>
            <span class="close-btn" onclick="closeModal()">&times;</span>
        </div>
        <div id="modalBody"></div>
    </div>

    <div id="mynetwork"></div>

    <script type="text/javascript">
        const nodes = new vis.DataSet(%s);
        const edges = new vis.DataSet(%s);
        const container = document.getElementById('mynetwork');
        const data = { nodes: nodes, edges: edges };
        const options = {
            nodes: {
                shape: 'dot', size: 20,
                font: { color: '#f1f5f9', size: 16, face: 'Segoe UI', strokeWidth: 0 },
                borderWidth: 2, shadow: true
            },
            edges: {
                width: 2,
                color: { color: '#64748b', highlight: '#38bdf8', hover: '#94a3b8' },
                arrows: { to: { enabled: true, scaleFactor: 0.8 } },
                font: { 
                    color: '#cbd5e1', 
                    size: 11, 
                    align: 'top', // Follow the line direction
                    strokeWidth: 2,
                    strokeColor: '#0f172a' // Small dark outline instead of block background
                },
                hoverWidth: 1.5, smooth: { type: 'continuous' }
            },
            groups: {
                domain: { color: { background: '#0ea5e9', border: '#0284c7' } },
                subdomain: { color: { background: '#8b5cf6', border: '#7c3aed' } },
                ipv4: { color: { background: '#10b981', border: '#059669' } },
                email: { color: { background: '#f59e0b', border: '#d97706' } }
            },
            physics: {
                enabled: true,
                barnesHut: { 
                    gravitationalConstant: -1500, // Reduced repulsion
                    centralGravity: 0.1,         // Reduced pull to center
                    springLength: 150,
                    springConstant: 0.02,        // Much softer springs
                    damping: 0.3,                // Higher damping to slow down movement
                    avoidOverlap: 0.2
                },
                stabilization: { iterations: 200 }
            },
            interaction: { hover: true, navigationButtons: true, keyboard: true, dragNodes: true }
        };
        const network = new vis.Network(container, data, options);

        // Apply dark gray border for out-of-scope nodes while keeping group background
        nodes.forEach(node => {
            if (node.outOfScope) {
                const groupColor = (options.groups[node.group] && options.groups[node.group].color) 
                    ? options.groups[node.group].color.background 
                    : '#64748b';
                nodes.update({
                    id: node.id,
                    color: { border: '#334155', background: groupColor, highlight: groupColor }
                });
            }
        });

        function closeModal() { document.getElementById('modal').style.display = 'none'; }

        function formatTime(isoStr) {
            if (!isoStr) return '';
            // Treat the string as local time (no Z or T forcing)
            const date = new Date(isoStr.replace(' ', 'T'));
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        }

        network.on("click", function (params) {
            let content = '';
            // 1. Check if a Node was clicked
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const node = nodes.get(nodeId);
                if (node) {
                    content += '<div class="detail-item"><div class="detail-label">Object Value</div><div class="detail-value code">' + node.label + '</div></div>';
                    content += '<div class="detail-item"><div class="detail-label">Entity Type</div><div class="detail-value">' + node.group + '</div></div>';
                    if (node.outOfScope) {
                        content += '<div style="color: #ef4444; font-size: 0.85rem; font-weight: bold; margin-top: 10px; display: flex; align-items: center;">';
                        content += '<span style="margin-right: 5px;">⚠️</span> OUT OF SCOPE';
                        content += '</div>';
                    }
                    document.getElementById('modalBody').innerHTML = content;
                    document.getElementById('modal').style.display = 'block';
                }
            } 
            // 2. Check if an Edge was clicked
            else if (params.edges.length > 0) {
                const edgeId = params.edges[0];
                const edge = edges.get(edgeId);
                if (edge) {
                    if (edge.context) {
                        content += '<div class="detail-item"><div class="detail-label">Context</div><div class="detail-value code">' + edge.context + '</div></div>';
                    }
                    if (edge.rawData) {
                        content += '<div class="detail-item"><div class="detail-label">Raw Data</div><div class="detail-value code">' + edge.rawData + '</div></div>';
                    }
                    content += '<div class="detail-item"><div class="detail-label">Method</div><div class="detail-value">' + edge.function + '</div></div>';
                    content += '<div class="detail-item"><div class="detail-label">Discovery Time</div><div class="detail-value">' + formatTime(edge.createdAt) + '</div></div>';
                    document.getElementById('modalBody').innerHTML = content;
                    document.getElementById('modal').style.display = 'block';
                }
            } else {
                closeModal();
            }
        });
    </script>
</body>
</html>`, graph.ProjectName, graph.ProjectName, timestamp, len(visNodes), len(visEdges), statsStr, string(nodesJSON), string(edgesJSON))

	err := os.WriteFile(reportPath, []byte(htmlContent), 0600)
	if err != nil {
		return "", err
	}

	return reportPath, nil
}
