package graph

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"unicode"
)

func Text(view View) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "project: %s\ngraph: %s; origin: %s\nnodes: %d; edges: %d; unlinked packages: %d\n", view.Project, view.Coverage.GraphState, view.Coverage.OriginState, len(view.Nodes), len(view.Edges), view.Unlinked)
	for _, node := range view.Nodes {
		fmt.Fprintf(&out, "node %s %s@%s [%s]", node.ID, node.Name, node.Version, node.Kind)
		if node.Unlinked {
			out.WriteString(" unlinked")
		}
		out.WriteByte('\n')
		if node.PURL != "" {
			fmt.Fprintf(&out, "  purl: %s\n", node.PURL)
		}
		for _, origin := range node.Origins {
			fmt.Fprintf(&out, "  origin: %s %s [%s]\n", origin.Kind, origin.SafeURL, origin.Status)
		}
	}
	for _, edge := range view.Edges {
		fmt.Fprintf(&out, "edge %s -> %s [%s]", edge.From, edge.To, edge.Kind)
		if edge.Condition != "" {
			fmt.Fprintf(&out, " if %s", edge.Condition)
		}
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

func DOT(view View) []byte {
	var out strings.Builder
	out.WriteString("digraph ravel {\n  rankdir=LR;\n  graph [label=")
	out.WriteString(dotQuote(view.Project + " | graph=" + view.Coverage.GraphState + " | origin=" + view.Coverage.OriginState))
	out.WriteString(", labelloc=t];\n  node [shape=box];\n")
	for _, node := range view.Nodes {
		label := node.Name
		if node.Version != "" {
			label += "@" + node.Version
		}
		label += "\n" + node.ID
		tooltip := node.PURL
		for _, origin := range node.Origins {
			if origin.SafeURL != "" {
				tooltip += "\n" + origin.SafeURL
			}
		}
		fmt.Fprintf(&out, "  %s [label=%s, tooltip=%s", dotQuote(node.ID), dotQuote(label), dotQuote(tooltip))
		if node.Unlinked {
			out.WriteString(", style=dashed")
		}
		out.WriteString("];\n")
	}
	for _, edge := range view.Edges {
		label := edge.Kind
		if edge.Condition != "" {
			label += " if " + edge.Condition
		}
		fmt.Fprintf(&out, "  %s -> %s [label=%s", dotQuote(edge.From), dotQuote(edge.To), dotQuote(label))
		if edge.Condition != "" {
			out.WriteString(", style=dashed")
		}
		out.WriteString("];\n")
	}
	out.WriteString("}\n")
	return []byte(out.String())
}

func dotQuote(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			out.WriteString("\\\\")
		case '"':
			out.WriteString("\\\"")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		default:
			if unicode.IsControl(r) {
				out.WriteByte(' ')
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

type point struct{ x, y int }

func HTML(view View) ([]byte, error) {
	if len(view.Nodes) > 300 || len(view.Edges) > 1500 {
		return nil, fmt.Errorf("HTML graph exceeds 300 nodes or 1500 edges; use --focus and --depth, or --format dot")
	}
	positions, width, height := layout(view)
	var out strings.Builder
	out.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Ravel graph</title><style>")
	out.WriteString("body{font:14px system-ui,sans-serif;color:#15243a;background:#f5f7fb;margin:0}header{padding:18px 24px;background:#162740;color:white}h1{font-size:20px;margin:0 0 8px}.meta{margin:0;color:#d8e2ef}.notice{padding:10px 24px;background:#fff0c5}.frame{overflow:auto;margin:20px;background:white;border:1px solid #c7d2e1;border-radius:8px;max-height:75vh}.frame svg{display:block}.edge{stroke:#7b8ca5;stroke-width:1.5;fill:none}.edge.conditional{stroke:#a15b22;stroke-dasharray:5 4}.node rect{fill:#e6f0ff;stroke:#5473a1;stroke-width:1.5;rx:7}.node.root rect{fill:#d9f4e9;stroke:#35765d}.node.unlinked rect{stroke-dasharray:5 4}.node text{font-size:12px;fill:#10243d}.node a{text-decoration:none}.details{margin:20px;padding:0 18px 18px;background:white;border:1px solid #c7d2e1;border-radius:8px}.details li{margin:8px 0;overflow-wrap:anywhere}.legend{padding:0 24px;color:#45566b}code{font-size:12px}")
	out.WriteString("</style></head><body><header><h1>")
	out.WriteString(html.EscapeString(view.Project))
	out.WriteString(" · dependency graph</h1><p class=\"meta\">Graph coverage: ")
	out.WriteString(html.EscapeString(view.Coverage.GraphState))
	out.WriteString(" · Origin coverage: ")
	out.WriteString(html.EscapeString(view.Coverage.OriginState))
	fmt.Fprintf(&out, " · %d nodes · %d edges · %d unlinked packages</p></header>", len(view.Nodes), len(view.Edges), view.Unlinked)
	if view.Coverage.GraphState != "complete_for_scope" {
		out.WriteString("<p class=\"notice\">The recorded dependency graph is partial for this scan. Missing edges are not inferred.</p>")
	}
	out.WriteString("<p class=\"legend\">Arrows point from depender to dependency. Dashed arrows have a condition. Dashed boxes have no recorded edges. Select a box to view its identity and origin.</p><div class=\"frame\"><svg xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"Dependency graph\" width=\"")
	fmt.Fprintf(&out, "%d\" height=\"%d\" viewBox=\"0 0 %d %d\"><defs><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\"><path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#7b8ca5\"/></marker></defs>", width, height, width, height)
	index := map[string]int{}
	for i, node := range view.Nodes {
		index[node.ID] = i
	}
	for _, edge := range view.Edges {
		from, to := positions[edge.From], positions[edge.To]
		class := "edge"
		if edge.Condition != "" {
			class += " conditional"
		}
		startX, endX := from.x+210, to.x
		if from.x >= to.x {
			startX, endX = from.x+105, to.x+105
		}
		fmt.Fprintf(&out, "<path class=\"%s\" d=\"M %d %d L %d %d\" marker-end=\"url(#arrow)\"><title>%s</title></path>", class, startX, from.y+30, endX, to.y+30, html.EscapeString(edge.Kind+conditionSuffix(edge.Condition)))
	}
	for _, node := range view.Nodes {
		position := positions[node.ID]
		class := "node"
		if node.ID == "root" {
			class += " root"
		}
		if node.Unlinked {
			class += " unlinked"
		}
		label := node.Name
		if node.Version != "" {
			label += "@" + node.Version
		}
		short := []rune(label)
		if len(short) > 29 {
			label = string(short[:28]) + "…"
		}
		fmt.Fprintf(&out, "<g class=\"%s\"><a href=\"#node-%d\"><rect x=\"%d\" y=\"%d\" width=\"210\" height=\"60\"/><text x=\"%d\" y=\"%d\">%s</text><title>%s</title></a></g>", class, index[node.ID], position.x, position.y, position.x+10, position.y+35, html.EscapeString(label), html.EscapeString(node.ID+" · "+node.PURL))
	}
	out.WriteString("</svg></div><section class=\"details\"><h2>Components and origins</h2><ol>")
	for i, node := range view.Nodes {
		fmt.Fprintf(&out, "<li id=\"node-%d\"><strong>%s", i, html.EscapeString(node.Name))
		if node.Version != "" {
			out.WriteString("@" + html.EscapeString(node.Version))
		}
		out.WriteString("</strong> <code>" + html.EscapeString(node.ID) + "</code>")
		if node.PURL != "" {
			out.WriteString("<br>PURL: <code>" + html.EscapeString(node.PURL) + "</code>")
		}
		for _, origin := range node.Origins {
			out.WriteString("<br>Origin: " + html.EscapeString(origin.Kind) + " <code>" + html.EscapeString(origin.SafeURL) + "</code> (" + html.EscapeString(origin.Status) + ")")
		}
		out.WriteString("</li>")
	}
	out.WriteString("</ol></section><section class=\"details\"><h2>Relationships</h2><ol>")
	for _, edge := range view.Edges {
		out.WriteString("<li><code>" + html.EscapeString(edge.From) + "</code> → <code>" + html.EscapeString(edge.To) + "</code> · " + html.EscapeString(edge.Kind))
		if edge.Condition != "" {
			out.WriteString(" · if " + html.EscapeString(edge.Condition))
		}
		out.WriteString("</li>")
	}
	out.WriteString("</ol></section></body></html>\n")
	return []byte(out.String()), nil
}

func conditionSuffix(condition string) string {
	if condition == "" {
		return ""
	}
	return " if " + condition
}

func layout(view View) (map[string]point, int, int) {
	levels := map[string]int{}
	seed := "root"
	if view.Focus != "" {
		seed = view.Focus
	}
	levels[seed] = 0
	queue := []string{seed}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, edge := range view.Edges {
			if edge.From == current {
				if _, exists := levels[edge.To]; !exists {
					levels[edge.To] = levels[current] + 1
					queue = append(queue, edge.To)
				}
			}
		}
	}
	maxLevel := 0
	for _, level := range levels {
		if level > maxLevel {
			maxLevel = level
		}
	}
	rows := map[int][]string{}
	for _, node := range view.Nodes {
		level, exists := levels[node.ID]
		if !exists {
			level = maxLevel + 1
		}
		rows[level] = append(rows[level], node.ID)
	}
	keys := make([]int, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	positions := map[string]point{}
	maxRows, maxColumns := 0, 0
	for _, level := range keys {
		ids := rows[level]
		sort.Strings(ids)
		if len(ids) > maxRows {
			maxRows = len(ids)
		}
		if level > maxColumns {
			maxColumns = level
		}
		for row, id := range ids {
			positions[id] = point{x: 35 + level*260, y: 35 + row*95}
		}
	}
	return positions, 280 + (maxColumns+1)*260, 100 + maxRows*95
}
