package graph

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Pirikara/Ravel/internal/model"
)

const MaxNodes = 1000
const MaxEdges = 5000

type Options struct {
	Focus     string
	Direction string
	Depth     int
}

type Node struct {
	ID       string
	Name     string
	Version  string
	Kind     string
	PURL     string
	Origins  []model.Origin
	Unlinked bool
}

type View struct {
	Project   string
	Coverage  model.Coverage
	Focus     string
	Direction string
	Depth     int
	Nodes     []Node
	Edges     []model.Edge
	Unlinked  int
}

func Build(doc model.Document, options Options) (View, error) {
	if options.Direction != "dependencies" && options.Direction != "dependents" {
		return View{}, errors.New("direction must be dependencies or dependents")
	}
	if options.Depth < -1 || options.Depth > 1000 || options.Focus == "" && options.Depth >= 0 {
		return View{}, errors.New("depth must be -1 or 0..1000 and requires --focus")
	}
	if options.Focus == "" && (len(doc.Components)+1 > MaxNodes || len(doc.Edges) > MaxEdges) {
		return View{}, fmt.Errorf("graph exceeds %d nodes or %d edges; use --focus and --depth", MaxNodes, MaxEdges)
	}
	components := make(map[string]model.Component, len(doc.Components))
	for _, component := range doc.Components {
		if component.ID == "" || component.ID == "root" {
			return View{}, errors.New("invalid component ID in Ravel JSON")
		}
		if _, exists := components[component.ID]; exists {
			return View{}, fmt.Errorf("duplicate component ID %q", component.ID)
		}
		components[component.ID] = component
	}
	adjacent := make(map[string][]string)
	for _, edge := range doc.Edges {
		if edge.From != "root" {
			if _, exists := components[edge.From]; !exists {
				return View{}, fmt.Errorf("edge refers to unknown component %q", edge.From)
			}
		}
		if edge.To != "root" {
			if _, exists := components[edge.To]; !exists {
				return View{}, fmt.Errorf("edge refers to unknown component %q", edge.To)
			}
		}
		if options.Direction == "dependencies" {
			adjacent[edge.From] = append(adjacent[edge.From], edge.To)
		} else {
			adjacent[edge.To] = append(adjacent[edge.To], edge.From)
		}
	}
	focus, err := resolveFocus(components, options.Focus)
	if err != nil {
		return View{}, err
	}
	selected := map[string]bool{"root": true}
	if focus == "" {
		for id := range components {
			selected[id] = true
		}
	} else {
		selected = map[string]bool{focus: true}
		frontier := []string{focus}
		for depth := 0; len(frontier) > 0 && (options.Depth < 0 || depth < options.Depth); depth++ {
			next := []string{}
			for _, current := range frontier {
				for _, neighbor := range adjacent[current] {
					if !selected[neighbor] {
						selected[neighbor] = true
						next = append(next, neighbor)
					}
				}
			}
			frontier = next
		}
	}
	view := View{Project: doc.Project, Coverage: doc.Coverage, Focus: focus, Direction: options.Direction, Depth: options.Depth}
	incidence := map[string]int{}
	for _, edge := range doc.Edges {
		incidence[edge.From]++
		incidence[edge.To]++
		if selected[edge.From] && selected[edge.To] {
			view.Edges = append(view.Edges, edge)
		}
	}
	if selected["root"] {
		view.Nodes = append(view.Nodes, Node{ID: "root", Name: doc.Project, Kind: "project", Unlinked: incidence["root"] == 0})
	}
	for id, component := range components {
		if !selected[id] {
			continue
		}
		node := Node{ID: id, Name: component.Name, Version: component.Version, Kind: component.Kind, PURL: component.PURL, Unlinked: incidence[id] == 0}
		for _, origin := range doc.Origins {
			if origin.Occurrence == id {
				node.Origins = append(node.Origins, origin)
			}
		}
		if node.Unlinked {
			view.Unlinked++
		}
		view.Nodes = append(view.Nodes, node)
	}
	if len(view.Nodes) > MaxNodes || len(view.Edges) > MaxEdges {
		return View{}, fmt.Errorf("graph exceeds %d nodes or %d edges; use --focus and --depth", MaxNodes, MaxEdges)
	}
	sort.Slice(view.Nodes, func(i, j int) bool { return view.Nodes[i].ID < view.Nodes[j].ID })
	sort.Slice(view.Edges, func(i, j int) bool {
		a, b := view.Edges[i], view.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Condition < b.Condition
	})
	return view, nil
}

func resolveFocus(components map[string]model.Component, query string) (string, error) {
	if query == "" || query == "root" {
		return query, nil
	}
	if _, exists := components[query]; exists {
		return query, nil
	}
	match := ""
	for id, component := range components {
		if component.Name != query && (component.PURL == "" || component.PURL != query) {
			continue
		}
		if match != "" {
			return "", fmt.Errorf("package %q is ambiguous; use a component ID", query)
		}
		match = id
	}
	if match == "" {
		return "", fmt.Errorf("package %q not found", query)
	}
	return match, nil
}
