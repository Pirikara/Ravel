package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
)

// Diff compares two Ravel documents by occurrence ID. Evidence file paths and
// digests are intentionally excluded from change detection.
type Diff struct {
	AddedComponents    []model.Component          `json:"addedComponents"`
	RemovedComponents  []model.Component          `json:"removedComponents"`
	ChangedComponents  []ComponentChange          `json:"changedComponents"`
	AddedEdges         []model.Edge               `json:"addedEdges"`
	RemovedEdges       []model.Edge               `json:"removedEdges"`
	AddedOrigins       []model.Origin             `json:"addedOrigins"`
	RemovedOrigins     []model.Origin             `json:"removedOrigins"`
	AddedDevelopment   []model.Development        `json:"addedDevelopment"`
	RemovedDevelopment []model.Development        `json:"removedDevelopment"`
	RootChange         *RootChange                `json:"rootChange,omitempty"`
	AddedRuntimes      []model.RuntimeRequirement `json:"addedRuntimes"`
	RemovedRuntimes    []model.RuntimeRequirement `json:"removedRuntimes"`
	BeforeCoverage     model.Coverage             `json:"beforeCoverage"`
	AfterCoverage      model.Coverage             `json:"afterCoverage"`
}

type ComponentChange struct {
	Before model.Component `json:"before"`
	After  model.Component `json:"after"`
}

type RootChange struct {
	Before *model.ProjectIdentity `json:"before"`
	After  *model.ProjectIdentity `json:"after"`
}

func Compare(before, after model.Document) Diff {
	result := Diff{
		AddedComponents: []model.Component{}, RemovedComponents: []model.Component{}, ChangedComponents: []ComponentChange{},
		AddedEdges: []model.Edge{}, RemovedEdges: []model.Edge{}, AddedOrigins: []model.Origin{}, RemovedOrigins: []model.Origin{}, AddedDevelopment: []model.Development{}, RemovedDevelopment: []model.Development{},
		AddedRuntimes: []model.RuntimeRequirement{}, RemovedRuntimes: []model.RuntimeRequirement{},
		BeforeCoverage: before.Coverage, AfterCoverage: after.Coverage,
	}
	if !sameRoot(before.Root, after.Root) {
		result.RootChange = &RootChange{Before: before.Root, After: after.Root}
	}
	previousRuntimes, currentRuntimes := map[string]model.RuntimeRequirement{}, map[string]model.RuntimeRequirement{}
	for _, runtime := range before.Runtimes {
		previousRuntimes[runtimeKey(runtime)] = runtime
	}
	for _, runtime := range after.Runtimes {
		currentRuntimes[runtimeKey(runtime)] = runtime
	}
	for key, runtime := range previousRuntimes {
		if _, found := currentRuntimes[key]; !found {
			result.RemovedRuntimes = append(result.RemovedRuntimes, runtime)
		}
	}
	for key, runtime := range currentRuntimes {
		if _, found := previousRuntimes[key]; !found {
			result.AddedRuntimes = append(result.AddedRuntimes, runtime)
		}
	}
	sort.Slice(result.AddedRuntimes, func(i, j int) bool { return runtimeKey(result.AddedRuntimes[i]) < runtimeKey(result.AddedRuntimes[j]) })
	sort.Slice(result.RemovedRuntimes, func(i, j int) bool {
		return runtimeKey(result.RemovedRuntimes[i]) < runtimeKey(result.RemovedRuntimes[j])
	})
	previous := make(map[string]model.Component, len(before.Components))
	current := make(map[string]model.Component, len(after.Components))
	for _, component := range before.Components {
		previous[component.ID] = component
	}
	for _, component := range after.Components {
		current[component.ID] = component
	}
	for id, component := range previous {
		next, ok := current[id]
		if !ok {
			result.RemovedComponents = append(result.RemovedComponents, component)
		} else if !sameComponent(component, next) {
			result.ChangedComponents = append(result.ChangedComponents, ComponentChange{Before: component, After: next})
		}
	}
	for id, component := range current {
		if _, ok := previous[id]; !ok {
			result.AddedComponents = append(result.AddedComponents, component)
		}
	}
	sort.Slice(result.AddedComponents, func(i, j int) bool { return result.AddedComponents[i].ID < result.AddedComponents[j].ID })
	sort.Slice(result.RemovedComponents, func(i, j int) bool { return result.RemovedComponents[i].ID < result.RemovedComponents[j].ID })
	sort.Slice(result.ChangedComponents, func(i, j int) bool {
		return result.ChangedComponents[i].Before.ID < result.ChangedComponents[j].Before.ID
	})
	beforeEdges := make(map[string]model.Edge, len(before.Edges))
	afterEdges := make(map[string]model.Edge, len(after.Edges))
	for _, edge := range before.Edges {
		beforeEdges[edgeKey(edge)] = edge
	}
	for _, edge := range after.Edges {
		afterEdges[edgeKey(edge)] = edge
	}
	for key, edge := range beforeEdges {
		if _, ok := afterEdges[key]; !ok {
			result.RemovedEdges = append(result.RemovedEdges, edge)
		}
	}
	for key, edge := range afterEdges {
		if _, ok := beforeEdges[key]; !ok {
			result.AddedEdges = append(result.AddedEdges, edge)
		}
	}
	sort.Slice(result.AddedEdges, func(i, j int) bool { return edgeKey(result.AddedEdges[i]) < edgeKey(result.AddedEdges[j]) })
	sort.Slice(result.RemovedEdges, func(i, j int) bool { return edgeKey(result.RemovedEdges[i]) < edgeKey(result.RemovedEdges[j]) })
	beforeOrigins := make(map[string]model.Origin, len(before.Origins))
	afterOrigins := make(map[string]model.Origin, len(after.Origins))
	for _, origin := range before.Origins {
		beforeOrigins[originKey(origin)] = origin
	}
	for _, origin := range after.Origins {
		afterOrigins[originKey(origin)] = origin
	}
	for key, origin := range beforeOrigins {
		if _, ok := afterOrigins[key]; !ok {
			result.RemovedOrigins = append(result.RemovedOrigins, origin)
		}
	}
	for key, origin := range afterOrigins {
		if _, ok := beforeOrigins[key]; !ok {
			result.AddedOrigins = append(result.AddedOrigins, origin)
		}
	}
	sort.Slice(result.AddedOrigins, func(i, j int) bool { return originKey(result.AddedOrigins[i]) < originKey(result.AddedOrigins[j]) })
	sort.Slice(result.RemovedOrigins, func(i, j int) bool { return originKey(result.RemovedOrigins[i]) < originKey(result.RemovedOrigins[j]) })
	beforeDevelopment := map[string]model.Development{}
	afterDevelopment := map[string]model.Development{}
	for _, source := range before.Development {
		beforeDevelopment[developmentKey(source)] = source
	}
	for _, source := range after.Development {
		afterDevelopment[developmentKey(source)] = source
	}
	for key, source := range beforeDevelopment {
		if _, ok := afterDevelopment[key]; !ok {
			result.RemovedDevelopment = append(result.RemovedDevelopment, source)
		}
	}
	for key, source := range afterDevelopment {
		if _, ok := beforeDevelopment[key]; !ok {
			result.AddedDevelopment = append(result.AddedDevelopment, source)
		}
	}
	sort.Slice(result.AddedDevelopment, func(i, j int) bool {
		return developmentKey(result.AddedDevelopment[i]) < developmentKey(result.AddedDevelopment[j])
	})
	sort.Slice(result.RemovedDevelopment, func(i, j int) bool {
		return developmentKey(result.RemovedDevelopment[i]) < developmentKey(result.RemovedDevelopment[j])
	})
	return result
}

func sameRoot(a, b *model.ProjectIdentity) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Name == b.Name && a.Version == b.Version
}

func runtimeKey(runtime model.RuntimeRequirement) string {
	runtime.Evidence = model.Evidence{}
	encoded, _ := json.Marshal(runtime)
	return string(encoded)
}

func developmentKey(source model.Development) string {
	return strings.Join([]string{source.Occurrence, source.SafeURL, source.Status}, "\x00")
}

func sameComponent(a, b model.Component) bool {
	a.Evidence, b.Evidence = nil, nil
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func edgeKey(edge model.Edge) string {
	return strings.Join([]string{edge.From, edge.To, edge.Kind, edge.Condition}, "\x00")
}
func originKey(origin model.Origin) string {
	return strings.Join([]string{origin.Occurrence, origin.Kind, origin.SafeURL, origin.LocalPath, origin.Target, origin.Revision, origin.VCSType, origin.Status}, "\x00")
}

func DiffText(diff Diff) string {
	var lines []string
	if change := diff.RootChange; change != nil {
		switch {
		case change.Before == nil:
			lines = append(lines, "+ application "+rootLabel(change.After))
		case change.After == nil:
			lines = append(lines, "- application "+rootLabel(change.Before))
		default:
			lines = append(lines, "~ application "+rootLabel(change.Before)+" -> "+rootLabel(change.After))
		}
	}
	for _, runtime := range diff.RemovedRuntimes {
		lines = append(lines, "- runtime "+runtimeLabel(runtime))
	}
	for _, runtime := range diff.AddedRuntimes {
		lines = append(lines, "+ runtime "+runtimeLabel(runtime))
	}
	for _, component := range diff.RemovedComponents {
		lines = append(lines, "- package "+component.Name+"@"+component.Version+" ["+component.ID+"]")
	}
	for _, component := range diff.AddedComponents {
		lines = append(lines, "+ package "+component.Name+"@"+component.Version+" ["+component.ID+"]")
	}
	for _, change := range diff.ChangedComponents {
		lines = append(lines, "~ package "+change.Before.Name+"@"+change.Before.Version+" -> "+change.After.Name+"@"+change.After.Version+" ["+change.Before.ID+"]")
	}
	for _, edge := range diff.RemovedEdges {
		lines = append(lines, "- edge "+edge.From+" -> "+edge.To+" ("+edge.Kind+")")
	}
	for _, edge := range diff.AddedEdges {
		lines = append(lines, "+ edge "+edge.From+" -> "+edge.To+" ("+edge.Kind+")")
	}
	for _, origin := range diff.RemovedOrigins {
		lines = append(lines, "- origin "+origin.Occurrence+" "+origin.Kind+" "+origin.SafeURL+origin.LocalPath+origin.Target)
	}
	for _, origin := range diff.AddedOrigins {
		lines = append(lines, "+ origin "+origin.Occurrence+" "+origin.Kind+" "+origin.SafeURL+origin.LocalPath+origin.Target)
	}
	for _, source := range diff.RemovedDevelopment {
		lines = append(lines, "- development "+source.Occurrence+" "+source.SafeURL)
	}
	for _, source := range diff.AddedDevelopment {
		lines = append(lines, "+ development "+source.Occurrence+" "+source.SafeURL)
	}
	lines = append(lines, fmt.Sprintf("coverage: graph %s -> %s; origin %s -> %s", diff.BeforeCoverage.GraphState, diff.AfterCoverage.GraphState, diff.BeforeCoverage.OriginState, diff.AfterCoverage.OriginState))
	return strings.Join(lines, "\n") + "\n"
}

func rootLabel(root *model.ProjectIdentity) string {
	if root.Version == "" {
		return root.Name
	}
	return root.Name + "@" + root.Version
}

func runtimeLabel(runtime model.RuntimeRequirement) string {
	label := runtime.Name + " " + runtime.Relation + " " + strconv.Quote(runtime.Requirement) + " [" + runtime.Scope + "]"
	if runtime.Policy != "" {
		label += " (policy " + strconv.Quote(runtime.Policy) + ")"
	}
	return label
}
