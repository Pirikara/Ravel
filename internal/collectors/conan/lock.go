package conan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const maxLockBytes = 16 << 20

type lockfile struct {
	Version        string   `json:"version"`
	GraphLock      *graph   `json:"graph_lock"`
	Requires       []string `json:"requires"`
	BuildRequires  []string `json:"build_requires"`
	PythonRequires []string `json:"python_requires"`
	ConfigRequires []string `json:"config_requires"`
}

type graph struct {
	Nodes map[string]node `json:"nodes"`
}

type node struct {
	Ref       string   `json:"ref"`
	Requires  []string `json:"requires"`
	Context   string   `json:"context"`
	PackageID string   `json:"package_id"`
	Prev      string   `json:"prev"`
}

type reference struct {
	name, version, user, channel, rrev string
}

// Collect inventories the graph in Conan 1 lockfiles and the candidate set in
// Conan 2 lockfiles. A Conan 2 lockfile can contain unused entries from earlier
// configurations, so it does not establish a selected dependency graph.
func Collect(filename, project string) (model.Document, error) {
	file, err := os.Open(filename)
	if err != nil {
		return model.Document{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxLockBytes || info.Size() <= 0 {
		return model.Document{}, errors.New("Conan lockfile size is invalid or exceeds 16 MiB")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid Conan lockfile: %w", err)
	}
	doc := common.NewDocument(filename, project, "conan", data)
	baseEvidence := common.Evidence(filename, "conan-lock", "", data)
	switch lock.Version {
	case "0.4":
		if lock.GraphLock == nil || lock.GraphLock.Nodes == nil {
			return model.Document{}, errors.New("Conan 1 lockfile has no graph nodes")
		}
		collectV1(&doc, filename, baseEvidence, lock.GraphLock.Nodes)
	case "0.5":
		if lock.GraphLock != nil {
			return model.Document{}, errors.New("Conan 2 lockfile unexpectedly contains graph_lock")
		}
		collectV2(&doc, filename, baseEvidence, lock)
	default:
		return model.Document{}, fmt.Errorf("unsupported Conan lockfile version %q", lock.Version)
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conan_distribution_origin_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

func collectV1(doc *model.Document, filename string, baseEvidence model.Evidence, nodes map[string]node) {
	keys := make([]string, 0, len(nodes))
	for id := range nodes {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	ids := map[string]string{}
	indegree := map[string]int{}
	for _, key := range keys {
		n := nodes[key]
		if n.Ref == "" {
			continue
		}
		ref, err := parseReference(n.Ref)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conan_invalid_reference", Name: key})
			continue
		}
		id := "conan:" + common.ID(filename+"\x00"+key+"\x00"+n.Ref)
		ids[key] = id
		context := "node=" + key
		if n.Context != "" {
			context += ";context=" + n.Context
		}
		if n.PackageID != "" {
			context += ";package-id=" + n.PackageID
		}
		if n.Prev != "" {
			context += ";package-revision=" + n.Prev
		}
		evidence := baseEvidence
		evidence.Pointer = "/graph_lock/nodes/" + key
		doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: ref.name, Version: ref.version, Context: context, PURL: ref.purl(), Evidence: []model.Evidence{evidence}})
	}
	for _, key := range keys {
		n := nodes[key]
		for _, child := range n.Requires {
			childID, ok := ids[child]
			if !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conan_unresolved_node", Name: child, Scope: key})
				continue
			}
			indegree[child]++
			from := ids[key]
			if from == "" {
				from = "root"
			}
			condition := ""
			if nodes[child].Context == "build" {
				condition = "build context"
			}
			evidence := baseEvidence
			evidence.Pointer = "/graph_lock/nodes/" + key + "/requires"
			doc.Edges = append(doc.Edges, model.Edge{From: from, To: childID, Kind: "requires", Condition: condition, Evidence: evidence})
		}
	}
	for _, key := range keys {
		if id := ids[key]; id != "" && indegree[key] == 0 {
			evidence := baseEvidence
			evidence.Pointer = "/graph_lock/nodes/" + key
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "requires", Evidence: evidence})
		}
	}
	if len(nodes) == 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conan_dependency_graph_unavailable"})
	}
}

func collectV2(doc *model.Document, filename string, baseEvidence model.Evidence, lock lockfile) {
	for _, category := range []struct {
		name string
		refs []string
	}{
		{"requires", lock.Requires}, {"build_requires", lock.BuildRequires},
		{"python_requires", lock.PythonRequires}, {"config_requires", lock.ConfigRequires},
	} {
		for i, raw := range category.refs {
			ref, err := parseReference(raw)
			if err != nil {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conan_invalid_reference", Name: raw})
				continue
			}
			pointer := fmt.Sprintf("/%s/%d", category.name, i)
			evidence := baseEvidence
			evidence.Pointer = pointer
			id := "conan:" + common.ID(filename+"\x00"+pointer+"\x00"+raw)
			doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: ref.name, Version: ref.version, Context: "lock-category=" + category.name + ";selection=unverified", PURL: ref.purl(), Evidence: []model.Evidence{evidence}})
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "conan_lock_selection_unverified"},
		model.Issue{Code: "conan_dependency_graph_unavailable"})
}

func parseReference(raw string) (reference, error) {
	if raw == "" || len(raw) > 512 || strings.ContainsAny(raw, "\x00\r\n\t :?\\") {
		return reference{}, errors.New("invalid Conan reference")
	}
	text, _, _ := strings.Cut(raw, "%")
	base, revision, hasRevision := strings.Cut(text, "#")
	if hasRevision && (revision == "" || strings.Contains(revision, "#")) {
		return reference{}, errors.New("invalid Conan recipe revision")
	}
	packagePart, userChannel, hasUser := strings.Cut(base, "@")
	name, version, ok := strings.Cut(packagePart, "/")
	if !ok || name == "" || version == "" || strings.Contains(version, "/") || strings.ContainsAny(name+version, "@#%") {
		return reference{}, errors.New("invalid Conan package name or version")
	}
	ref := reference{name: name, version: version, rrev: revision}
	if hasUser {
		ref.user, ref.channel, ok = strings.Cut(userChannel, "/")
		if !ok || ref.user == "" || ref.channel == "" || strings.Contains(ref.channel, "/") || strings.ContainsAny(userChannel, "@#%") {
			return reference{}, errors.New("invalid Conan user or channel")
		}
	}
	return ref, nil
}

func (r reference) purl() string {
	qualifiers := packageurl.Qualifiers{}
	if r.user != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "user", Value: r.user}, packageurl.Qualifier{Key: "channel", Value: r.channel})
	}
	if r.rrev != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "rrev", Value: r.rrev})
	}
	return packageurl.NewPackageURL("conan", "", r.name, r.version, qualifiers, "").ToString()
}
