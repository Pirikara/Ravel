package export

import (
	"encoding/json"
	"sort"

	"github.com/Pirikara/Ravel/internal/model"
)

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type component struct {
	Type               string       `json:"type"`
	BomRef             string       `json:"bom-ref"`
	Name               string       `json:"name"`
	Version            string       `json:"version,omitempty"`
	PURL               string       `json:"purl,omitempty"`
	Hashes             []model.Hash `json:"hashes,omitempty"`
	Properties         []property   `json:"properties,omitempty"`
	ExternalReferences []reference  `json:"externalReferences,omitempty"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type bom struct {
	BomFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	Version      int          `json:"version"`
	Metadata     any          `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies,omitempty"`
}

func CycloneDX(doc model.Document) ([]byte, error) {
	root := component{Type: "application", BomRef: "root", Name: doc.Project}
	for _, runtime := range doc.Runtimes {
		value, err := json.Marshal(struct {
			Name        string `json:"name"`
			Requirement string `json:"requirement"`
			Relation    string `json:"relation"`
			Policy      string `json:"policy,omitempty"`
		}{runtime.Name, runtime.Requirement, runtime.Relation, runtime.Policy})
		if err != nil {
			return nil, err
		}
		root.Properties = append(root.Properties, property{Name: "ravel:runtimeRequirement", Value: string(value)})
	}
	out := bom{
		BomFormat: "CycloneDX", SpecVersion: "1.7", Version: 1,
		Metadata:   map[string]any{"component": root},
		Components: []component{},
	}
	origins := map[string][]model.Origin{}
	for _, o := range doc.Origins {
		origins[o.Occurrence] = append(origins[o.Occurrence], o)
	}
	development := map[string][]model.Development{}
	for _, source := range doc.Development {
		development[source.Occurrence] = append(development[source.Occurrence], source)
	}
	for _, c := range doc.Components {
		kind := "library"
		if c.Kind == "module" || c.Kind == "file" {
			kind = "file"
		} else if c.Kind == "application" {
			kind = "application"
		}
		item := component{Type: kind, BomRef: c.ID, Name: c.Name, Version: c.Version, PURL: c.PURL, Hashes: c.Hashes}
		if len(c.Patches) > 0 {
			// The lockfile integrity is for the unmodified tarball, not the
			// package tree after the project patch has been applied.
			item.Hashes = nil
			for _, hash := range c.Hashes {
				item.Properties = append(item.Properties, property{Name: "ravel:baseArtifactHash", Value: hash.Alg + ":" + hash.Content})
			}
			for _, patch := range c.Patches {
				item.Properties = append(item.Properties, property{Name: "ravel:patchStatus", Value: patch.Status})
				if patch.Path != "" {
					item.Properties = append(item.Properties, property{Name: "ravel:patchPath", Value: patch.Path})
				}
				if patch.Hash != nil {
					item.Properties = append(item.Properties, property{Name: "ravel:patchHash", Value: patch.Hash.Alg + ":" + patch.Hash.Content})
				}
			}
		}
		seenVCS := map[string]bool{}
		if c.Platform != "" {
			item.Properties = append(item.Properties, property{Name: "ravel:platform", Value: c.Platform})
		}
		if c.Context != "" {
			item.Properties = append(item.Properties, property{Name: "ravel:context", Value: c.Context})
		}
		for _, o := range origins[c.ID] {
			switch o.Kind {
			case "declared_registry":
				item.Properties = append(item.Properties, property{Name: "ravel:declaredRegistry", Value: o.SafeURL})
			case "vcs":
				item.ExternalReferences = append(item.ExternalReferences, reference{Type: "vcs", URL: o.SafeURL})
				seenVCS[o.SafeURL] = true
				if o.Revision != "" {
					item.Properties = append(item.Properties, property{Name: "ravel:vcsRevision", Value: o.Revision})
				}
			case "local":
				if o.LocalPath != "" {
					item.Properties = append(item.Properties, property{Name: "ravel:localPath", Value: o.LocalPath})
				}
			case "download_url":
				item.ExternalReferences = append(item.ExternalReferences, reference{Type: "distribution", URL: o.SafeURL})
			case "registry_identity":
				item.Properties = append(item.Properties, property{Name: "ravel:registryIdentity", Value: o.SafeURL})
			case "podspec":
				item.Properties = append(item.Properties, property{Name: "ravel:podspec", Value: o.SafeURL})
			case "module_replacement":
				item.Properties = append(item.Properties, property{Name: "ravel:moduleReplacement", Value: o.Target})
			case "sdk":
				item.Properties = append(item.Properties, property{Name: "ravel:sdk", Value: o.Target})
			}
		}
		for _, source := range development[c.ID] {
			if !seenVCS[source.SafeURL] {
				item.ExternalReferences = append(item.ExternalReferences, reference{Type: "vcs", URL: source.SafeURL})
				seenVCS[source.SafeURL] = true
			}
			item.Properties = append(item.Properties, property{Name: "ravel:developmentRepository", Value: source.SafeURL})
		}
		out.Components = append(out.Components, item)
	}
	edges := map[string][]string{}
	for _, e := range doc.Edges {
		if e.Condition != "" {
			continue
		}
		edges[e.From] = append(edges[e.From], e.To)
	}
	refs := []string{"root"}
	for _, c := range doc.Components {
		refs = append(refs, c.ID)
	}
	for _, ref := range refs {
		children := edges[ref]
		if len(children) == 0 && doc.Coverage.GraphState != "complete_for_scope" {
			continue
		}
		sort.Strings(children)
		if children == nil {
			children = []string{}
		}
		out.Dependencies = append(out.Dependencies, dependency{Ref: ref, DependsOn: children})
	}
	return json.MarshalIndent(out, "", "  ")
}
