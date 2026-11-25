package export

import (
	"encoding/json"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
)

// Standard formats have no native representation for a correlation between
// an installed occurrence and a lock declaration. Retain that distinction in
// annotations rather than exporting the declaration as verified provenance.
func imageLockAnnotations(doc model.Document) map[string][]property {
	annotations := map[string][]property{}
	add := func(id, name string, value any) {
		data, _ := json.Marshal(value)
		annotations[id] = append(annotations[id], property{Name: name, Value: string(data)})
	}
	for _, c := range doc.Components {
		for _, e := range c.Evidence {
			if e.Method == "image-lockfile-correlation" {
				add(c.ID, "ravel:lockfileEvidence", e)
			}
		}
	}
	for _, origin := range doc.Origins {
		if origin.Status == "correlated_from_lockfile" {
			add(origin.Occurrence, "ravel:lockfileOrigin", origin)
		} else if origin.Status == "recorded_in_install_metadata" {
			add(origin.Occurrence, "ravel:installedOrigin", origin)
		}
	}
	for _, edge := range doc.Edges {
		if isImageLockEdge(edge) {
			add(edge.From, "ravel:lockfileDependency", edge)
		}
	}
	for _, c := range doc.Components {
		if len(annotations[c.ID]) > 0 {
			annotations[c.ID] = append([]property{{Name: "ravel:occurrence", Value: c.ID}}, annotations[c.ID]...)
		}
	}
	return annotations
}

func isAnnotatedImageOrigin(origin model.Origin) bool {
	return origin.Status == "correlated_from_lockfile" || origin.Status == "recorded_in_install_metadata"
}

func isImageLockEdge(edge model.Edge) bool {
	return edge.Evidence.Method == "image-lockfile-correlation" && strings.Contains(edge.Condition, "lockfile_installation=unverified")
}
