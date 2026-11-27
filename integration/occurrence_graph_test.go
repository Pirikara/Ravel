package integration_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOccurrenceGraphRegressions(t *testing.T) {
	for _, sample := range []struct {
		fixture, file string
		count         int
	}{
		{"npm-workspace-graph", "package-lock.json", 5},
		{"pnpm-alias-occurrences", "pnpm-lock.yaml", 6},
		{"pnpm-local-directory", "pnpm-lock.yaml", 2},
		{"uv-dev-groups", "uv.lock", 5},
		{"yarn-workspace-roots", "yarn.lock", 3},
		{"yarn-classic-bare-alias", "yarn.lock", 2},
	} {
		t.Run(sample.fixture, func(t *testing.T) {
			doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", sample.fixture, sample.file))
			if len(doc.Components) != sample.count {
				t.Fatal(doc.Components)
			}
			names := map[string]string{}
			realIDs := []string{}
			for _, c := range doc.Components {
				names[c.ID] = c.Name
				if c.Name == "real" {
					realIDs = append(realIDs, c.ID)
				}
				if sample.fixture == "pnpm-local-directory" && c.Name == "local-app" {
					if c.Kind != "application" || c.Version != "1.2.3" || c.PURL != "" || len(c.Evidence) != 2 {
						t.Fatal(c)
					}
				}
				if sample.fixture == "yarn-workspace-roots" {
					for _, e := range c.Evidence {
						if e.Collector == "yarn-berry" && e.Line == 0 {
							t.Fatal(e)
						}
					}
				}
			}
			if sample.fixture == "pnpm-alias-occurrences" && (len(realIDs) != 2 || realIDs[0] == realIDs[1]) {
				t.Fatal(realIDs)
			}
			seen := map[string]bool{}
			for _, e := range doc.Edges {
				key := names[e.From] + "->" + names[e.To]
				seen[key] = true
				switch sample.fixture {
				case "npm-workspace-graph":
					if names[e.To] == "peer" && (e.Kind != "peer_requirement" || e.Condition == "") {
						t.Fatal(e)
					}
					if names[e.To] == "builder" && e.Kind != "direct_dev" {
						t.Fatal(e)
					}
				case "pnpm-alias-occurrences":
					if names[e.To] == "binary" && (!strings.Contains(e.Condition, "optional") || !strings.Contains(e.Condition, "platform=linux/x64")) {
						t.Fatal(e)
					}
				case "uv-dev-groups":
					for name, condition := range map[string]string{"pytest": "group=dev", "sphinx": "group=docs", "pillow": "extra=image"} {
						if names[e.To] == name && !strings.Contains(e.Condition, condition) {
							t.Fatal(e)
						}
					}
				}
			}
			switch sample.fixture {
			case "npm-workspace-graph":
				for _, edge := range []string{"app->lib", "app->builder", "app->peer", "app->shared"} {
					if !seen[edge] {
						t.Fatal(edge, doc.Edges)
					}
				}
			case "pnpm-alias-occurrences":
				if !seen["real->helper"] || !seen["real->binary"] {
					t.Fatal(doc.Edges)
				}
			case "pnpm-local-directory":
				if !seen["local-app->leaf"] || len(doc.Development) != 1 {
					t.Fatal(doc.Edges, doc.Development)
				}
			case "uv-dev-groups":
				for _, edge := range []string{"group-app->pytest", "group-app->sphinx", "group-app->pillow"} {
					if !seen[edge] {
						t.Fatal(edge, doc.Edges)
					}
				}
			case "yarn-classic-bare-alias":
				if !seen["target->leaf"] {
					t.Fatal(doc.Edges)
				}
			}
			assertDevelopmentExports(t, doc)
		})
	}
}
