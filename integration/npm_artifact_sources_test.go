package integration_test

import (
	"encoding/json"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNpmArtifactSourcesAcrossManagersAndFormats(t *testing.T) {
	want := map[string]string{
		"parse-tokens":       "https://registry.npmjs.org/parse-tokens/-/parse-tokens-1.2.3.tgz",
		"@demo/theme-tokens": "https://registry.example.test/api/npm/team/@demo/theme-tokens/-/@demo/theme-tokens-1.2.3.tgz",
	}
	for _, manager := range []string{"npm", "pnpm", "yarn-classic", "yarn-berry", "bun"} {
		t.Run(manager, func(t *testing.T) {
			input := filepath.Join("..", "testdata", "fixtures", manager+"-artifact-sources")
			doc := scanDevelopmentSample(t, input)
			if len(doc.Components) != len(want) {
				t.Fatal("unexpected package inventory", doc.Components)
			}
			for _, c := range doc.Components {
				location := want[c.Name]
				if location == "" {
					t.Fatal("unexpected package", c)
				}
				found := false
				for _, o := range doc.Origins {
					if o.Occurrence == c.ID && o.Kind == "download_url" && o.SafeURL == location {
						found = true
					}
				}
				if !found {
					t.Fatal("recorded distribution URL lost", c.Name, doc.Origins)
				}
				if c.Name == "parse-tokens" {
					if c.PURL != "pkg:npm/parse-tokens@1.2.3" {
						t.Fatal("default registry coordinate changed", c)
					}
				} else {
					_, query, _ := strings.Cut(c.PURL, "?")
					values, err := url.ParseQuery(query)
					if err != nil || values.Get("download_url") != location || c.PURLBasis != "source_qualified" {
						t.Fatal("custom distribution source missing from PURL", c)
					}
				}
			}
			for _, i := range doc.Coverage.Issues {
				if i.Code == "unsafe_or_invalid_source" {
					t.Fatal("valid package source rejected", i)
				}
			}
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				out, err := exec.Command(executable, "scan", input, "--format", format).Output()
				if err != nil {
					t.Fatal(err)
				}
				var result struct {
					Components []struct {
						Name               string
						ExternalReferences []struct{ Type, URL string }
					}
					Packages []struct{ Name, DownloadLocation, SourceInfo string }
				}
				if err := json.Unmarshal(out, &result); err != nil {
					t.Fatal(err)
				}
				matched := map[string]bool{}
				for _, c := range result.Components {
					for _, r := range c.ExternalReferences {
						if r.Type == "distribution" && r.URL == want[c.Name] {
							matched[c.Name] = true
						}
					}
				}
				for _, p := range result.Packages {
					if location, ok := want[p.Name]; ok && p.DownloadLocation == location && strings.Contains(p.SourceInfo, location) {
						matched[p.Name] = true
					}
				}
				if len(matched) != len(want) {
					t.Fatal("standard export lost a distribution source", format, matched)
				}
			}
		})
	}
}
