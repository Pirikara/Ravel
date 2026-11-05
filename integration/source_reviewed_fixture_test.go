package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

type sourceReviewedCorpus struct {
	Cases []struct {
		Fixture          string `json:"fixture"`
		SourceFile       string `json:"sourceFile"`
		CompletePackages bool   `json:"completePackages"`
		GraphState       string `json:"graphState"`
		Packages         []struct {
			Name           string   `json:"name"`
			Version        string   `json:"version"`
			SourceFile     string   `json:"sourceFile"`
			SourceSnippets []string `json:"sourceSnippets"`
		} `json:"packages"`
		Edges []struct {
			From          string `json:"from"`
			To            string `json:"to"`
			Kind          string `json:"kind"`
			Condition     string `json:"condition"`
			SourceSnippet string `json:"sourceSnippet"`
		} `json:"edges"`
		UnknownPURL  []string `json:"unknownPURL"`
		InferredPURL []string `json:"inferredPURL"`
	} `json:"cases"`
}

// The corpus checks representative managers and format versions against their
// input files. Other scanners can suggest claims, but never supply assertions.
func TestSourceReviewedFixtureClaims(t *testing.T) {
	var corpus sourceReviewedCorpus
	for _, filename := range []string{"source_reviewed_cases.json", "source_reviewed_cases_extended.json"} {
		data, err := os.ReadFile(filepath.Join("testdata", filename))
		if err != nil {
			t.Fatal(err)
		}
		var additional sourceReviewedCorpus
		if err := json.Unmarshal(data, &additional); err != nil {
			t.Fatal(err)
		}
		corpus.Cases = append(corpus.Cases, additional.Cases...)
	}
	if len(corpus.Cases) < 50 {
		t.Fatalf("source-reviewed fixture set unexpectedly small: %d cases", len(corpus.Cases))
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Fixture, func(t *testing.T) {
			if tc.Fixture == "" || tc.SourceFile == "" || filepath.Base(tc.Fixture) != tc.Fixture || filepath.IsAbs(tc.SourceFile) || strings.Contains(tc.SourceFile, "..") {
				t.Fatal("unsafe or incomplete fixture source path")
			}
			fixture := filepath.Join("..", "testdata", "fixtures", tc.Fixture)
			source, err := os.ReadFile(filepath.Join(fixture, tc.SourceFile))
			if err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json").Output()
			if err != nil {
				t.Fatalf("scan failed: %v: %s", err, output)
			}
			var doc model.Document
			if err := json.Unmarshal(output, &doc); err != nil {
				t.Fatal(err)
			}
			components := map[string]model.Component{}
			for _, component := range doc.Components {
				key := component.Name + "@" + component.Version
				if _, duplicate := components[key]; duplicate {
					t.Fatalf("ambiguous component identity %q in fixture claims", key)
				}
				components[key] = component
			}
			for _, claim := range tc.Packages {
				key := claim.Name + "@" + claim.Version
				if _, found := components[key]; !found {
					t.Fatalf("source-reviewed package %q missing", key)
				}
				if len(claim.SourceSnippets) == 0 {
					t.Fatalf("package %q has no source evidence", key)
				}
				claimSource := source
				claimSourceFile := tc.SourceFile
				if claim.SourceFile != "" {
					if filepath.IsAbs(claim.SourceFile) || strings.Contains(claim.SourceFile, "..") {
						t.Fatalf("unsafe package source path %q", claim.SourceFile)
					}
					claimSource, err = os.ReadFile(filepath.Join(fixture, claim.SourceFile))
					if err != nil {
						t.Fatal(err)
					}
					claimSourceFile = claim.SourceFile
				}
				for _, snippet := range claim.SourceSnippets {
					if snippet == "" || !strings.Contains(string(claimSource), snippet) {
						t.Fatalf("source evidence %q for %q absent from %s", snippet, key, claimSourceFile)
					}
				}
			}
			if tc.CompletePackages && len(components) != len(tc.Packages) {
				t.Fatalf("package inventory differs from reviewed source: got %d, want %d: %#v", len(components), len(tc.Packages), components)
			}
			for _, claim := range tc.Edges {
				if claim.SourceSnippet == "" || !strings.Contains(string(source), claim.SourceSnippet) {
					t.Fatalf("edge source evidence %q absent", claim.SourceSnippet)
				}
				from := claim.From
				if from != "root" {
					component, found := components[from]
					if !found {
						t.Fatalf("edge source %q missing", from)
					}
					from = component.ID
				}
				toComponent, found := components[claim.To]
				if !found {
					t.Fatalf("edge target %q missing", claim.To)
				}
				matched := false
				for _, edge := range doc.Edges {
					if edge.From == from && edge.To == toComponent.ID && edge.Kind == claim.Kind && edge.Condition == claim.Condition {
						matched = true
					}
				}
				if !matched {
					t.Fatalf("source-reviewed edge %s -> %s (%s, %s) missing", claim.From, claim.To, claim.Kind, claim.Condition)
				}
			}
			for _, key := range tc.UnknownPURL {
				component, found := components[key]
				if !found || component.PURL != "" {
					t.Fatalf("unverified origin invented for %q: %#v", key, component)
				}
			}
			for _, key := range tc.InferredPURL {
				component, found := components[key]
				if !found || component.PURL == "" || component.PURLBasis != "ecosystem_inferred" {
					t.Fatalf("inferred ecosystem identity missing for %q: %#v", key, component)
				}
				for _, origin := range doc.Origins {
					if origin.Occurrence == component.ID && origin.Kind == "registry_identity" {
						t.Fatalf("inferred package identity claimed a registry origin for %q", key)
					}
				}
			}
			if tc.GraphState != "" && doc.Coverage.GraphState != tc.GraphState {
				t.Fatalf("graph state %q, want %q", doc.Coverage.GraphState, tc.GraphState)
			}
		})
	}
}
