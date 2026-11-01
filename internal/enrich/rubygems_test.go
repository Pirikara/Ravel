package enrich

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func testBundlerDocument(names ...string) model.Document {
	doc := common.NewDocument("Gemfile.lock", "sample", "bundler", nil)
	for i, name := range names {
		id := "gem:" + common.ID(name+string(rune('0'+i)))
		doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: "3.1.0", Evidence: []model.Evidence{{Collector: "bundler-lock", InputPath: "Gemfile.lock", Method: "lockfile-analysis"}}})
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "declared_registry", SafeURL: "https://rubygems.org/", Status: "declared"})
	}
	common.Finalize(&doc)
	return doc
}

func stubClient(t *testing.T, body string, status int, count *int) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		*count++
		if request.Method != http.MethodGet || request.URL.Host != "rubygems.org" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected request: %s", request.URL)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: request, Header: make(http.Header)}, nil
	})}
}

func TestRubyGemsVersionMetadataIsVerifiedAndRedacted(t *testing.T) {
	body := `{"name":"rack","version":"3.1.0","platform":"ruby","metadata":{"source_code_uri":"https://user:example-secret@github.com/rack/rack?token=hidden"}}`
	count := 0
	now := time.Date(2026, time.October, 30, 1, 2, 3, 0, time.UTC)
	doc, err := RubyGems(context.Background(), testBundlerDocument("rack"), Options{RegistryURL: "https://rubygems.org", MaxRequests: 1, Client: stubClient(t, body, 200, &count), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256([]byte(body))
	if count != 1 || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/rack/rack" || doc.Development[0].Status != "registry_metadata" || doc.Development[0].Evidence.InputDigest != "sha256:"+hex.EncodeToString(sha[:]) || doc.Development[0].Evidence.ObservedAt != "2026-10-30T01:02:03Z" {
		t.Fatalf("registry metadata evidence wrong: %#v", doc)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "example-secret") || strings.Contains(string(encoded), "token=hidden") {
		t.Fatal("registry metadata secret leaked into Ravel JSON")
	}
}

func TestRubyGemsRejectsMismatchedAndUnsafeMetadata(t *testing.T) {
	cases := []struct {
		name, body, issue string
	}{
		{"different-version", `{"name":"rack","version":"9.9.9","platform":"ruby","metadata":{"source_code_uri":"https://github.com/rack/rack"}}`, "registry_metadata_identity_mismatch"},
		{"different-platform", `{"name":"rack","version":"3.1.0","platform":"java","metadata":{"source_code_uri":"https://github.com/rack/rack"}}`, "registry_metadata_identity_mismatch"},
		{"unsafe-source", `{"name":"rack","version":"3.1.0","platform":"ruby","metadata":{"source_code_uri":"file:///etc/passwd"}}`, "unsafe_or_invalid_development_source"},
		{"missing-source", `{"name":"rack","version":"3.1.0","platform":"ruby","metadata":{}}`, "development_source_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			doc, err := RubyGems(context.Background(), testBundlerDocument("rack"), Options{RegistryURL: "https://rubygems.org/", MaxRequests: 1, Client: stubClient(t, tc.body, 200, &count)})
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 || len(doc.Development) != 0 || len(doc.Coverage.Issues) != 1 || doc.Coverage.Issues[0].Code != tc.issue {
				t.Fatalf("untrusted metadata supplied development source: %#v", doc)
			}
		})
	}
}

func TestRubyGemsRegistrySelectionAndRequestLimit(t *testing.T) {
	count := 0
	body := `{"name":"rack","version":"3.1.0","platform":"ruby","metadata":{"source_code_uri":"https://github.com/rack/rack"}}`
	client := stubClient(t, body, 200, &count)
	doc, err := RubyGems(context.Background(), testBundlerDocument("rack"), Options{RegistryURL: "https://other.example.test", MaxRequests: 1, Client: client})
	if err != nil || count != 0 || len(doc.Development) != 0 {
		t.Fatalf("wrong registry was contacted: %v %#v", err, doc)
	}
	input := testBundlerDocument("rack", "other")
	if input.Components[0].Name != "rack" {
		input.Components[0], input.Components[1] = input.Components[1], input.Components[0]
	}
	doc, err = RubyGems(context.Background(), input, Options{RegistryURL: "https://rubygems.org", MaxRequests: 1, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(doc.Development) != 1 || len(doc.Coverage.Issues) != 1 || doc.Coverage.Issues[0].Code != "registry_metadata_request_limit" || doc.Coverage.Issues[0].Name != "other" {
		t.Fatalf("request limit did not preserve partial coverage: %#v", doc)
	}
}

func TestRubyGemsMergedOccurrencesShareRequestButKeepEvidence(t *testing.T) {
	input := testBundlerDocument("rack", "rack")
	for i := range input.Components {
		oldID := input.Components[i].ID
		input.Components[i].ID = "merge:" + common.ID(oldID)
		for j := range input.Origins {
			if input.Origins[j].Occurrence == oldID {
				input.Origins[j].Occurrence = input.Components[i].ID
			}
		}
	}
	body := `{"name":"rack","version":"3.1.0","platform":"ruby","metadata":{"source_code_uri":"https://github.com/rack/rack"}}`
	count := 0
	doc, err := RubyGems(context.Background(), input, Options{RegistryURL: "https://rubygems.org", MaxRequests: 1, Client: stubClient(t, body, 200, &count)})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(doc.Development) != 2 || doc.Development[0].Occurrence == doc.Development[1].Occurrence || len(doc.Coverage.Issues) != 0 {
		t.Fatalf("merged Bundler occurrences lost independent provenance: %#v", doc)
	}
}
