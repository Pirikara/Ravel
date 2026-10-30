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

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const pyPITestHash = "946d195a0d259cbba61165e88e65941f16e9b36ea6ddb97f00452bae8b1287d3"

func pyPITestDocument(collector string) model.Document {
	doc := common.NewDocument("uv.lock", "sample", "uv", nil)
	doc.Components = append(doc.Components, model.Component{ID: "python:one", Kind: "package", Name: "IDNA", Version: "3.10", Hashes: []model.Hash{{Alg: "SHA-256", Content: pyPITestHash}}, Evidence: []model.Evidence{{Collector: collector}}})
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: "python:one", Kind: "declared_registry", SafeURL: "https://pypi.org/simple"})
	common.Finalize(&doc)
	return doc
}

func pyPITestClient(t *testing.T, body string, count *int) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		*count++
		if request.URL.String() != "https://pypi.org/pypi/idna/3.10/json" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected PyPI endpoint: %s", request.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Request: request, Header: make(http.Header)}, nil
	})}
}

func TestPyPIRequiresMatchingReleaseArtifact(t *testing.T) {
	body := `{"info":{"name":"idna","version":"3.10","project_urls":{"Source":"https://user:example-secret@github.com/kjd/idna?token=hidden"}},"urls":[{"url":"https://files.pythonhosted.org/idna.whl","digests":{"sha256":"` + pyPITestHash + `"}}]}`
	count := 0
	now := time.Date(2026, time.October, 30, 1, 2, 3, 0, time.UTC)
	doc, err := PyPI(context.Background(), pyPITestDocument("uv-lock"), Options{RegistryURL: "https://pypi.org", MaxRequests: 1, Client: pyPITestClient(t, body, &count), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256([]byte(body))
	if count != 1 || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/kjd/idna" || doc.Development[0].Evidence.InputDigest != "sha256:"+hex.EncodeToString(sha[:]) || doc.Development[0].Evidence.Pointer != "/info/project_urls/Source" || doc.Development[0].Evidence.ObservedAt != "2026-10-30T01:02:03Z" {
		t.Fatalf("PyPI artifact identity or evidence wrong: %#v", doc)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "example-secret") || strings.Contains(string(encoded), "token=hidden") {
		t.Fatal("PyPI metadata secret leaked")
	}
}

func TestPyPIRejectsUnverifiedMetadata(t *testing.T) {
	cases := []struct {
		name, body, issue string
	}{
		{"wrong-name", `{"info":{"name":"other","version":"3.10","project_urls":{"Source":"https://github.com/kjd/idna"}},"urls":[]}`, "registry_metadata_identity_mismatch"},
		{"wrong-version", `{"info":{"name":"idna","version":"3.11","project_urls":{"Source":"https://github.com/kjd/idna"}},"urls":[]}`, "registry_metadata_identity_mismatch"},
		{"wrong-hash", `{"info":{"name":"idna","version":"3.10","project_urls":{"Source":"https://github.com/kjd/idna"}},"urls":[{"url":"https://files.pythonhosted.org/idna.whl","digests":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}`, "registry_metadata_artifact_mismatch"},
		{"unsafe-source", `{"info":{"name":"idna","version":"3.10","project_urls":{"Source":"file:///etc/passwd"}},"urls":[{"url":"https://files.pythonhosted.org/idna.whl","digests":{"sha256":"` + pyPITestHash + `"}}]}`, "unsafe_or_invalid_development_source"},
		{"missing-source", `{"info":{"name":"idna","version":"3.10","project_urls":{"Homepage":"https://example.test"}},"urls":[{"url":"https://files.pythonhosted.org/idna.whl","digests":{"sha256":"` + pyPITestHash + `"}}]}`, "development_source_unavailable"},
		{"ambiguous-source", `{"info":{"name":"idna","version":"3.10","project_urls":{"Source":"https://github.com/kjd/idna","Repository":"https://gitlab.example.test/idna"}},"urls":[{"url":"https://files.pythonhosted.org/idna.whl","digests":{"sha256":"` + pyPITestHash + `"}}]}`, "ambiguous_development_source"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			doc, err := PyPI(context.Background(), pyPITestDocument("pylock"), Options{RegistryURL: "https://pypi.org", MaxRequests: 1, Client: pyPITestClient(t, tc.body, &count)})
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 || len(doc.Development) != 0 || len(doc.Coverage.Issues) != 1 || doc.Coverage.Issues[0].Code != tc.issue {
				t.Fatalf("unverified metadata supplied a development source: %#v", doc)
			}
		})
	}
}

func TestPyPISkipsUnknownIndexAndMissingHash(t *testing.T) {
	count := 0
	body := `{"info":{"name":"idna","version":"3.10"}}`
	client := pyPITestClient(t, body, &count)
	doc := pyPITestDocument("uv-lock")
	doc.Origins[0].SafeURL = "https://private.example.test/simple"
	doc, err := PyPI(context.Background(), doc, Options{RegistryURL: "https://pypi.org", MaxRequests: 1, Client: client})
	if err != nil || count != 0 || len(doc.Development) != 0 {
		t.Fatalf("unselected index was queried: %v %#v", err, doc)
	}
	doc = pyPITestDocument("uv-lock")
	doc.Components[0].Hashes = nil
	doc, err = PyPI(context.Background(), doc, Options{RegistryURL: "https://pypi.org", MaxRequests: 1, Client: client})
	if err != nil || count != 0 || len(doc.Development) != 0 || len(doc.Coverage.Issues) != 1 || doc.Coverage.Issues[0].Code != "registry_metadata_artifact_unverified" {
		t.Fatalf("unhashed artifact was queried: %v %#v", err, doc)
	}
}

func TestPyPISourcePointerIsStableForDuplicateLabels(t *testing.T) {
	for range 50 {
		source, pointer, issue := pyPISource(map[string]string{"Source": "https://github.com/kjd/idna", "Repository": "https://github.com/kjd/idna"})
		if source != "https://github.com/kjd/idna" || pointer != "/info/project_urls/Source" || issue != "" {
			t.Fatalf("unstable PyPI source evidence: %q %q %q", source, pointer, issue)
		}
	}
}
