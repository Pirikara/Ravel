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

const npmTestTarball = "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"

func npmTestDocument(collector string) model.Document {
	doc := common.NewDocument("package-lock.json", "sample", "npm", nil)
	doc.Components = append(doc.Components, model.Component{ID: "npm:one", Kind: "package", Name: "is-number", Version: "7.0.0", Evidence: []model.Evidence{{Collector: collector, InputPath: "package-lock.json", Method: "lockfile-analysis"}}})
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: "npm:one", Kind: "download_url", SafeURL: npmTestTarball, Status: "declared"})
	common.Finalize(&doc)
	return doc
}

func npmClient(t *testing.T, body string, status int, count *int) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		*count++
		if request.URL.String() != "https://registry.npmjs.org/is-number/7.0.0" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected npm endpoint: %s", request.URL)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: request, Header: make(http.Header)}, nil
	})}
}

func TestNPMVersionAndTarballAreVerifiedBeforeRepository(t *testing.T) {
	body := `{"name":"is-number","version":"7.0.0","dist":{"tarball":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"},"repository":{"url":"git+https://user:example-secret@github.com/jonschlinkert/is-number.git?token=hidden","type":"git"}}`
	count := 0
	now := time.Date(2026, time.October, 30, 1, 2, 3, 0, time.UTC)
	doc, err := NPM(context.Background(), npmTestDocument("npm-lock"), Options{RegistryURL: "https://registry.npmjs.org", MaxRequests: 1, Client: npmClient(t, body, 200, &count), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256([]byte(body))
	if count != 1 || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/jonschlinkert/is-number.git" || doc.Development[0].Status != "registry_metadata" || doc.Development[0].Evidence.InputDigest != "sha256:"+hex.EncodeToString(sha[:]) || doc.Development[0].Evidence.ObservedAt != "2026-10-30T01:02:03Z" {
		t.Fatalf("npm registry metadata evidence wrong: %#v", doc)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "example-secret") || strings.Contains(string(encoded), "token=hidden") {
		t.Fatal("npm registry metadata secret leaked")
	}
}

func TestNPMRejectsMismatchedAndUnsafeMetadata(t *testing.T) {
	cases := []struct {
		name, body, issue string
	}{
		{"wrong-version", `{"name":"is-number","version":"8.0.0","dist":{"tarball":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"},"repository":"https://github.com/jonschlinkert/is-number"}`, "registry_metadata_identity_mismatch"},
		{"wrong-tarball", `{"name":"is-number","version":"7.0.0","dist":{"tarball":"https://registry.npmjs.org/is-number/-/other-7.0.0.tgz"},"repository":"https://github.com/jonschlinkert/is-number"}`, "registry_metadata_artifact_mismatch"},
		{"unsafe-repository", `{"name":"is-number","version":"7.0.0","dist":{"tarball":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"},"repository":"file:///etc/passwd"}`, "unsafe_or_invalid_development_source"},
		{"missing-repository", `{"name":"is-number","version":"7.0.0","dist":{"tarball":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"}}`, "development_source_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			doc, err := NPM(context.Background(), npmTestDocument("pnpm-lock"), Options{RegistryURL: "https://registry.npmjs.org", MaxRequests: 1, Client: npmClient(t, tc.body, 200, &count)})
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 || len(doc.Development) != 0 || len(doc.Coverage.Issues) != 1 || doc.Coverage.Issues[0].Code != tc.issue {
				t.Fatalf("unverified npm metadata supplied development source: %#v", doc)
			}
		})
	}
}

func TestNPMSkipsOtherRegistry(t *testing.T) {
	count := 0
	body := `{"name":"is-number","version":"7.0.0"}`
	doc, err := NPM(context.Background(), npmTestDocument("npm-lock"), Options{RegistryURL: "https://other.example.test", MaxRequests: 1, Client: npmClient(t, body, 200, &count)})
	if err != nil || count != 0 || len(doc.Development) != 0 {
		t.Fatalf("wrong npm registry was contacted: %v %#v", err, doc)
	}
}

func TestNPMScopedPackageUsesEncodedVersionEndpoint(t *testing.T) {
	doc := common.NewDocument("package-lock.json", "sample", "npm", nil)
	doc.Components = append(doc.Components, model.Component{ID: "npm:scoped", Kind: "package", Name: "@scope/tool", Version: "1.0.0", Evidence: []model.Evidence{{Collector: "npm-lock"}}})
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: "npm:scoped", Kind: "download_url", SafeURL: "https://registry.npmjs.org/@scope/tool/-/tool-1.0.0.tgz"})
	count := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		count++
		if request.URL.String() != "https://registry.npmjs.org/@scope%2Ftool/1.0.0" {
			t.Fatalf("scoped npm endpoint was not encoded: %s", request.URL)
		}
		body := `{"name":"@scope/tool","version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/@scope/tool/-/tool-1.0.0.tgz"},"repository":"https://github.com/scope/tool"}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Request: request, Header: make(http.Header)}, nil
	})}
	doc, err := NPM(context.Background(), doc, Options{RegistryURL: "https://registry.npmjs.org", MaxRequests: 1, Client: client})
	if err != nil || count != 1 || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/scope/tool" {
		t.Fatalf("scoped npm package was not enriched: %v %#v", err, doc)
	}
}
