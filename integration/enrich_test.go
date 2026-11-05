package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestRubyGemsEnrichCLI(t *testing.T) {
	response, err := os.ReadFile(filepath.Join("..", "testdata", "api", "rubygems", "rack-3.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/api/v2/rubygems/rack/versions/3.1.0.json" || r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected registry request: %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	defer server.Close()
	certFile := filepath.Join(t.TempDir(), "registry-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certFile, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(t.TempDir(), "Gemfile.lock")
	lockContent := "GEM\n  remote: " + server.URL + "\n  specs:\n    rack (3.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 3.1.0)\n"
	if err := os.WriteFile(lock, []byte(lockContent), 0o644); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "lock.ravel.json")
	if output, err := exec.Command(executable, "scan", lock, "--format", "ravel-json", "--output", input).CombinedOutput(); err != nil {
		t.Fatalf("Bundler scan failed: %v, %s", err, output)
	}
	if output, err := exec.Command(executable, "enrich", input, "--registry", server.URL).CombinedOutput(); err == nil || !strings.Contains(string(output), "--network allow") {
		t.Fatalf("enrich contacted registry without opt-in: %v, %s", err, output)
	}
	if requests.Load() != 0 {
		t.Fatal("RubyGems registry was contacted without network opt-in")
	}
	result := filepath.Join(t.TempDir(), "enriched.ravel.json")
	cmd := exec.Command(executable, "enrich", input, "--network", "allow", "--registry", server.URL, "--output", result)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("RubyGems enrichment failed: %v, %s", err, output)
	}
	if requests.Load() != 1 {
		t.Fatalf("expected one registry request, got %d", requests.Load())
	}
	encoded, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(encoded, &doc); err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(response)
	if len(doc.Components) != 1 || doc.Components[0].Name != "rack" || doc.Components[0].PURL != "" || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/rack/rack" || doc.Development[0].Status != "registry_metadata" || doc.Development[0].Evidence.InputDigest != "sha256:"+hex.EncodeToString(sha[:]) || doc.Development[0].Evidence.InputPath != server.URL+"/api/v2/rubygems/rack/versions/3.1.0.json" {
		t.Fatalf("RubyGems metadata was not attached with evidence: %#v", doc)
	}
	if _, err := time.Parse(time.RFC3339, doc.Development[0].Evidence.ObservedAt); err != nil {
		t.Fatalf("registry observation time missing: %q", doc.Development[0].Evidence.ObservedAt)
	}
	if output, err := exec.Command(executable, "enrich", input, "--network", "allow", "--registry", server.URL, "--output", input).CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("enrich overwrote its input: %v, %s", err, output)
	}
	if requests.Load() != 1 {
		t.Fatal("output protection failed after a network request")
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		cmd := exec.Command(executable, "enrich", input, "--network", "allow", "--registry", server.URL, "--format", format)
		cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile, "SOURCE_DATE_EPOCH=1700000000")
		output, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(output, &raw); err != nil {
			t.Fatal(err)
		}
		validateMergedSBOMSchema(t, format, raw)
	}
}

func TestNPMEnrichCLI(t *testing.T) {
	response, err := os.ReadFile(filepath.Join("..", "testdata", "api", "npm", "is-number-7.0.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(response, &metadata); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var body []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/is-number/7.0.0" || r.Method != http.MethodGet {
			t.Errorf("unexpected npm request: %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	metadata["dist"].(map[string]any)["tarball"] = server.URL + "/is-number/-/is-number-7.0.0.tgz"
	body, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "npm-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certFile, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(t.TempDir(), "package-lock.json")
	lockData := map[string]any{
		"name": "ravel-npm-enrich", "version": "1.0.0", "lockfileVersion": 3,
		"packages": map[string]any{
			"":                       map[string]any{"name": "ravel-npm-enrich", "version": "1.0.0", "dependencies": map[string]string{"is-number": "7.0.0"}},
			"node_modules/is-number": map[string]any{"version": "7.0.0", "resolved": server.URL + "/is-number/-/is-number-7.0.0.tgz"},
		},
	}
	encoded, err := json.Marshal(lockData)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "npm.ravel.json")
	if output, err := exec.Command(executable, "scan", lock, "--format", "ravel-json", "--output", input).CombinedOutput(); err != nil {
		t.Fatalf("npm scan failed: %v, %s", err, output)
	}
	result := filepath.Join(t.TempDir(), "enriched.json")
	cmd := exec.Command(executable, "enrich", input, "--ecosystem", "npm", "--network", "allow", "--registry", server.URL, "--output", result)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("npm metadata enrichment failed: %v, %s", err, output)
	}
	if requests.Load() != 1 {
		t.Fatalf("expected one npm request, got %d", requests.Load())
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(body)
	if len(doc.Components) != 1 || doc.Components[0].Name != "is-number" || doc.Components[0].PURL != "" || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/jonschlinkert/is-number.git" || doc.Development[0].Status != "registry_metadata" || doc.Development[0].Evidence.InputDigest != "sha256:"+hex.EncodeToString(sha[:]) || doc.Development[0].Evidence.InputPath != server.URL+"/is-number/7.0.0" {
		t.Fatalf("npm development metadata was not attached with evidence: %#v", doc)
	}
	if _, err := time.Parse(time.RFC3339, doc.Development[0].Evidence.ObservedAt); err != nil {
		t.Fatalf("npm metadata observation time missing: %q", doc.Development[0].Evidence.ObservedAt)
	}
	if output, err := exec.Command(executable, "enrich", input, "--ecosystem", "npm", "--registry", server.URL).CombinedOutput(); err == nil || !strings.Contains(string(output), "--network allow") {
		t.Fatalf("npm metadata request was not opt-in: %v, %s", err, output)
	}
	if requests.Load() != 1 {
		t.Fatal("npm registry contacted without network opt-in")
	}
}

func TestNPMEnrichAcrossLockfileFormats(t *testing.T) {
	response, err := os.ReadFile(filepath.Join("..", "testdata", "api", "npm", "is-number-7.0.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(response, &metadata); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var body []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/is-number/7.0.0" {
			t.Errorf("unexpected npm request: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	metadata["dist"].(map[string]any)["tarball"] = server.URL + "/is-number/-/is-number-7.0.0.tgz"
	body, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "npm-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certFile, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"pnpm-enrich", "bun-enrich", "yarn-classic-enrich", "yarn-berry-enrich"} {
		t.Run(fixture, func(t *testing.T) {
			inputDir := t.TempDir()
			entries, err := os.ReadDir(filepath.Join("..", "testdata", "fixtures", fixture))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", fixture, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				data = []byte(strings.ReplaceAll(string(data), "https://registry.npmjs.org", server.URL))
				if err := os.WriteFile(filepath.Join(inputDir, entry.Name()), data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			input := filepath.Join(t.TempDir(), "scan.ravel.json")
			if output, err := exec.Command(executable, "scan", inputDir, "--format", "ravel-json", "--output", input).CombinedOutput(); err != nil {
				t.Fatalf("scan failed: %v, %s", err, output)
			}
			result := filepath.Join(t.TempDir(), "enriched.ravel.json")
			before := requests.Load()
			cmd := exec.Command(executable, "enrich", input, "--ecosystem", "npm", "--network", "allow", "--registry", server.URL, "--output", result)
			cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("enrichment failed: %v, %s", err, output)
			}
			if got := requests.Load() - before; got != 1 {
				t.Fatalf("expected one metadata request, got %d", got)
			}
			data, err := os.ReadFile(result)
			if err != nil {
				t.Fatal(err)
			}
			var doc model.Document
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Components) != 1 || doc.Components[0].Name != "is-number" || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/jonschlinkert/is-number.git" || doc.Development[0].Evidence.Collector != "npm-registry-api" {
				t.Fatalf("npm lockfile metadata was not enriched: %#v", doc)
			}
		})
	}
	for _, fixture := range []string{"pnpm-generated-10", "bun-generated-1_3", "yarn-berry-basic"} {
		t.Run("no-source-"+fixture, func(t *testing.T) {
			input := filepath.Join(t.TempDir(), "scan.ravel.json")
			fixturePath := filepath.Join("..", "testdata", "fixtures", fixture)
			if output, err := exec.Command(executable, "scan", fixturePath, "--format", "ravel-json", "--output", input).CombinedOutput(); err != nil {
				t.Fatalf("scan failed: %v, %s", err, output)
			}
			before := requests.Load()
			cmd := exec.Command(executable, "enrich", input, "--ecosystem", "npm", "--network", "allow", "--registry", server.URL)
			cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile)
			output, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			if got := requests.Load() - before; got != 0 {
				t.Fatalf("lockfile without a matching tarball made %d metadata requests", got)
			}
			var doc model.Document
			if err := json.Unmarshal(output, &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Development) != 0 {
				t.Fatalf("development source was inferred without a matching tarball: %#v", doc.Development)
			}
		})
	}
}

func TestPyPIEnrichAcrossLockfileFormats(t *testing.T) {
	response, err := os.ReadFile(filepath.Join("..", "testdata", "api", "pypi", "idna-3.10.json"))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/pypi/idna/3.10/json" || r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected PyPI request: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	defer server.Close()
	certFile := filepath.Join(t.TempDir(), "pypi-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certFile, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(response)
	for _, fixture := range []string{"uv-pypi-enrich", "pylock-pypi-enrich"} {
		t.Run(fixture, func(t *testing.T) {
			entries, err := os.ReadDir(filepath.Join("..", "testdata", "fixtures", fixture))
			if err != nil {
				t.Fatal(err)
			}
			inputDir := t.TempDir()
			for _, entry := range entries {
				data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", fixture, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				data = []byte(strings.ReplaceAll(string(data), "https://pypi.org/simple", server.URL+"/simple"))
				if err := os.WriteFile(filepath.Join(inputDir, entry.Name()), data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			input := filepath.Join(t.TempDir(), "scan.ravel.json")
			if output, err := exec.Command(executable, "scan", inputDir, "--format", "ravel-json", "--output", input).CombinedOutput(); err != nil {
				t.Fatalf("scan failed: %v, %s", err, output)
			}
			if output, err := exec.Command(executable, "enrich", input, "--ecosystem", "pypi", "--registry", server.URL).CombinedOutput(); err == nil || !strings.Contains(string(output), "--network allow") {
				t.Fatalf("PyPI contacted without network opt-in: %v, %s", err, output)
			}
			before := requests.Load()
			result := filepath.Join(t.TempDir(), "enriched.ravel.json")
			cmd := exec.Command(executable, "enrich", input, "--ecosystem", "pypi", "--network", "allow", "--registry", server.URL, "--output", result)
			cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("PyPI enrichment failed: %v, %s", err, output)
			}
			if got := requests.Load() - before; got != 1 {
				t.Fatalf("expected one PyPI request, got %d", got)
			}
			data, err := os.ReadFile(result)
			if err != nil {
				t.Fatal(err)
			}
			var doc model.Document
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			foundIDNA := false
			for _, component := range doc.Components {
				foundIDNA = foundIDNA || component.Name == "idna" && component.Version == "3.10"
			}
			if !foundIDNA || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/kjd/idna" || doc.Development[0].Status != "registry_metadata" || doc.Development[0].Evidence.Collector != "pypi-json-api" || doc.Development[0].Evidence.InputDigest != "sha256:"+hex.EncodeToString(sha[:]) || doc.Development[0].Evidence.InputPath != server.URL+"/pypi/idna/3.10/json" {
				t.Fatalf("PyPI development metadata was not attached with evidence: %#v", doc)
			}
			if _, err := time.Parse(time.RFC3339, doc.Development[0].Evidence.ObservedAt); err != nil {
				t.Fatalf("PyPI metadata observation time missing: %q", doc.Development[0].Evidence.ObservedAt)
			}
		})
	}
	t.Run("strict-hash-mismatch", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "uv-pypi-enrich", "uv.lock"))
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.ReplaceAll(string(data), "https://pypi.org/simple", server.URL+"/simple"))
		const realHash = "946d195a0d259cbba61165e88e65941f16e9b36ea6ddb97f00452bae8b1287d3"
		data = []byte(strings.ReplaceAll(string(data), realHash, strings.Repeat("a", 64)))
		inputDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(inputDir, "uv.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(t.TempDir(), "scan.ravel.json")
		if output, err := exec.Command(executable, "scan", inputDir, "--format", "ravel-json", "--output", input).CombinedOutput(); err != nil {
			t.Fatalf("scan failed: %v, %s", err, output)
		}
		result := filepath.Join(t.TempDir(), "enriched.ravel.json")
		cmd := exec.Command(executable, "enrich", input, "--ecosystem", "pypi", "--network", "allow", "--registry", server.URL, "--strict", "--output", result)
		cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile)
		output, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 {
			t.Fatalf("strict mismatch did not return 3: %v, %s", err, output)
		}
		encoded, err := os.ReadFile(result)
		if err != nil {
			t.Fatalf("strict mismatch did not write a reportable result: %v", err)
		}
		var doc model.Document
		if err := json.Unmarshal(encoded, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Development) != 0 || len(doc.Coverage.Issues) != 1 || doc.Coverage.Issues[0].Code != "registry_metadata_artifact_mismatch" {
			t.Fatalf("strict mismatch attached unverified metadata: %#v", doc)
		}
	})
}
