package conda

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledMetadata(t *testing.T) {
	const filename = "opt/conda/conda-meta/python-3.12.7-h123_0.json"
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "oci", "conda-meta", filepath.Base(filename)))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := CollectInstalledMetadata(data, filename, "sample", filename)
	if err != nil || len(doc.Components) != 1 || len(doc.Edges) != 1 || doc.Components[0].Name != "python" || doc.Components[0].Version != "3.12.7" || doc.Components[0].PURL != "" || doc.Components[0].Context != "environment=/opt/conda;build=h123_0;subdir=linux-aarch64" {
		t.Fatalf("installed Conda package incorrect: doc=%#v err=%v", doc, err)
	}
	root, err := CollectInstalledMetadata(data, "conda-meta/python-3.12.7-h123_0.json", "sample", "conda-meta/python-3.12.7-h123_0.json")
	if err != nil || root.Components[0].Context != "environment=/;build=h123_0;subdir=linux-aarch64" {
		t.Fatalf("root Conda environment incorrect: doc=%#v err=%v", root, err)
	}
	for _, tc := range []struct {
		name, filename string
		data           []byte
	}{
		{"filename mismatch", "opt/conda/conda-meta/python-3.12.8-h123_0.json", data},
		{"wrong parent", "opt/conda/cache/python-3.12.7-h123_0.json", data},
		{"traversal", "opt/conda/../conda-meta/python-3.12.7-h123_0.json", data},
		{"missing build", filename, []byte(`{"name":"python","version":"3.12.7"}`)},
		{"invalid JSON", filename, []byte(`{"name":`)},
		{"oversized", filename, make([]byte, MaxInstalledMetadataBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CollectInstalledMetadata(tc.data, "sample", "sample", tc.filename); err == nil {
				t.Fatal("invalid Conda record was accepted")
			}
		})
	}
}

func TestInstalledMetadataRecordedURL(t *testing.T) {
	const filename = "opt/conda/conda-meta/tokenizers-1.2.3-py314_0.json"
	record := map[string]any{"name": "tokenizers", "version": "1.2.3", "build": "py314_0", "subdir": "linux-aarch64", "fn": "tokenizers-1.2.3-py314_0.conda", "channel": "https://repo.example.test/main/linux-aarch64"}
	validURL := "https://repo.example.test/main/linux-aarch64/tokenizers-1.2.3-py314_0.conda"
	for _, tc := range []struct{ name, url, channel, want string }{
		{"matching archive", validURL + "?token=secret", "https://repo.example.test/main/linux-aarch64", validURL},
		{"wrong identity", "https://repo.example.test/main/linux-aarch64/other-1.2.3-py314_0.conda", "https://repo.example.test/main/linux-aarch64", ""},
		{"secret parent", "https://repo.example.test/token/secret/tokenizers-1.2.3-py314_0.conda", "https://repo.example.test/token/secret", ""},
		{"wrong subdir", "https://repo.example.test/main/noarch/tokenizers-1.2.3-py314_0.conda", "https://repo.example.test/main/noarch", ""},
		{"wrong channel", validURL, "https://other.example.test/main/linux-aarch64", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record["url"] = tc.url
			record["channel"] = tc.channel
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := CollectInstalledMetadata(data, filename, "sample", filename)
			if err != nil || len(doc.Components) != 1 || doc.Components[0].PURL != "" {
				t.Fatalf("Conda record invalid: doc=%#v err=%v", doc, err)
			}
			if tc.want == "" {
				if len(doc.Origins) != 0 {
					t.Fatalf("unsafe origin emitted: %#v", doc.Origins)
				}
			} else if len(doc.Origins) != 1 || doc.Origins[0].SafeURL != tc.want || doc.Origins[0].Status != "recorded_in_install_metadata" || doc.Origins[0].Evidence.Pointer != "/url" {
				t.Fatalf("recorded origin missing: %#v", doc.Origins)
			}
		})
	}
}
