package enrich

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const maxPyPIResponse = 2 << 20

var pythonProjectName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
var pythonSeparatorRun = regexp.MustCompile(`[-_.]+`)
var pythonVersionPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+!-]*$`)

type pyPIMetadata struct {
	Info struct {
		Name        string            `json:"name"`
		Version     string            `json:"version"`
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
	URLs []struct {
		URL     string `json:"url"`
		Digests struct {
			SHA256 string `json:"sha256"`
		} `json:"digests"`
	} `json:"urls"`
}

// PyPI requires a declared index and a SHA-256 digest of a distribution in
// the release response before attaching project-supplied source metadata.
func PyPI(ctx context.Context, doc model.Document, options Options) (model.Document, error) {
	registry, err := registryURL(options.RegistryURL)
	if err != nil {
		return model.Document{}, err
	}
	if options.MaxRequests < 1 || options.MaxRequests > 10000 {
		return model.Document{}, fmt.Errorf("max requests must be between 1 and 10000")
	}
	client := options.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	origins := map[string][]model.Origin{}
	for _, origin := range doc.Origins {
		origins[origin.Occurrence] = append(origins[origin.Occurrence], origin)
	}
	cache := map[string]metadataResult{}
	requests := 0
	for _, component := range doc.Components {
		if component.Kind != "package" || !pythonLockComponent(component) || component.Name == "" || component.Version == "" {
			continue
		}
		declared := []string{}
		for _, origin := range origins[component.ID] {
			if origin.Kind == "declared_registry" {
				declared = append(declared, origin.SafeURL)
			}
		}
		if len(declared) != 1 || canonicalRegistry(declared[0]) != registry+"/simple" {
			continue
		}
		if len(component.Name) > 256 || len(component.Version) > 128 || !pythonProjectName.MatchString(component.Name) || !pythonVersionPath.MatchString(component.Version) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "registry_metadata_invalid_identity", Name: component.Name})
			continue
		}
		digest := singleSHA256(component.Hashes)
		if digest == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "registry_metadata_artifact_unverified", Name: component.Name})
			continue
		}
		name := canonicalPythonName(component.Name)
		key := name + "\x00" + component.Version + "\x00" + digest
		result, found := cache[key]
		if !found {
			if requests >= options.MaxRequests {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "registry_metadata_request_limit", Name: component.Name})
				continue
			}
			requests++
			result = fetchPyPI(ctx, client, registry, name, component.Version, digest, now)
			cache[key] = result
		}
		if result.Issue != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: result.Issue, Name: component.Name})
			continue
		}
		duplicate := false
		for _, source := range doc.Development {
			if source.Occurrence == component.ID && source.SafeURL == result.Source {
				duplicate = true
				break
			}
		}
		if !duplicate {
			doc.Development = append(doc.Development, model.Development{
				Occurrence: component.ID, SafeURL: result.Source, Status: "registry_metadata",
				Evidence: model.Evidence{Collector: "pypi-json-api", InputPath: result.URL, InputDigest: "sha256:" + result.Digest, Pointer: result.Pointer, Method: "registry-metadata", ObservedAt: result.ObservedAt},
			})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func fetchPyPI(ctx context.Context, client *http.Client, registry, name, version, digest string, now func() time.Time) metadataResult {
	endpoint := registry + "/pypi/" + url.PathEscape(name) + "/" + url.PathEscape(version) + "/json"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return metadataResult{Issue: "registry_metadata_unavailable"}
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return metadataResult{Issue: "registry_metadata_unavailable"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.String() != endpoint {
		return metadataResult{Issue: "registry_metadata_unavailable"}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxPyPIResponse+1))
	if err != nil || len(data) > maxPyPIResponse {
		return metadataResult{Issue: "registry_metadata_unavailable"}
	}
	var metadata pyPIMetadata
	if err := json.Unmarshal(data, &metadata); err != nil || !pythonProjectName.MatchString(metadata.Info.Name) || canonicalPythonName(metadata.Info.Name) != name || metadata.Info.Version != version {
		return metadataResult{Issue: "registry_metadata_identity_mismatch"}
	}
	verified := false
	for _, file := range metadata.URLs {
		if strings.EqualFold(file.Digests.SHA256, digest) && safeurl.Clean(file.URL) != "" {
			verified = true
			break
		}
	}
	if !verified {
		return metadataResult{Issue: "registry_metadata_artifact_mismatch"}
	}
	source, pointer, issue := pyPISource(metadata.Info.ProjectURLs)
	if issue != "" {
		return metadataResult{Issue: issue}
	}
	sha := sha256.Sum256(data)
	return metadataResult{URL: endpoint, Digest: hex.EncodeToString(sha[:]), ObservedAt: now().UTC().Format(time.RFC3339), Source: source, Pointer: pointer}
}

func pyPISource(projectURLs map[string]string) (string, string, string) {
	sources := map[string]string{}
	labels := make([]string, 0, len(projectURLs))
	for label := range projectURLs {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		raw := projectURLs[label]
		name := strings.ToLower(strings.NewReplacer(" ", "", "-", "", "_", "").Replace(label))
		switch name {
		case "source", "sourcecode", "repository", "github", "gitlab":
		default:
			continue
		}
		clean := safeurl.Clean(raw)
		if clean == "" {
			return "", "", "unsafe_or_invalid_development_source"
		}
		sources[clean] = "/info/project_urls/" + strings.ReplaceAll(strings.ReplaceAll(label, "~", "~0"), "/", "~1")
	}
	if len(sources) == 0 {
		return "", "", "development_source_unavailable"
	}
	if len(sources) > 1 {
		return "", "", "ambiguous_development_source"
	}
	for source, pointer := range sources {
		return source, pointer, ""
	}
	return "", "", "development_source_unavailable"
}

func canonicalPythonName(name string) string {
	return pythonSeparatorRun.ReplaceAllString(strings.ToLower(name), "-")
}

func singleSHA256(hashes []model.Hash) string {
	digest := ""
	for _, hash := range hashes {
		if !strings.EqualFold(hash.Alg, "SHA-256") {
			continue
		}
		value := strings.ToLower(hash.Content)
		if len(value) != 64 {
			return ""
		}
		if _, err := hex.DecodeString(value); err != nil || digest != "" && digest != value {
			return ""
		}
		digest = value
	}
	return digest
}

func pythonLockComponent(component model.Component) bool {
	for _, evidence := range component.Evidence {
		if evidence.Collector == "uv-lock" || evidence.Collector == "pylock" {
			return true
		}
	}
	return false
}
