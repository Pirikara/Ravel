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
	"strings"
	"time"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

const maxNPMResponse = 2 << 20

var npmNamePart = regexp.MustCompile(`^(@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$`)
var npmVersionPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

type npmMetadata struct {
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	Repository json.RawMessage `json:"repository"`
	Dist       struct {
		Tarball string `json:"tarball"`
	} `json:"dist"`
}

// NPM enriches a resolved package only when the version endpoint confirms
// both its name/version and the exact declared tarball URL from the lockfile.
func NPM(ctx context.Context, doc model.Document, options Options) (model.Document, error) {
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
		if component.Kind != "package" || !npmLockComponent(component) || component.Name == "" || component.Version == "" {
			continue
		}
		var downloads []string
		for _, origin := range origins[component.ID] {
			if origin.Kind == "download_url" {
				downloads = append(downloads, origin.SafeURL)
			}
		}
		if len(downloads) != 1 || safeurl.Clean(downloads[0]) != downloads[0] || !strings.HasPrefix(downloads[0], registry+"/") {
			continue
		}
		if len(component.Name) > 256 || len(component.Version) > 128 || !npmNamePart.MatchString(component.Name) || !npmVersionPart.MatchString(component.Version) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "registry_metadata_invalid_identity", Name: component.Name})
			continue
		}
		key := component.Name + "\x00" + component.Version + "\x00" + downloads[0]
		result, found := cache[key]
		if !found {
			if requests >= options.MaxRequests {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "registry_metadata_request_limit", Name: component.Name})
				continue
			}
			requests++
			result = fetchNPM(ctx, client, registry, component.Name, component.Version, downloads[0], now)
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
				Evidence: model.Evidence{Collector: "npm-registry-api", InputPath: result.URL, InputDigest: "sha256:" + result.Digest, Pointer: "/repository", Method: "registry-metadata", ObservedAt: result.ObservedAt},
			})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func fetchNPM(ctx context.Context, client *http.Client, registry, name, version, download string, now func() time.Time) metadataResult {
	endpoint := registry + "/" + url.PathEscape(name) + "/" + url.PathEscape(version)
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
	data, err := io.ReadAll(io.LimitReader(response.Body, maxNPMResponse+1))
	if err != nil || len(data) > maxNPMResponse {
		return metadataResult{Issue: "registry_metadata_unavailable"}
	}
	var metadata npmMetadata
	if err := json.Unmarshal(data, &metadata); err != nil || metadata.Name != name || metadata.Version != version {
		return metadataResult{Issue: "registry_metadata_identity_mismatch"}
	}
	if safeurl.Clean(metadata.Dist.Tarball) != download {
		return metadataResult{Issue: "registry_metadata_artifact_mismatch"}
	}
	repository := npmRepository(metadata.Repository)
	if repository == "" {
		return metadataResult{Issue: "development_source_unavailable"}
	}
	clean := safeurl.Clean(repository)
	if clean == "" {
		return metadataResult{Issue: "unsafe_or_invalid_development_source"}
	}
	digest := sha256.Sum256(data)
	return metadataResult{URL: endpoint, Digest: hex.EncodeToString(digest[:]), ObservedAt: now().UTC().Format(time.RFC3339), Source: clean}
}

func npmRepository(raw json.RawMessage) string {
	var repository string
	if json.Unmarshal(raw, &repository) == nil {
		return repository
	}
	var object struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &object) == nil {
		return object.URL
	}
	return ""
}

func npmLockComponent(component model.Component) bool {
	for _, evidence := range component.Evidence {
		switch evidence.Collector {
		case "npm-lock", "pnpm-lock", "bun-lock", "yarn-classic", "yarn-berry":
			return true
		}
	}
	return false
}
