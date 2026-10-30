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

const maxRubyGemsResponse = 2 << 20

var gemPathPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

type Options struct {
	RegistryURL string
	MaxRequests int
	Client      *http.Client
	Now         func() time.Time
}

type rubyGemsMetadata struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Metadata struct {
		SourceCodeURI string `json:"source_code_uri"`
	} `json:"metadata"`
}

type metadataResult struct {
	URL        string
	Digest     string
	ObservedAt string
	Source     string
	Pointer    string
	Issue      string
}

// RubyGems fetches version-specific metadata only for GEM occurrences whose
// single declared registry exactly matches the explicitly selected registry.
// Fetch failures are recorded as coverage issues; they never invent a source.
func RubyGems(ctx context.Context, doc model.Document, options Options) (model.Document, error) {
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
		if component.Kind != "package" || !bundlerComponent(component) || component.Name == "" || component.Version == "" {
			continue
		}
		declared := []string{}
		for _, origin := range origins[component.ID] {
			if origin.Kind == "declared_registry" {
				declared = append(declared, origin.SafeURL)
			}
		}
		if len(declared) != 1 || canonicalRegistry(declared[0]) != registry {
			continue
		}
		if len(component.Name) > 256 || len(component.Version) > 128 || !gemPathPart.MatchString(component.Name) || !gemPathPart.MatchString(component.Version) || component.Platform != "" && (len(component.Platform) > 128 || !gemPathPart.MatchString(component.Platform)) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "registry_metadata_invalid_identity", Name: component.Name})
			continue
		}
		platform := component.Platform
		if platform == "" {
			platform = "ruby"
		}
		key := component.Name + "\x00" + component.Version + "\x00" + platform
		result, found := cache[key]
		if !found {
			if requests >= options.MaxRequests {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "registry_metadata_request_limit", Name: component.Name})
				continue
			}
			requests++
			result = fetchRubyGems(ctx, client, registry, component.Name, component.Version, platform, now)
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
				Evidence: model.Evidence{Collector: "rubygems-api", InputPath: result.URL, InputDigest: "sha256:" + result.Digest, Pointer: "/metadata/source_code_uri", Method: "registry-metadata", ObservedAt: result.ObservedAt},
			})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func fetchRubyGems(ctx context.Context, client *http.Client, registry, name, version, platform string, now func() time.Time) metadataResult {
	endpoint := registry + "/api/v2/rubygems/" + url.PathEscape(name) + "/versions/" + url.PathEscape(version) + ".json"
	if platform != "ruby" {
		endpoint += "?platform=" + url.QueryEscape(platform)
	}
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
	data, err := io.ReadAll(io.LimitReader(response.Body, maxRubyGemsResponse+1))
	if err != nil || len(data) > maxRubyGemsResponse {
		return metadataResult{Issue: "registry_metadata_unavailable"}
	}
	var metadata rubyGemsMetadata
	if err := json.Unmarshal(data, &metadata); err != nil || metadata.Name != name || metadata.Version != version || metadata.Platform != platform {
		return metadataResult{Issue: "registry_metadata_identity_mismatch"}
	}
	if metadata.Metadata.SourceCodeURI == "" {
		return metadataResult{Issue: "development_source_unavailable"}
	}
	clean := safeurl.Clean(metadata.Metadata.SourceCodeURI)
	if clean == "" {
		return metadataResult{Issue: "unsafe_or_invalid_development_source"}
	}
	digest := sha256.Sum256(data)
	return metadataResult{URL: endpoint, Digest: hex.EncodeToString(digest[:]), ObservedAt: now().UTC().Format(time.RFC3339), Source: clean}
}

func registryURL(raw string) (string, error) {
	clean := safeurl.Clean(raw)
	parsed, err := url.Parse(clean)
	if clean == "" || strings.TrimSpace(raw) != clean || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("registry must be an HTTPS URL without credentials or query")
	}
	return canonicalRegistry(clean), nil
}

func canonicalRegistry(raw string) string {
	clean := safeurl.Clean(raw)
	if clean == "" || raw != clean {
		return ""
	}
	parsed, err := url.Parse(clean)
	if err != nil || parsed.Host == "" {
		return ""
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed.String()
}

func bundlerComponent(component model.Component) bool {
	for _, evidence := range component.Evidence {
		if evidence.Collector == "bundler-lock" {
			return true
		}
	}
	return false
}
