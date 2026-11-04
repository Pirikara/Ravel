package update

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

const maxReleaseJSON = 8 << 20
const maxChecksums = 1 << 20
const maxArchive = 128 << 20

const githubAPI = "https://api.github.com/repos/Pirikara/Ravel"
const githubDownloads = "https://github.com/Pirikara/Ravel/releases/download"

var tagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Asset struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	State  string `json:"state"`
}

type Release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

type Client struct {
	HTTP        *http.Client
	APIURL      string
	DownloadURL string
	UserAgent   string
}

func NewClient(version string) *Client {
	return &Client{
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		APIURL:      githubAPI,
		DownloadURL: githubDownloads,
		UserAgent:   "ravel/" + version,
	}
}

// Latest selects the highest semantic version from published releases. The
// GitHub /releases/latest endpoint excludes prereleases, so beta tracking uses
// the release list instead.
func (c *Client) Latest(ctx context.Context, channel string) (Release, error) {
	if channel != "stable" && channel != "beta" {
		return Release{}, errors.New("channel must be stable or beta")
	}
	endpoint := strings.TrimRight(c.APIURL, "/") + "/releases?per_page=100"
	data, err := c.get(ctx, endpoint, maxReleaseJSON, "application/vnd.github+json")
	if err != nil {
		return Release{}, err
	}
	var releases []Release
	if err := json.Unmarshal(data, &releases); err != nil {
		return Release{}, fmt.Errorf("invalid release response: %w", err)
	}
	var selected Release
	var selectedVersion *semver.Version
	for _, release := range releases {
		if release.Draft || !tagPattern.MatchString(release.Tag) {
			continue
		}
		candidate, err := semver.NewVersion(release.Tag)
		if err != nil || channel == "stable" && (release.Prerelease || candidate.Prerelease() != "") {
			continue
		}
		if selectedVersion == nil || candidate.GreaterThan(selectedVersion) {
			selected, selectedVersion = release, candidate
		}
	}
	if selectedVersion == nil {
		return Release{}, fmt.Errorf("no published %s release found", channel)
	}
	return selected, nil
}

func Compare(current, latest string) (int, error) {
	a, err := semver.NewVersion(current)
	if err != nil {
		return 0, fmt.Errorf("current version %q is not a release version", current)
	}
	b, err := semver.NewVersion(latest)
	if err != nil {
		return 0, fmt.Errorf("invalid release version %q", latest)
	}
	return a.Compare(b), nil
}

func ArchiveName(tag, goos, goarch string) (string, error) {
	if !tagPattern.MatchString(tag) {
		return "", fmt.Errorf("invalid release tag %q", tag)
	}
	switch goos + "/" + goarch {
	case "darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64":
		return fmt.Sprintf("ravel_%s_%s_%s.tar.gz", tag, goos, goarch), nil
	case "windows/amd64":
		return fmt.Sprintf("ravel_%s_%s_%s.zip", tag, goos, goarch), nil
	default:
		return "", fmt.Errorf("no release archive for %s/%s", goos, goarch)
	}
}

func (c *Client) assetURL(tag, name string) string {
	return strings.TrimRight(c.DownloadURL, "/") + "/" + url.PathEscape(tag) + "/" + url.PathEscape(name)
}

func findAsset(release Release, name string, maxSize int64) (Asset, error) {
	var found Asset
	count := 0
	for _, asset := range release.Assets {
		if asset.Name == name {
			found = asset
			count++
		}
	}
	if count != 1 || found.State != "uploaded" || found.Size <= 0 || found.Size > maxSize || !digestPattern.MatchString(found.Digest) {
		return Asset{}, fmt.Errorf("release %s has no unique verified %s asset", release.Tag, name)
	}
	return found, nil
}

func (c *Client) get(ctx context.Context, endpoint string, limit int64, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", c.UserAgent)
	response, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned HTTP %d", endpoint, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", endpoint, limit)
	}
	return data, nil
}

func (c *Client) download(ctx context.Context, release Release, asset Asset, limit int64) ([]byte, error) {
	data, err := c.get(ctx, c.assetURL(release.Tag, asset.Name), limit, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != asset.Size {
		return nil, fmt.Errorf("%s size differs from release metadata", asset.Name)
	}
	got := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	if got != asset.Digest {
		return nil, fmt.Errorf("%s digest differs from release metadata", asset.Name)
	}
	return data, nil
}

func (c *Client) DownloadArchive(ctx context.Context, release Release, name string) ([]byte, error) {
	archiveAsset, err := findAsset(release, name, maxArchive)
	if err != nil {
		return nil, err
	}
	checksumsAsset, err := findAsset(release, "SHA256SUMS", maxChecksums)
	if err != nil {
		return nil, err
	}
	checksums, err := c.download(ctx, release, checksumsAsset, maxChecksums)
	if err != nil {
		return nil, err
	}
	want := strings.TrimPrefix(archiveAsset.Digest, "sha256:")
	matches := 0
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == name {
			matches++
			if fields[0] != want {
				return nil, fmt.Errorf("%s digest differs from SHA256SUMS", name)
			}
		}
	}
	if matches != 1 {
		return nil, fmt.Errorf("SHA256SUMS has no unique entry for %s", name)
	}
	return c.download(ctx, release, archiveAsset, maxArchive)
}
