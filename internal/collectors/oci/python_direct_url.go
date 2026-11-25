package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

var imageVCSCommit = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
var imageSVNRevision = regexp.MustCompile(`^[0-9]{1,20}$`)

func collectImagePythonDirectURLs(doc *model.Document, files map[string]imageProjectFile) {
	resolved := map[string]bool{}
	for i := range doc.Components {
		c := &doc.Components[i]
		if installedImageEcosystem(*c) != "pypi" {
			continue
		}
		metadata := installedImagePath(*c)
		if !strings.HasSuffix(metadata, ".dist-info/METADATA") {
			continue
		}
		name := path.Join(path.Dir(metadata), "direct_url.json")
		state, found := files[name]
		if !found {
			continue
		}
		issue := func(code string) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: c.Name, Scope: name})
		}
		var record struct {
			URL string `json:"url"`
			VCS *struct {
				VCS    string `json:"vcs"`
				Commit string `json:"commit_id"`
			} `json:"vcs_info"`
			Archive      map[string]json.RawMessage `json:"archive_info"`
			Directory    map[string]json.RawMessage `json:"dir_info"`
			Subdirectory string                     `json:"subdirectory"`
		}
		if state.status != "" || len(state.data) > 64<<10 || json.Unmarshal(state.data, &record) != nil {
			issue("python_direct_url_invalid")
			continue
		}
		variants := 0
		if record.VCS != nil {
			variants++
		}
		if record.Archive != nil {
			variants++
		}
		if record.Directory != nil {
			variants++
		}
		if variants != 1 || record.URL == "" {
			issue("python_direct_url_invalid")
			continue
		}
		origin := model.Origin{Occurrence: c.ID, Status: "recorded_in_install_metadata"}
		if record.Directory != nil {
			u, err := url.Parse(record.URL)
			if err != nil || u.Scheme != "file" || !strings.HasPrefix(u.Path, "/") || u.Host != "" && u.Host != "localhost" {
				issue("python_direct_url_invalid")
				continue
			}
			origin.Kind = "local" // The build machine's local path is not an image location.
		} else {
			origin.SafeURL = safeurl.Clean(record.URL)
			if origin.SafeURL == "" {
				issue("python_direct_url_unsupported")
				continue
			}
			origin.Kind = "download_url"
			if record.VCS != nil {
				vcs, commit := record.VCS.VCS, record.VCS.Commit
				if (vcs == "git" || vcs == "hg") && imageVCSCommit.MatchString(commit) || vcs == "svn" && imageSVNRevision.MatchString(commit) {
					origin.Kind, origin.Revision, origin.VCSType = "vcs", commit, vcs
				} else {
					issue("python_direct_url_unsupported")
					continue
				}
			}
		}
		if record.Subdirectory != "" {
			if path.IsAbs(record.Subdirectory) || path.Clean(record.Subdirectory) != record.Subdirectory || record.Subdirectory == ".." || strings.HasPrefix(record.Subdirectory, "../") || strings.ContainsAny(record.Subdirectory, "\\\x00\r\n") {
				issue("python_direct_url_invalid")
				continue
			}
			origin.Target = "subdirectory=" + record.Subdirectory
		}
		hash := sha256.Sum256(state.data)
		origin.Evidence = model.Evidence{Collector: "python-direct-url", InputPath: "oci:" + state.layer + "!/" + name, InputDigest: "sha256:" + hex.EncodeToString(hash[:]), Method: "installed-source-record", Pointer: "/url"}
		c.Evidence = append(c.Evidence, origin.Evidence)
		doc.Origins = append(doc.Origins, origin)
		resolved[c.ID] = true
		issue("installed_distribution_origin_unverified")
	}
	issues := doc.Coverage.Issues[:0]
	for _, issue := range doc.Coverage.Issues {
		if issue.Code != "distribution_source_unavailable" || !resolved[issue.Scope] {
			issues = append(issues, issue)
		}
	}
	doc.Coverage.Issues = issues
}
