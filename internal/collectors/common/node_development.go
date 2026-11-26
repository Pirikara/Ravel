package common

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
)

// CollectNodeDevelopment reads the declared repository only. homepage and bugs
// URLs do not establish where the package's source is maintained.
func CollectNodeDevelopment(doc *model.Document, occurrence string, data []byte, evidence model.Evidence) {
	var fields map[string]json.RawMessage
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return
	}
	raw := bytes.TrimSpace(fields["repository"])
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return
	}
	pointer := strings.TrimRight(evidence.Pointer, "/") + "/repository"
	value := nodeRepository(raw)
	var object map[string]json.RawMessage
	json.Unmarshal(raw, &object)
	if value == "" {
		if !bytes.Equal(raw, []byte(`""`)) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_source_unresolved", Scope: occurrence})
		}
		return
	}
	evidence.Pointer = pointer
	before := len(doc.Development)
	AddDevelopment(doc, occurrence, value, "declared", evidence)
	if len(doc.Development) > before && object != nil {
		var directory string
		if json.Unmarshal(object["directory"], &directory) == nil && directory != "" {
			if len(directory) <= 4096 && path.Clean(directory) == directory && !path.IsAbs(directory) && directory != ".." && !strings.HasPrefix(directory, "../") && !strings.ContainsAny(directory, "\\\x00\r\n") {
				doc.Development[len(doc.Development)-1].Directory = directory
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_directory_unresolved", Scope: occurrence})
			}
		}
	}
}

func npmRepositoryURL(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(value, "git+"))
	value, _, _ = strings.Cut(value, "#")
	for prefix, host := range map[string]string{"github:": "github.com", "gitlab:": "gitlab.com", "bitbucket:": "bitbucket.org", "gist:": "gist.github.com"} {
		if strings.HasPrefix(value, prefix) {
			repo := strings.TrimPrefix(value, prefix)
			if validRepositoryShorthand(repo, prefix == "gist:") && (prefix == "gitlab:" || strings.Count(repo, "/") <= 1) {
				return "https://" + host + "/" + strings.TrimSuffix(repo, ".git") + ".git"
			}
			return value
		}
	}
	if validRepositoryShorthand(value, false) && strings.Count(value, "/") == 1 && !strings.Contains(value, ":") {
		return "https://github.com/" + strings.TrimSuffix(value, ".git") + ".git"
	}
	return value
}

func validRepositoryShorthand(value string, gist bool) bool {
	if strings.ContainsAny(value, "?#@% \\\t\r\n") {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) < 2 && !(gist && len(parts) == 1) {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
				return false
			}
		}
	}
	return true
}

func nodeRepository(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		var object struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(raw, &object) != nil {
			return ""
		}
		value = object.URL
	}
	return npmRepositoryURL(value)
}
