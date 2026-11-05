package conda

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const MaxInstalledMetadataBytes = 1 << 20

var packageName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
var packageVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+!~-]{0,127}$`)
var packageSubdir = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type installedMetadata struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Build   string   `json:"build"`
	Subdir  string   `json:"subdir"`
	URL     string   `json:"url"`
	Fn      string   `json:"fn"`
	Channel string   `json:"channel"`
	Depends []string `json:"depends"`
}

// IsInstalledMetadataPath accepts a package record immediately below a
// conda-meta directory at any environment prefix. Package identity is checked
// against the filename after parsing the record.
func IsInstalledMetadataPath(filename string) bool {
	return filename != "" && !strings.HasPrefix(filename, "/") && path.Clean(filename) == filename && path.Base(path.Dir(filename)) == "conda-meta" && strings.HasSuffix(filename, ".json") && len(path.Base(filename)) > len(".json")
}

func CollectInstalledMetadata(data []byte, source, project, filename string) (model.Document, error) {
	if !IsInstalledMetadataPath(filename) || len(data) == 0 || len(data) > MaxInstalledMetadataBytes {
		return model.Document{}, errors.New("invalid Conda metadata path or size")
	}
	var record installedMetadata
	if err := json.Unmarshal(data, &record); err != nil {
		return model.Document{}, errors.New("invalid Conda metadata JSON")
	}
	if !packageName.MatchString(record.Name) || !packageVersion.MatchString(record.Version) || !packageVersion.MatchString(record.Build) || path.Base(filename) != record.Name+"-"+record.Version+"-"+record.Build+".json" || len(record.Depends) > 4096 || record.Subdir != "" && !packageSubdir.MatchString(record.Subdir) {
		return model.Document{}, errors.New("invalid Conda package identity or metadata")
	}
	for _, dependency := range record.Depends {
		if dependency == "" || len(dependency) > 512 || strings.ContainsAny(dependency, "\r\n\x00") {
			return model.Document{}, errors.New("invalid Conda dependency declaration")
		}
	}
	digest := sha256.Sum256(data)
	evidence := model.Evidence{Collector: "conda-meta", InputPath: source, InputDigest: "sha256:" + hex.EncodeToString(digest[:]), Method: "installed-package-record"}
	doc := common.NewDocument(source, project, "conda", nil)
	id := "conda-installed:" + common.ID(source+"\x00"+record.Name+"\x00"+record.Version+"\x00"+record.Build)
	environment := path.Dir(path.Dir(filename))
	if environment == "." {
		environment = ""
	}
	context := "environment=/" + environment + ";build=" + record.Build
	if record.Subdir != "" {
		context += ";subdir=" + record.Subdir
	}
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: record.Name, Version: record.Version, Context: context, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	if record.URL != "" {
		base := record.Name + "-" + record.Version + "-" + record.Build
		for _, suffix := range []string{".conda", ".tar.bz2"} {
			filename := base + suffix
			if record.Fn != "" && record.Fn != filename {
				continue
			}
			if clean := safeurl.CleanCondaArtifact(record.URL, filename, record.Subdir); clean != "" {
				if strings.HasPrefix(record.Channel, "https://") &&
					strings.TrimRight(safeurl.Clean(record.Channel), "/") != strings.TrimSuffix(clean, "/"+filename) {
					continue
				}
				originEvidence := evidence
				originEvidence.Pointer = "/url"
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "download_url", SafeURL: clean, Status: "recorded_in_install_metadata", Evidence: originEvidence})
				break
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}
