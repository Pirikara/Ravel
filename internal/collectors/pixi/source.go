package pixi

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

// The eight-digit selector hash distinguishes build configurations. It is
// not an artifact checksum or a package version.
func parseSourceIdentifier(value string) (name, location, hash string, ok bool) {
	if len(value) > 2048 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", "", "", false
	}
	identifier, location, found := strings.Cut(value, " @ ")
	name, hash, bracket := strings.Cut(identifier, "[")
	if !found || !bracket || !strings.HasSuffix(hash, "]") || !namePattern.MatchString(name) || location == "" {
		return "", "", "", false
	}
	hash = strings.TrimSuffix(hash, "]")
	if len(hash) != 8 {
		return "", "", "", false
	}
	for _, c := range hash {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", "", "", false
		}
	}
	return name, location, hash, true
}

func addSourceOrigin(doc *model.Document, id string, record resolvedRecord, evidence model.Evidence) {
	location := record.sourceLocation
	if !strings.Contains(location, "://") && !strings.HasPrefix(location, "git+") {
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "local", LocalPath: location, Status: "declared", Evidence: evidence})
		return
	}
	if clean := safeurl.Clean(location); clean != "" {
		origin := model.Origin{Occurrence: id, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: evidence}
		if strings.HasPrefix(location, "git+") {
			origin.Kind, origin.VCSType = "vcs", "git"
			if parsed, err := url.Parse(clean); err == nil {
				if index := strings.LastIndexByte(parsed.Path, '@'); index >= 0 && revisionPattern.MatchString(parsed.Path[index+1:]) {
					origin.Revision = parsed.Path[index+1:]
					parsed.Path, parsed.RawPath = parsed.Path[:index], ""
					origin.SafeURL = parsed.String()
				}
			}
		}
		doc.Origins = append(doc.Origins, origin)
	} else {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_source_unresolved", Name: record.name})
	}
}
