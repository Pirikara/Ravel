package rpm

import (
	"path"
	"strings"

	rpmdb "github.com/anchore/go-rpmdb/pkg"

	"github.com/Pirikara/Ravel/internal/model"
)

const maxRPMFileEntries = 1_000_000

// indexFileOwners looks up only paths required by installed packages. A
// filename in the RPM database proves ownership, but not that the file still
// exists in a scanned rootfs. Ghost and missing-ok records are not treated as
// definite providers because RPM does not promise to install those files.
func indexFileOwners(packages []installedPackage, wanted map[string]bool) (map[string][]rpmProvider, []model.Issue) {
	owners := map[string][]rpmProvider{}
	if len(wanted) == 0 {
		return owners, nil
	}
	wantedBasenames := map[string]bool{}
	for name := range wanted {
		wantedBasenames[path.Base(name)] = true
	}
	var issues []model.Issue
	filesSeen := 0
	for _, pkg := range packages {
		entry := pkg.header
		if entry == nil {
			issues = append(issues, model.Issue{Code: "rpm_file_inventory_unavailable", Name: pkg.name})
			return map[string][]rpmProvider{}, issues
		}
		if len(entry.BaseNames) == 0 {
			continue
		}
		if len(entry.BaseNames) != len(entry.DirIndexes) || len(entry.BaseNames) != len(entry.FileFlags) {
			issues = append(issues, model.Issue{Code: "rpm_file_inventory_unavailable", Name: pkg.name})
			return map[string][]rpmProvider{}, issues
		}
		for i, base := range entry.BaseNames {
			filesSeen++
			if filesSeen > maxRPMFileEntries {
				issues = append(issues, model.Issue{Code: "rpm_file_inventory_limited", Name: "RPM database"})
				return map[string][]rpmProvider{}, issues
			}
			if !wantedBasenames[base] {
				continue
			}
			idx := entry.DirIndexes[i]
			if idx < 0 || int(idx) >= len(entry.DirNames) || base == "" || base == "." || base == ".." || strings.ContainsAny(base, "/\x00") {
				issues = append(issues, model.Issue{Code: "rpm_file_inventory_unavailable", Name: pkg.name})
				return map[string][]rpmProvider{}, issues
			}
			dir := entry.DirNames[idx]
			if !validRPMFileDirectory(dir) {
				issues = append(issues, model.Issue{Code: "rpm_file_inventory_unavailable", Name: pkg.name})
				return map[string][]rpmProvider{}, issues
			}
			name := dir + base
			if !wanted[name] || entry.FileFlags[i]&(rpmdb.RPMFILE_GHOST|rpmdb.RPMFILE_MISSINGOK) != 0 {
				continue
			}
			owners[name] = append(owners[name], rpmProvider{ref: pkg.ref, known: true})
		}
	}
	return owners, issues
}

func validRPMFileDirectory(dir string) bool {
	return dir == "/" || strings.HasPrefix(dir, "/") && !strings.HasPrefix(dir, "//") && strings.HasSuffix(dir, "/") && path.Clean(dir)+"/" == dir
}

func validRPMFileRequirement(name string) bool {
	return strings.HasPrefix(name, "/") && path.Clean(name) == name && !strings.ContainsAny(name, "\x00\r\n")
}
