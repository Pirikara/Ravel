package stack

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

const maxLockBytes = 16 << 20

var hackagePackage = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9-]{0,127})-([0-9]+(?:\.[0-9]+)*)(?:@(sha256:[0-9a-fA-F]{64},[0-9]+|rev:[0-9]+))?$`)
var gitCommit = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
var packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)
var packageVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)

type lockfile struct {
	Packages []struct {
		Completed completedPackage `yaml:"completed"`
	} `yaml:"packages"`
	Snapshots []yaml.Node `yaml:"snapshots"`
}

type completedPackage struct {
	Hackage string `yaml:"hackage"`
	Git     string `yaml:"git"`
	Commit  string `yaml:"commit"`
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	Subdir  string `yaml:"subdir"`
}

// CollectLock inventories completed immutable package locations. The lockfile
// also names snapshots, but does not enumerate which snapshot packages a build
// uses, so no selected dependency graph can be inferred from it alone.
func CollectLock(filename, project string) (model.Document, error) {
	file, err := os.Open(filename)
	if err != nil {
		return model.Document{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxLockBytes {
		return model.Document{}, errors.New("Stack lockfile size is invalid or exceeds 16 MiB")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return model.Document{}, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return model.Document{}, fmt.Errorf("invalid Stack lockfile YAML: %w", err)
	}
	if err := checkYAML(&root, 0, new(int)); err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := root.Decode(&lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid Stack lockfile: %w", err)
	}
	if lock.Packages == nil && lock.Snapshots == nil {
		return model.Document{}, errors.New("Stack lockfile has neither packages nor snapshots")
	}
	doc := common.NewDocument(filename, project, "stack", data)
	baseEvidence := common.Evidence(filename, "stack-lock", "", data)
	for i, pkg := range lock.Packages {
		completed := pkg.Completed
		evidence := baseEvidence
		evidence.Pointer = fmt.Sprintf("/packages/%d/completed", i)
		id := "stack:" + common.ID(filename+"\x00"+evidence.Pointer)
		component := model.Component{ID: id, Kind: "package", Context: "selection=unverified", Evidence: []model.Evidence{evidence}}
		switch {
		case completed.Hackage != "" && completed.Git == "":
			match := hackagePackage.FindStringSubmatch(completed.Hackage)
			if match == nil {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "stack_lock_package_invalid", Name: completed.Hackage})
				continue
			}
			component.Name, component.Version = match[1], match[2]
			component.PURL = packageurl.NewPackageURL("hackage", "", component.Name, component.Version, nil, "").ToString()
			if match[3] != "" {
				component.Context += ";hackage-pin=" + match[3]
			}
		case completed.Git != "" && completed.Hackage == "":
			if !packageName.MatchString(completed.Name) || !gitCommit.MatchString(completed.Commit) || completed.Version != "" && !packageVersion.MatchString(completed.Version) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "stack_lock_package_invalid", Name: completed.Name})
				continue
			}
			component.Name, component.Version = completed.Name, completed.Version
			if completed.Subdir != "" {
				if len(completed.Subdir) > 256 || strings.ContainsAny(completed.Subdir, "\x00\r\n;") || strings.HasPrefix(completed.Subdir, "/") || completed.Subdir == ".." || strings.HasPrefix(completed.Subdir, "../") || path.Clean(completed.Subdir) != completed.Subdir {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "stack_lock_package_invalid", Name: completed.Name})
					continue
				}
				component.Context += ";subdir=" + completed.Subdir
			}
			if clean := safeurl.Clean(completed.Git); clean != "" {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "vcs", SafeURL: clean, Revision: completed.Commit, Status: "declared", Evidence: evidence})
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: completed.Name})
			}
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "stack_lock_package_unhandled", Name: fmt.Sprintf("entry-%d", i)})
			continue
		}
		doc.Components = append(doc.Components, component)
		if len(doc.Components) > 100000 {
			return model.Document{}, errors.New("Stack lockfile has too many packages")
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "stack_lock_selection_unverified"},
		model.Issue{Code: "stack_snapshot_contents_unavailable"},
		model.Issue{Code: "stack_distribution_bytes_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

func checkYAML(node *yaml.Node, depth int, count *int) error {
	*count = *count + 1
	if depth > 64 || *count > 100000 {
		return errors.New("Stack lockfile YAML exceeds nesting or node limit")
	}
	if node.Kind == yaml.AliasNode {
		return errors.New("Stack lockfile YAML aliases are unsupported")
	}
	for _, child := range node.Content {
		if err := checkYAML(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}
