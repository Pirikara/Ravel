package maven

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const maxReactorOutput = 128 << 20

type reactorTree struct {
	path string
	data []byte
	root node
}

func collectResolvedMulti(pom, project string, manifest pomDocument, staticDoc model.Document, networkAllow bool) (model.Document, error) {
	moduleByCoordinate := map[string]string{}
	moduleName := map[string]string{}
	for _, component := range staticDoc.Components {
		if component.Kind != "application" || !strings.HasPrefix(component.ID, "maven-module:") {
			continue
		}
		coordinate := component.Name + "\x00" + component.Version
		if moduleByCoordinate[coordinate] != "" {
			return model.Document{}, fmt.Errorf("Maven reactor has duplicate module coordinates: %s", component.Name)
		}
		moduleByCoordinate[coordinate] = component.ID
		moduleName[component.ID] = component.Name
	}
	if len(moduleByCoordinate) == 0 {
		return model.Document{}, errors.New("Maven reactor has no readable modules")
	}
	tempDir, err := os.MkdirTemp("", "ravel-maven-reactor-")
	if err != nil {
		return model.Document{}, err
	}
	defer os.RemoveAll(tempDir)
	// Maven expands project properties for each reactor project, producing one
	// tree per project without writing generated files into the source tree.
	treePath := filepath.Join(tempDir, "${project.groupId}--${project.artifactId}--${project.version}.json")
	args := []string{"-B", "dependency:tree", "-DoutputType=json", "-DoutputFile=" + treePath}
	if !networkAllow {
		args = append(args, "-o")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mvn", args...)
	cmd.Dir = filepath.Dir(pom)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return model.Document{}, fmt.Errorf("Maven reactor dependency trees timed out: %w", ctx.Err())
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return model.Document{}, fmt.Errorf("Maven reactor dependency trees failed (exit code %d)", exit.ExitCode())
		}
		return model.Document{}, fmt.Errorf("Maven reactor dependency trees failed: %w", err)
	}
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		return model.Document{}, err
	}
	if len(entries) != len(moduleByCoordinate)+1 {
		return model.Document{}, fmt.Errorf("Maven wrote %d reactor trees; expected %d", len(entries), len(moduleByCoordinate)+1)
	}
	trees := map[string]reactorTree{}
	totalSize := int64(0)
	rootGroup := strings.TrimSpace(manifest.GroupID)
	if rootGroup == "" {
		rootGroup = strings.TrimSpace(manifest.Parent.GroupID)
	}
	rootVersion := strings.TrimSpace(manifest.Version)
	if rootVersion == "" {
		rootVersion = strings.TrimSpace(manifest.Parent.Version)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return model.Document{}, err
		}
		if filepath.Ext(entry.Name()) != ".json" || !info.Mode().IsRegular() {
			return model.Document{}, fmt.Errorf("Maven wrote an unexpected reactor output: %s", entry.Name())
		}
		totalSize += info.Size()
		if totalSize > maxReactorOutput {
			return model.Document{}, errors.New("Maven reactor trees exceeded size limit")
		}
		path := filepath.Join(tempDir, entry.Name())
		data, root, err := readTree(path)
		if err != nil {
			return model.Document{}, err
		}
		coordinate := root.GroupID + ":" + root.ArtifactID + "\x00" + root.Version
		ref := moduleByCoordinate[coordinate]
		if ref == "" {
			if !literalMavenCoordinateMatches(strings.TrimSpace(manifest.ArtifactID), root.ArtifactID) ||
				!literalMavenCoordinateMatches(rootGroup, root.GroupID) ||
				!literalMavenCoordinateMatches(rootVersion, root.Version) {
				return model.Document{}, fmt.Errorf("Maven wrote a tree for an undeclared reactor project: %s:%s", root.GroupID, root.ArtifactID)
			}
			ref = "root"
		}
		if _, exists := trees[ref]; exists {
			return model.Document{}, fmt.Errorf("Maven wrote duplicate reactor trees for %s", root.ArtifactID)
		}
		trees[ref] = reactorTree{path: path, data: data, root: root}
	}
	if len(trees) != len(moduleByCoordinate)+1 || trees["root"].path == "" {
		return model.Document{}, errors.New("Maven omitted a reactor dependency tree")
	}
	localByPackageRef := map[string]string{}
	for ref, tree := range trees {
		localByPackageRef[treeNodeRef(tree.root)] = ref
	}
	doc := common.NewDocument(pom, project, "maven", nil)
	rootTree := trees["root"]
	rootEvidence := common.Evidence("mvn dependency:tree root", "maven-tree", "/", rootTree.data)
	rootEvidence.Method = "resolver-output"
	doc.Root = &model.ProjectIdentity{Name: rootTree.root.GroupID + ":" + rootTree.root.ArtifactID,
		Version: rootTree.root.Version, Evidence: rootEvidence}
	doc.Sources = append(doc.Sources, staticDoc.Sources...)
	doc.Origins = append(doc.Origins, staticDoc.Origins...)
	for _, component := range staticDoc.Components {
		if component.Kind == "application" && strings.HasPrefix(component.ID, "maven-module:") {
			doc.Components = append(doc.Components, component)
		}
	}
	seenEdges := map[string]bool{}
	for _, edge := range staticDoc.Edges {
		if edge.Kind == "module" {
			appendReactorEdge(&doc, seenEdges, edge)
		}
	}
	for ref, tree := range trees {
		// The module's own tree supplies its dependencies. Stop when another
		// project is reached so the same subtree is not attributed twice.
		treeDoc, err := collectTree(tree.path, project, tree.data, tree.root, func(n node) bool {
			return localByPackageRef[treeNodeRef(n)] != ""
		})
		if err != nil {
			return model.Document{}, err
		}
		label := "root"
		if ref != "root" {
			label = moduleName[ref]
		}
		inputPath := "mvn dependency:tree " + label
		for _, component := range treeDoc.Components {
			if localByPackageRef[component.ID] != "" {
				continue
			}
			component.ID = reactorExternalRef(ref, component.ID)
			component.Context = "project=" + label + ";" + component.Context
			component.Context = strings.TrimSuffix(component.Context, ";")
			for i := range component.Evidence {
				component.Evidence[i].InputPath = inputPath
			}
			doc.Components = append(doc.Components, component)
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: component.Name, Scope: label})
		}
		for _, edge := range treeDoc.Edges {
			if edge.From == "root" {
				edge.From = ref
			} else if local := localByPackageRef[edge.From]; local != "" {
				edge.From = local
			} else {
				edge.From = reactorExternalRef(ref, edge.From)
			}
			if local := localByPackageRef[edge.To]; local != "" {
				edge.To = local
			} else {
				edge.To = reactorExternalRef(ref, edge.To)
			}
			edge.Evidence.InputPath = inputPath
			appendReactorEdge(&doc, seenEdges, edge)
		}
		for _, issue := range treeDoc.Coverage.Issues {
			if issue.Code != "manifest_freshness_unverified" && issue.Code != "missing_source" {
				issue.Scope = label
				doc.Coverage.Issues = append(doc.Coverage.Issues, issue)
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func treeNodeRef(n node) string {
	key := strings.Join([]string{n.GroupID, n.ArtifactID, n.Version, n.Type, n.Classifier}, "\x00")
	return "maven:" + common.ID(key)
}

func literalMavenCoordinateMatches(declared, resolved string) bool {
	return declared == "" || strings.ContainsAny(declared, "${}") || declared == resolved
}

func reactorExternalRef(projectRef, packageRef string) string {
	return "maven:" + common.ID(projectRef+"\x00"+packageRef)
}

func appendReactorEdge(doc *model.Document, seen map[string]bool, edge model.Edge) {
	key := strings.Join([]string{edge.From, edge.To, edge.Kind, edge.Condition}, "\x00")
	if !seen[key] {
		doc.Edges = append(doc.Edges, edge)
		seen[key] = true
	}
}
