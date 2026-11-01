package gradle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const maxGraphOutput = 64 << 20

var configurationName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,127}$`)

// This script is supplied by Ravel. It reads Gradle's selected graph without
// asking for artifact files, and writes a bounded JSON interchange file.
const graphInitScript = `import groovy.json.JsonOutput
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.component.ProjectComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.api.artifacts.result.UnresolvedDependencyResult

gradle.projectsLoaded { g ->
  g.rootProject.tasks.register('ravelSbomGraph') {
    doLast {
      def configurationName = System.getProperty('ravel.configuration')
      def projects = g.rootProject.allprojects.findAll { p ->
        def configuration = p.configurations.findByName(configurationName)
        configuration != null && configuration.canBeResolved
      }.sort { a, b -> a.path <=> b.path }
      if (projects.isEmpty()) {
        throw new GradleException('Ravel configuration is unavailable or not resolvable')
      }
      def describe = { component, encode, projectPath ->
        def identifier = component.id
        def kind = identifier instanceof ModuleComponentIdentifier ? 'module' :
                   identifier instanceof ProjectComponentIdentifier ? 'project' : 'other'
        def dependencies = component.dependencies.findAll { it instanceof ResolvedDependencyResult }
          .collect { encode(it.selected.id) }
        def failed = component.dependencies.count { it instanceof UnresolvedDependencyResult }
        [id: encode(identifier), kind: kind, projectPath: projectPath,
         group: kind == 'module' ? identifier.group : '',
         name: kind == 'module' ? identifier.module :
               kind == 'project' ? identifier.projectPath : identifier.displayName,
         version: kind == 'module' ? identifier.version : '',
         dependencies: dependencies, failed: failed,
         variantCount: component.variants.size()]
      }
      def nodes = []
      def rootId
      if (projects.size() == 1 && projects[0].path == ':') {
        def graph = projects[0].configurations.getByName(configurationName).incoming.resolutionResult
        rootId = graph.root.id.displayName
        nodes.addAll(graph.allComponents.collect { component ->
          describe(component, { id -> id.displayName }, ':')
        })
      } else {
        rootId = 'ravel:aggregate-root'
        def root = [id: rootId, kind: 'project', name: ':', projectPath: ':',
                    dependencies: [], failed: 0, variantCount: 1]
        nodes << root
        projects.each { p ->
          def graph = p.configurations.getByName(configurationName).incoming.resolutionResult
          def encode = { id -> p.path + '|' + id.displayName }
          root.dependencies << encode(graph.root.id)
          nodes.addAll(graph.allComponents.collect { component ->
            describe(component, encode, p.path)
          })
        }
      }
      nodes.sort { a, b -> a.id <=> b.id }
      new File(System.getProperty('ravel.output')).setText(JsonOutput.toJson(
        [root: rootId, configuration: configurationName, nodes: nodes]), 'UTF-8')
    }
  }
}
`

type resolvedGraph struct {
	Root          string `json:"root"`
	Configuration string `json:"configuration"`
	Nodes         []struct {
		ID           string   `json:"id"`
		Kind         string   `json:"kind"`
		ProjectPath  string   `json:"projectPath"`
		Group        string   `json:"group"`
		Name         string   `json:"name"`
		Version      string   `json:"version"`
		Dependencies []string `json:"dependencies"`
		Failed       int      `json:"failed"`
		VariantCount int      `json:"variantCount"`
	} `json:"nodes"`
}

// CollectResolved runs Gradle only after CLI opt-in. Gradle build logic and
// init scripts can execute arbitrary code; --offline controls only Gradle's
// own dependency fetching.
func CollectResolved(buildFile, project, configuration string, networkAllow bool) (model.Document, error) {
	base := filepath.Base(buildFile)
	if base != "build.gradle" && base != "build.gradle.kts" {
		return model.Document{}, errors.New("Gradle resolver requires build.gradle or build.gradle.kts")
	}
	if !configurationName.MatchString(configuration) {
		return model.Document{}, errors.New("invalid Gradle configuration name")
	}
	if _, err := os.Stat(buildFile); err != nil {
		return model.Document{}, err
	}
	tempDir, err := os.MkdirTemp("", "ravel-gradle-")
	if err != nil {
		return model.Document{}, err
	}
	defer os.RemoveAll(tempDir)
	initPath := filepath.Join(tempDir, "ravel.init.gradle")
	graphPath := filepath.Join(tempDir, "graph.json")
	if err := os.WriteFile(initPath, []byte(graphInitScript), 0o600); err != nil {
		return model.Document{}, err
	}
	command := "gradle"
	if networkAllow {
		wrapper := filepath.Join(filepath.Dir(buildFile), "gradlew")
		if stat, err := os.Stat(wrapper); err == nil && stat.Mode().IsRegular() && stat.Mode().Perm()&0o111 != 0 {
			command, err = filepath.Abs(wrapper)
			if err != nil {
				return model.Document{}, err
			}
		}
	}
	args := []string{"--no-daemon", "--no-configuration-cache", "--no-configure-on-demand", "--console=plain", "--init-script", initPath,
		"-Dravel.output=" + graphPath, "-Dravel.configuration=" + configuration}
	if !networkAllow {
		args = append(args, "--offline")
	}
	args = append(args, "ravelSbomGraph")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = filepath.Dir(buildFile)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return model.Document{}, fmt.Errorf("Gradle graph resolution timed out: %w", ctx.Err())
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return model.Document{}, fmt.Errorf("Gradle graph resolution failed (exit code %d)", exit.ExitCode())
		}
		return model.Document{}, fmt.Errorf("Gradle graph resolution failed: %w", err)
	}
	f, err := os.Open(graphPath)
	if err != nil {
		return model.Document{}, fmt.Errorf("Gradle did not write a graph: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxGraphOutput+1))
	if err != nil {
		return model.Document{}, err
	}
	if len(data) > maxGraphOutput {
		return model.Document{}, errors.New("Gradle graph exceeded size limit")
	}
	return collectGraph(buildFile, project, configuration, data)
}

func collectGraph(buildFile, project, configuration string, data []byte) (model.Document, error) {
	var graph resolvedGraph
	if err := json.Unmarshal(data, &graph); err != nil {
		return model.Document{}, fmt.Errorf("invalid Gradle graph: %w", err)
	}
	if graph.Root == "" || graph.Configuration != configuration || len(graph.Nodes) == 0 || len(graph.Nodes) > 100000 {
		return model.Document{}, errors.New("invalid Gradle graph root, configuration, or node count")
	}
	byID := map[string]string{graph.Root: "root"}
	seen := map[string]bool{}
	for _, node := range graph.Nodes {
		if node.ID == "" || seen[node.ID] || node.Failed < 0 || node.VariantCount < 0 {
			return model.Document{}, errors.New("invalid or duplicate Gradle graph node")
		}
		seen[node.ID] = true
		if node.ID != graph.Root {
			byID[node.ID] = "gradle:" + common.ID(node.ID)
		}
	}
	if !seen[graph.Root] {
		return model.Document{}, errors.New("Gradle graph root node missing")
	}
	doc := common.NewDocument(buildFile, project, "gradle", data)
	input := "gradle " + configuration
	for i, node := range graph.Nodes {
		ev := common.Evidence(input, "gradle-resolution-result", fmt.Sprintf("/nodes/%d", i), data)
		ev.Method = "resolver-output"
		if node.Failed > 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency"})
		}
		if node.VariantCount > 1 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "gradle_variant_union"})
		}
		if node.ID != graph.Root {
			if node.Name == "" {
				return model.Document{}, errors.New("Gradle graph node missing name")
			}
			kind := "package"
			purl := ""
			switch node.Kind {
			case "module":
				if node.Group == "" || node.Version == "" {
					return model.Document{}, errors.New("Gradle module missing coordinates")
				}
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: node.Group + ":" + node.Name})
			case "project":
				kind = "application"
			case "other":
				kind = "module"
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "gradle_unidentified_component"})
			default:
				return model.Document{}, errors.New("Gradle graph node has invalid kind")
			}
			name := node.Name
			if node.Kind == "module" {
				name = node.Group + ":" + node.Name
			} else if node.Kind == "other" {
				name = "unidentified Gradle component"
			}
			context := "configuration=" + configuration
			if node.ProjectPath != "" {
				context += ";project=" + node.ProjectPath
			}
			doc.Components = append(doc.Components, model.Component{ID: byID[node.ID], Kind: kind, Name: name, Version: node.Version, PURL: purl, Context: context, Evidence: []model.Evidence{ev}})
		}
		for j, dependency := range node.Dependencies {
			to, ok := byID[dependency]
			if !ok || to == "root" || dependency == node.ID {
				return model.Document{}, errors.New("Gradle graph has dangling or self dependency")
			}
			kind := "depends_on"
			if node.ID == graph.Root {
				kind = "direct"
			}
			edgeEvidence := ev
			edgeEvidence.Pointer = fmt.Sprintf("/nodes/%d/dependencies/%d", i, j)
			doc.Edges = append(doc.Edges, model.Edge{From: byID[node.ID], To: to, Kind: kind, Evidence: edgeEvidence})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}
