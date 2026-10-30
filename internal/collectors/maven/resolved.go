package maven

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const maxTreeOutput = 64 << 20

// CollectResolved asks Maven for its selected dependency tree. Maven can run
// build extensions and plugins, so the CLI requires explicit execution opt-in.
func CollectResolved(pom, project string, networkAllow bool) (model.Document, error) {
	if filepath.Base(pom) != "pom.xml" {
		return model.Document{}, errors.New("Maven resolver requires pom.xml")
	}
	manifest, _, err := readPOM(pom)
	if err != nil {
		return model.Document{}, err
	}
	tempDir, err := os.MkdirTemp("", "ravel-maven-")
	if err != nil {
		return model.Document{}, err
	}
	defer os.RemoveAll(tempDir)
	treePath := filepath.Join(tempDir, "dependency-tree.json")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{"-B", "-N", "dependency:tree", "-DoutputType=json", "-DoutputFile=" + treePath}
	if !networkAllow {
		args = append(args, "-o")
	}
	cmd := exec.CommandContext(ctx, "mvn", args...)
	cmd.Dir = filepath.Dir(pom)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return model.Document{}, fmt.Errorf("Maven dependency tree timed out: %w", ctx.Err())
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return model.Document{}, fmt.Errorf("Maven dependency tree failed (exit code %d)", exit.ExitCode())
		}
		return model.Document{}, fmt.Errorf("Maven dependency tree failed: %w", err)
	}
	stat, err := os.Stat(treePath)
	if err != nil {
		return model.Document{}, fmt.Errorf("Maven did not write a dependency tree: %w", err)
	}
	if stat.Size() > maxTreeOutput {
		return model.Document{}, errors.New("Maven dependency tree exceeded size limit")
	}
	doc, err := CollectTree(treePath, project)
	if err != nil {
		return model.Document{}, err
	}
	doc.Source = pom
	issues := doc.Coverage.Issues[:0]
	for _, issue := range doc.Coverage.Issues {
		if issue.Code != "manifest_freshness_unverified" {
			issues = append(issues, issue)
		}
	}
	doc.Coverage.Issues = issues
	doc.Coverage.GraphState = "complete_for_scope"
	if len(manifest.Modules) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "multi_module_scope_root", Name: pom})
	}
	for i := range doc.Components {
		for j := range doc.Components[i].Evidence {
			doc.Components[i].Evidence[j].InputPath = "mvn dependency:tree"
		}
	}
	for i := range doc.Edges {
		doc.Edges[i].Evidence.InputPath = "mvn dependency:tree"
	}
	common.Finalize(&doc)
	return doc, nil
}
