package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Pirikara/Ravel/internal/model"
)

var gitCommitID = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func attachLocalGit(doc *model.Document, input string) {
	provenance, err := localGitProvenance(input)
	if err != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "git_provenance_unavailable"})
		return
	}
	if provenance != nil {
		doc.Git = []model.GitProvenance{*provenance}
	}
}

func localGitProvenance(input string) (*model.GitProvenance, error) {
	absolute, err := filepath.Abs(input)
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	directory := absolute
	if info, err := os.Stat(absolute); err != nil || !info.IsDir() {
		directory = filepath.Dir(absolute)
	}
	root, err := gitOutput(directory, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, nil // An exported source tree has no Git provenance.
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	commit, err := gitOutput(directory, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || !gitCommitID.MatchString(commit) {
		return nil, fmt.Errorf("cannot resolve checked-out Git commit")
	}
	status, err := gitOutput(directory, "-c", "core.fsmonitor=false", "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return nil, fmt.Errorf("cannot read Git worktree status: %w", err)
	}
	scope, err := filepath.Rel(root, absolute)
	if err != nil || scope == ".." || strings.HasPrefix(scope, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("scan input is outside its Git worktree")
	}
	return &model.GitProvenance{Commit: commit, Dirty: status != "", Scope: filepath.ToSlash(scope)}, nil
}

func gitOutput(directory string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", directory}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var output boundedGitOutput
	cmd.Stdout = &output
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(output.data.String()), nil
}
