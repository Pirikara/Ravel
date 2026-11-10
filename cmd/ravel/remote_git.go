package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Pirikara/Ravel/internal/model"
)

const maxRemoteGitBytes int64 = 512 << 20
const maxRemoteGitEntries = 100000

var gitRefName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)

type boundedGitOutput struct {
	data bytes.Buffer
}

func (output *boundedGitOutput) Write(part []byte) (int, error) {
	if output.data.Len()+len(part) > 1<<20 {
		return 0, errors.New("Git output exceeds 1 MiB")
	}
	return output.data.Write(part)
}

type remoteGitOptions struct {
	Ref, Network, Manager, Configuration, Platform, ImageSource string
	Format, Output, Report                                      string
	All, Recursive, IncludeTestVendor, IncludeBinaries          bool
	IncludeArchives, Resolve, AllowExec, Strict                 bool
}

func runScanRemoteGit(rawURL string, options remoteGitOptions) int {
	repository, err := validateGitURL(rawURL)
	if err != nil || !validGitRef(options.Ref) {
		fmt.Fprintln(os.Stderr, "ravel: remote Git scans require a safe HTTPS or file URL and an explicit --git-ref")
		return 2
	}
	if repository.Scheme == "https" && options.Network != "allow" {
		fmt.Fprintln(os.Stderr, "ravel: HTTPS Git scans require --network allow")
		return 2
	}
	if options.Resolve || options.AllowExec || options.Configuration != "runtimeClasspath" || options.Platform != "" || options.ImageSource != "registry" || options.Report == "-" || options.Report != "" && samePath(options.Report, options.Output) || options.Format != "cyclonedx-json" && options.Format != "spdx-json" && options.Format != "ravel-json" {
		fmt.Fprintln(os.Stderr, "ravel: remote Git scans are static and require distinct, valid output files")
		return 2
	}
	validManager := options.Manager == "auto"
	for _, candidate := range staticManagers {
		validManager = validManager || options.Manager == candidate
	}
	if !validManager || options.All && options.Manager != "auto" || options.Recursive && !options.All ||
		(options.IncludeTestVendor || options.IncludeBinaries || options.IncludeArchives) && (!options.All || !options.Recursive) {
		fmt.Fprintln(os.Stderr, "ravel: invalid remote Git scan manager or discovery options")
		return 2
	}
	root, err := os.MkdirTemp("", "ravel-git-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	defer os.RemoveAll(root)
	checkout := filepath.Join(root, "checkout")
	if err := os.Mkdir(checkout, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if _, err := remoteGitCommand(root, checkout, false, "init", "--quiet"); err == nil {
		_, err = remoteGitCommand(root, checkout, false, "remote", "add", "origin", rawURL)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel: could not initialize temporary Git checkout")
		return 1
	}
	qualified, err := remoteGitRef(root, checkout, options.Ref)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if _, err := remoteGitCommand(root, checkout, false, "fetch", "--depth", "1", "--no-tags", "origin", qualified); err != nil {
		fmt.Fprintln(os.Stderr, "ravel: Git fetch failed or exceeded its time or size limit")
		return 1
	}
	commit, err := remoteGitCommand(root, checkout, false, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	commit = strings.TrimSpace(commit)
	if err != nil || !gitCommitID.MatchString(commit) {
		fmt.Fprintln(os.Stderr, "ravel: fetched Git ref does not resolve to a commit")
		return 1
	}
	if _, err := remoteGitCommand(root, checkout, true, "-c", "core.hooksPath="+os.DevNull, "checkout", "--detach", "--force", commit); err != nil {
		fmt.Fprintln(os.Stderr, "ravel: Git checkout failed or exceeded its time or size limit")
		return 1
	}
	if err := checkRemoteGitTree(root, checkout); err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	intermediate := filepath.Join(root, "scan.ravel.json")
	args := []string{checkout, "--format", "ravel-json", "--output", intermediate}
	if options.All {
		args = append(args, "--all")
	}
	if options.Recursive {
		args = append(args, "--recursive")
	}
	if options.IncludeTestVendor {
		args = append(args, "--include-test-and-vendor")
	}
	if options.IncludeBinaries {
		args = append(args, "--include-binaries")
	}
	if options.IncludeArchives {
		args = append(args, "--include-archives")
	}
	if options.Manager != "auto" {
		args = append(args, "--manager", options.Manager)
	}
	if code := runScanWithProgress(args, false); code != 0 {
		return code
	}
	doc, err := readRavelDocument(intermediate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	stable := "git+" + rawURL + "@" + commit
	doc.Project = strings.TrimSuffix(filepath.Base(repository.Path), ".git")
	rewriteGitPaths(&doc, checkout, stable)
	doc.Git = []model.GitProvenance{{Commit: commit, Dirty: false, Scope: ".", RequestedURL: rawURL, RequestedRef: options.Ref}}
	if _, err := os.Stat(filepath.Join(checkout, ".gitmodules")); err == nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "git_submodules_not_scanned"})
		doc.Coverage.GraphState = "partial"
	}
	return writeScanResult(doc, options.Format, options.Output, options.Report, options.Strict)
}

func validateGitURL(raw string) (*url.URL, error) {
	if strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("unsafe Git URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path == "" {
		return nil, errors.New("unsafe Git URL")
	}
	if u.Scheme == "https" && u.Hostname() != "" {
		return u, nil
	}
	if u.Scheme == "file" && (u.Host == "" || u.Host == "localhost") && filepath.IsAbs(u.Path) {
		return u, nil
	}
	return nil, errors.New("unsupported Git URL")
}

func validGitRef(ref string) bool {
	if gitCommitID.MatchString(ref) {
		return true
	}
	return gitRefName.MatchString(ref) && !strings.Contains(ref, "..") && !strings.Contains(ref, "//") && !strings.HasSuffix(ref, "/") && !strings.HasSuffix(ref, ".") && !strings.HasSuffix(ref, ".lock") && !strings.Contains(ref, "/.")
}

func remoteGitRef(root, checkout, ref string) (string, error) {
	if gitCommitID.MatchString(ref) || strings.HasPrefix(ref, "refs/heads/") || strings.HasPrefix(ref, "refs/tags/") {
		return ref, nil
	}
	out, err := remoteGitCommand(root, checkout, false, "ls-remote", "--refs", "--heads", "--tags", "origin", "refs/heads/"+ref, "refs/tags/"+ref)
	if err != nil {
		return "", errors.New("Git ref lookup failed")
	}
	matches := []string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && gitCommitID.MatchString(fields[0]) && (fields[1] == "refs/heads/"+ref || fields[1] == "refs/tags/"+ref) {
			matches = append(matches, fields[1])
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("Git ref is missing or ambiguous; use refs/heads/ or refs/tags/")
	}
	return matches[0], nil
}

func remoteGitCommand(root, checkout string, safeCheckout bool, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", checkout}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	if safeCheckout {
		cmd.Env = append(cmd.Env, "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	}
	var output boundedGitOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				return "", errors.New("Git command failed or produced excessive output")
			}
			return output.data.String(), nil
		case <-ticker.C:
			if err := checkRemoteGitSize(root); err != nil {
				cancel()
				<-done
				return "", err
			}
		case <-ctx.Done():
			<-done
			return "", errors.New("Git command timed out")
		}
	}
}

func checkRemoteGitSize(root string) error {
	var bytesUsed int64
	var entries int
	return filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		entries++
		if entries > maxRemoteGitEntries {
			return errors.New("remote Git checkout exceeds file-count limit")
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			bytesUsed += info.Size()
			if bytesUsed > maxRemoteGitBytes {
				return errors.New("remote Git checkout exceeds 512 MiB limit")
			}
		}
		return nil
	})
}

func checkRemoteGitTree(root, checkout string) error {
	if err := checkRemoteGitSize(root); err != nil {
		return err
	}
	canonicalCheckout, err := filepath.EvalSymlinks(checkout)
	if err != nil {
		return err
	}
	return filepath.WalkDir(checkout, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == filepath.Join(checkout, ".git") {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink == 0 {
			return nil
		}
		target, err := os.Readlink(path)
		if err != nil || filepath.IsAbs(target) {
			return errors.New("remote Git checkout contains an unsafe symlink")
		}
		resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
		relative, err := filepath.Rel(checkout, resolved)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("remote Git checkout contains an escaping symlink")
		}
		if real, err := filepath.EvalSymlinks(path); err == nil {
			relative, err = filepath.Rel(canonicalCheckout, real)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return errors.New("remote Git checkout contains an escaping symlink")
			}
		}
		return nil
	})
}

func rewriteGitPaths(doc *model.Document, checkout, stable string) {
	change := func(value string) string {
		return strings.ReplaceAll(value, checkout, stable)
	}
	evidence := func(item *model.Evidence) { item.InputPath = change(item.InputPath) }
	doc.Source = change(doc.Source)
	for i := range doc.Sources {
		doc.Sources[i] = change(doc.Sources[i])
	}
	if doc.Root != nil {
		evidence(&doc.Root.Evidence)
	}
	for i := range doc.Components {
		c := &doc.Components[i]
		c.Context = change(c.Context)
		for j := range c.Evidence {
			evidence(&c.Evidence[j])
		}
		for j := range c.Patches {
			c.Patches[j].Path = change(c.Patches[j].Path)
			for k := range c.Patches[j].Evidence {
				evidence(&c.Patches[j].Evidence[k])
			}
		}
	}
	for i := range doc.Edges {
		evidence(&doc.Edges[i].Evidence)
	}
	for i := range doc.Origins {
		doc.Origins[i].LocalPath = change(doc.Origins[i].LocalPath)
		evidence(&doc.Origins[i].Evidence)
	}
	for i := range doc.Development {
		evidence(&doc.Development[i].Evidence)
	}
	for i := range doc.Runtimes {
		doc.Runtimes[i].Scope = change(doc.Runtimes[i].Scope)
		evidence(&doc.Runtimes[i].Evidence)
	}
	for i := range doc.Coverage.Issues {
		doc.Coverage.Issues[i].Name = change(doc.Coverage.Issues[i].Name)
		doc.Coverage.Issues[i].Scope = change(doc.Coverage.Issues[i].Scope)
	}
	for i := range doc.Coverage.Inputs {
		item := &doc.Coverage.Inputs[i]
		if item.Project == "checkout" {
			item.Project = doc.Project
		}
		item.Source = change(item.Source)
		for j := range item.Issues {
			item.Issues[j].Name = change(item.Issues[j].Name)
			item.Issues[j].Scope = change(item.Issues[j].Scope)
		}
	}
}
