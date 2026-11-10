package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/bundler"
	"github.com/Pirikara/Ravel/internal/collectors/cargo"
	"github.com/Pirikara/Ravel/internal/collectors/dpkg"
	"github.com/Pirikara/Ravel/internal/collectors/gomod"
	"github.com/Pirikara/Ravel/internal/collectors/gradle"
	"github.com/Pirikara/Ravel/internal/collectors/javaarchive"
	"github.com/Pirikara/Ravel/internal/collectors/maven"
	"github.com/Pirikara/Ravel/internal/collectors/npm"
	"github.com/Pirikara/Ravel/internal/collectors/oci"
	"github.com/Pirikara/Ravel/internal/collectors/python"
	"github.com/Pirikara/Ravel/internal/collectors/rpm"
	"github.com/Pirikara/Ravel/internal/collectors/runtimeversion"
	"github.com/Pirikara/Ravel/internal/collectors/swiftpm"
	"github.com/Pirikara/Ravel/internal/export"
	"github.com/Pirikara/Ravel/internal/merge"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/report"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	code := 2
	switch os.Args[1] {
	case "version", "--version":
		if len(os.Args) != 2 {
			usage()
			break
		}
		fmt.Println("ravel", buildVersion())
		code = 0
	case "scan":
		code = runScan(os.Args[2:])
	case "explain":
		code = runExplain(os.Args[2:])
	case "graph":
		code = runGraph(os.Args[2:])
	case "diff":
		code = runDiff(os.Args[2:])
	case "merge":
		code = runMerge(os.Args[2:])
	case "enrich":
		code = runEnrich(os.Args[2:])
	case "vex":
		code = runVEX(os.Args[2:])
	case "update":
		code = runUpdate(os.Args[2:])
	default:
		usage()
	}
	os.Exit(code)
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ravel version")
	fmt.Fprintln(os.Stderr, "       ravel scan PATH|IMAGE:TAG|GIT_URL [--git-ref REF --network allow] [--manager NAME|--all [--recursive [--include-test-and-vendor] [--include-binaries] [--include-archives]]] [--image-source registry|docker] [--format cyclonedx-json|spdx-json|ravel-json] [--output FILE] [--report FILE] [--strict] [--resolve --allow-exec --network deny|allow] [--configuration NAME] [--platform OS/ARCH]")
	fmt.Fprintln(os.Stderr, "       ravel explain PACKAGE --input ravel.json [--format text|json]")
	fmt.Fprintln(os.Stderr, "       ravel graph --input ravel.json [--format html|dot|text] [--output FILE] [--focus PACKAGE] [--direction dependencies|dependents] [--depth N]")
	fmt.Fprintln(os.Stderr, "       ravel diff BEFORE.ravel.json AFTER.ravel.json [--format text|json]")
	fmt.Fprintln(os.Stderr, "       ravel merge [--name PROJECT] [--format cyclonedx-json|spdx-json|ravel-json] [--output FILE] [--report FILE] [--strict] INPUT.ravel.json...")
	fmt.Fprintln(os.Stderr, "       ravel enrich INPUT.ravel.json --network allow [--ecosystem rubygems|npm|pypi] [--registry HTTPS_URL] [--max-requests N] [--format ravel-json|cyclonedx-json|spdx-json] [--output FILE] [--report FILE] [--strict]")
	fmt.Fprintln(os.Stderr, "       ravel vex --input INPUT.ravel.json --vex FILE.openvex.json [--format text|json] [--output FILE]")
	fmt.Fprintln(os.Stderr, "       ravel update [--check] [--channel auto|stable|beta]")
}

func runMerge(args []string) int {
	fs := flag.NewFlagSet("merge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "merged", "merged project name")
	format := fs.String("format", "cyclonedx-json", "output format")
	output := fs.String("output", "-", "output file or -")
	reportPath := fs.String("report", "", "coverage report path")
	strict := fs.Bool("strict", false, "fail on partial coverage")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	paths := append([]string{}, fs.Args()...)
	if len(paths) < 2 || *name == "" || *reportPath == "-" || *reportPath != "" && samePath(*reportPath, *output) {
		usage()
		return 2
	}
	sort.Strings(paths)
	for i, path := range paths {
		if samePath(path, *output) || *reportPath != "" && samePath(path, *reportPath) {
			fmt.Fprintln(os.Stderr, "ravel: merge output cannot overwrite an input")
			return 2
		}
		for j := 0; j < i; j++ {
			if samePath(path, paths[j]) {
				fmt.Fprintln(os.Stderr, "ravel: duplicate merge input")
				return 2
			}
		}
	}
	inputs := make([]model.Document, 0, len(paths))
	for _, path := range paths {
		doc, err := readRavelDocument(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		protected := append([]string{doc.Source}, doc.Sources...)
		for _, source := range protected {
			if source != "" && (samePath(*output, source) || *reportPath != "" && samePath(*reportPath, source)) {
				fmt.Fprintln(os.Stderr, "ravel: merge output cannot overwrite a scanned source")
				return 2
			}
		}
		inputs = append(inputs, doc)
	}
	doc, err := merge.Documents(*name, inputs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	var data []byte
	switch *format {
	case "cyclonedx-json":
		data, err = export.CycloneDX(doc)
	case "spdx-json":
		data, err = export.SPDX23(doc)
	case "ravel-json":
		data, err = json.MarshalIndent(doc, "", "  ")
	default:
		fmt.Fprintln(os.Stderr, "ravel: unsupported format")
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if err := write(*output, append(data, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if *reportPath != "" {
		coverage, err := coverageReport(doc, *format)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		if err := write(*reportPath, append(coverage, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
	}
	fmt.Fprintf(os.Stderr, "ravel: merged %d inputs, %d packages, graph=%s, origin=%s\n", len(doc.Coverage.Inputs), doc.Coverage.Packages, doc.Coverage.GraphState, doc.Coverage.OriginState)
	if *strict && len(doc.Coverage.Issues) > 0 {
		return 3
	}
	return 0
}

func readRavelDocument(path string) (model.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Document{}, err
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return model.Document{}, fmt.Errorf("invalid Ravel JSON: %w", err)
	}
	if doc.SchemaVersion != "0.1" {
		return model.Document{}, errors.New("unsupported Ravel JSON schema version")
	}
	return doc, nil
}

func runDiff(args []string) int {
	beforePath, afterPath := "", ""
	if len(args) >= 2 && !strings.HasPrefix(args[0], "-") && !strings.HasPrefix(args[1], "-") {
		beforePath, afterPath, args = args[0], args[1], args[2:]
	}
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if beforePath == "" && fs.NArg() == 2 {
		beforePath, afterPath = fs.Arg(0), fs.Arg(1)
	} else if fs.NArg() != 0 {
		usage()
		return 2
	}
	if beforePath == "" || afterPath == "" || (*format != "text" && *format != "json") {
		usage()
		return 2
	}
	before, err := readRavelDocument(beforePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	after, err := readRavelDocument(afterPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	difference := report.Compare(before, after)
	if *format == "json" {
		out, err := json.MarshalIndent(difference, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		_, err = os.Stdout.Write(append(out, '\n'))
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		return 0
	}
	if _, err := os.Stdout.WriteString(report.DiffText(difference)); err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	return 0
}

func runExplain(args []string) int {
	query := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		query, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "Ravel JSON input")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if query == "" && fs.NArg() == 1 {
		query = fs.Arg(0)
	} else if fs.NArg() != 0 {
		usage()
		return 2
	}
	if query == "" || *input == "" || (*format != "text" && *format != "json") {
		usage()
		return 2
	}
	doc, err := readRavelDocument(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	explanation, err := report.Explain(doc, query)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if *format == "json" {
		out, err := json.MarshalIndent(explanation, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		_, err = os.Stdout.Write(append(out, '\n'))
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		return 0
	}
	_, err = os.Stdout.WriteString(report.Text(doc, explanation))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	return 0
}

func runScan(args []string) int {
	path := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "cyclonedx-json", "output format")
	output := fs.String("output", "-", "output file or -")
	report := fs.String("report", "", "coverage report path")
	manager := fs.String("manager", "auto", "package manager")
	all := fs.Bool("all", false, "scan all static managers in one directory")
	recursive := fs.Bool("recursive", false, "include nested projects with --all")
	includeTestVendor := fs.Bool("include-test-and-vendor", false, "include tmp, fixtures, testdata, and vendor with --all --recursive")
	includeBinaries := fs.Bool("include-binaries", false, "include local Go ELF and Mach-O executables with --all --recursive")
	includeArchives := fs.Bool("include-archives", false, "include supported package archives with --all --recursive")
	strict := fs.Bool("strict", false, "fail on partial coverage")
	resolve := fs.Bool("resolve", false, "resolve dependencies with a package manager command")
	allowExec := fs.Bool("allow-exec", false, "allow a package manager command")
	network := fs.String("network", "deny", "deny or allow")
	configuration := fs.String("configuration", "runtimeClasspath", "Gradle configuration to resolve")
	platform := fs.String("platform", "", "OCI image platform: os/architecture[/variant]")
	imageSource := fs.String("image-source", "registry", "image reference source: registry or docker")
	gitRef := fs.String("git-ref", "", "Git branch, tag, qualified ref, or full commit for a remote URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 1 || (path != "." && fs.NArg() > 0) {
		fmt.Fprintln(os.Stderr, "ravel: specify exactly one scan path")
		return 2
	}
	if fs.NArg() == 1 {
		path = fs.Arg(0)
	}
	if *network != "deny" && *network != "allow" || *resolve && !*allowExec {
		fmt.Fprintln(os.Stderr, "ravel: --resolve requires --allow-exec; --network must be deny or allow")
		return 2
	}
	if *imageSource != "registry" && *imageSource != "docker" {
		fmt.Fprintln(os.Stderr, "ravel: --image-source must be registry or docker")
		return 2
	}
	if *gitRef != "" || strings.HasPrefix(strings.ToLower(path), "https://") || strings.HasPrefix(strings.ToLower(path), "file://") {
		return runScanRemoteGit(path, remoteGitOptions{
			Ref: *gitRef, Network: *network, Manager: *manager, All: *all, Recursive: *recursive,
			IncludeTestVendor: *includeTestVendor, IncludeBinaries: *includeBinaries, IncludeArchives: *includeArchives,
			Resolve: *resolve, AllowExec: *allowExec, Configuration: *configuration, Platform: *platform,
			ImageSource: *imageSource, Format: *format, Output: *output, Report: *report, Strict: *strict,
		})
	}
	remotePath := strings.ToLower(path)
	for _, prefix := range []string{"http://", "https://", "git://", "ssh://", "docker://", "oci://", "git@"} {
		if strings.HasPrefix(remotePath, prefix) {
			fmt.Fprintln(os.Stderr, "ravel: scan accepts a local path or image reference, not a URL")
			return 2
		}
	}
	if *manager != "auto" && *manager != "bundler" && *manager != "gemspec" && *manager != "github-actions" && *manager != "ruby-gem" && *manager != "npm" && *manager != "bun" && *manager != "deno" && *manager != "swiftpm" && *manager != "nuget" && *manager != "nuget-archive" && *manager != "npm-archive" && *manager != "deb-archive" && *manager != "rpm-archive" && *manager != "uv" && *manager != "pylock" && *manager != "requirements" && *manager != "pnpm" && *manager != "poetry" && *manager != "yarn" && *manager != "cargo" && *manager != "composer" && *manager != "conan" && *manager != "cocoapods" && *manager != "pipenv" && *manager != "pdm" && *manager != "go" && *manager != "pub" && *manager != "gradle" && *manager != "maven" && *manager != "sbt" && *manager != "mix" && *manager != "rebar" && *manager != "shards" && *manager != "cabal" && *manager != "stack" && *manager != "julia" && *manager != "renv" && *manager != "conda-lock" && *manager != "pixi" && *manager != "dpkg" && *manager != "apk" && *manager != "rpm" && *manager != "oci" && *manager != "java-archive" && *manager != "python-wheel" {
		fmt.Fprintln(os.Stderr, "ravel: unsupported manager")
		return 2
	}
	if *all {
		if *includeTestVendor && !*recursive {
			fmt.Fprintln(os.Stderr, "ravel: --include-test-and-vendor requires --all --recursive")
			return 2
		}
		if *includeBinaries && !*recursive {
			fmt.Fprintln(os.Stderr, "ravel: --include-binaries requires --all --recursive")
			return 2
		}
		if *includeArchives && !*recursive {
			fmt.Fprintln(os.Stderr, "ravel: --include-archives requires --all --recursive")
			return 2
		}
		if *manager != "auto" || *resolve || *allowExec || *configuration != "runtimeClasspath" || *platform != "" || *imageSource != "registry" || *network == "allow" {
			fmt.Fprintln(os.Stderr, "ravel: --all is static and cannot be combined with --manager, --resolve, --allow-exec, --configuration, --platform, --image-source, or --network allow")
			return 2
		}
		return runScanAll(path, *format, *output, *report, *strict, *recursive, *includeTestVendor, *includeBinaries, *includeArchives)
	}
	if *includeTestVendor {
		fmt.Fprintln(os.Stderr, "ravel: --include-test-and-vendor requires --all --recursive")
		return 2
	}
	if *includeBinaries {
		fmt.Fprintln(os.Stderr, "ravel: --include-binaries requires --all --recursive")
		return 2
	}
	if *includeArchives {
		fmt.Fprintln(os.Stderr, "ravel: --include-archives requires --all --recursive")
		return 2
	}
	if *recursive {
		fmt.Fprintln(os.Stderr, "ravel: --recursive requires --all")
		return 2
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) && looksLikeImageReference(path) {
		if *manager != "auto" && *manager != "oci" || *resolve || *allowExec || *configuration != "runtimeClasspath" || *imageSource == "docker" && *network == "allow" {
			fmt.Fprintln(os.Stderr, "ravel: image references require --manager auto|oci and cannot use resolver options")
			return 2
		}
		forbiddenNetwork := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "network" && f.Value.String() == "deny" {
				forbiddenNetwork = true
			}
		})
		if forbiddenNetwork && *imageSource == "registry" {
			fmt.Fprintln(os.Stderr, "ravel: registry images require network access; omit --network or use --network allow")
			return 2
		}
		if *imageSource == "registry" {
			return runScanImage(path, *platform, *format, *output, *report, *strict, false)
		}
		return runScanImage(path, *platform, *format, *output, *report, *strict, true)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if *imageSource != "registry" || *network == "allow" && !*resolve {
		fmt.Fprintln(os.Stderr, "ravel: --image-source requires an image reference; --network allow requires --resolve")
		return 2
	}
	project := filepath.Base(path)
	if !info.IsDir() {
		project = filepath.Base(filepath.Dir(path))
		if filepath.Base(path) == "project.assets.json" && project == "obj" {
			project = filepath.Base(filepath.Dir(filepath.Dir(path)))
		}
		if filepath.Base(path) == "modules.txt" && project == "vendor" {
			project = filepath.Base(filepath.Dir(filepath.Dir(path)))
		}
		if filepath.Base(path) == "status" && project == "dpkg" {
			project = filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(path)))))
		}
		if (filepath.Base(path) == "installed" || filepath.Base(path) == "installed.adb") && project == "db" {
			project = filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(path)))))
		}
	}
	runtimeDeclarations := runtimeversion.Result{}
	if info.IsDir() {
		runtimeDeclarations = runtimeversion.CollectDirectory(path)
	}
	lock, selected, err := selectLock(path, info.IsDir(), *manager)
	if err != nil {
		if info.IsDir() && *manager == "auto" && err.Error() == "no supported lockfile found" && len(runtimeDeclarations.Requirements) > 0 {
			return runScanAll(path, *format, *output, *report, *strict, false, false, false, false)
		}
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 2
	}
	if *resolve && selected != "go" && selected != "maven" && selected != "gradle" && selected != "cargo" && selected != "swiftpm" {
		fmt.Fprintln(os.Stderr, "ravel: --resolve currently supports Go modules, Maven, Gradle, Cargo, and SwiftPM")
		return 2
	}
	if *configuration != "runtimeClasspath" && (!*resolve || selected != "gradle") {
		fmt.Fprintln(os.Stderr, "ravel: --configuration requires Gradle --resolve")
		return 2
	}
	if *platform != "" && selected != "oci" {
		fmt.Fprintln(os.Stderr, "ravel: --platform requires an OCI image layout")
		return 2
	}
	selectedInputLock := lock
	if selected == "go" && *resolve && filepath.Base(lock) == "modules.txt" {
		candidate := filepath.Join(filepath.Dir(filepath.Dir(lock)), "go.mod")
		if _, err := os.Stat(candidate); err != nil {
			fmt.Fprintln(os.Stderr, "ravel: Go resolver requires go.mod")
			return 2
		}
		lock = candidate
	}
	if selected == "maven" && *resolve && filepath.Base(lock) == "dependency-tree.json" {
		candidate := filepath.Join(filepath.Dir(lock), "pom.xml")
		if _, err := os.Stat(candidate); err != nil {
			fmt.Fprintln(os.Stderr, "ravel: Maven resolver requires pom.xml")
			return 2
		}
		lock = candidate
	}
	if selected == "gradle" && *resolve && (filepath.Base(lock) == "gradle.lockfile" || filepath.Base(lock) == "buildscript-gradle.lockfile") {
		for _, name := range []string{"build.gradle", "build.gradle.kts"} {
			candidate := filepath.Join(filepath.Dir(lock), name)
			if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
				lock = candidate
				break
			}
		}
		if lock == selectedInputLock {
			fmt.Fprintln(os.Stderr, "ravel: Gradle resolver requires build.gradle or build.gradle.kts")
			return 2
		}
	}
	if selected == "cargo" && *resolve && filepath.Base(lock) == "Cargo.lock" {
		candidate := filepath.Join(filepath.Dir(lock), "Cargo.toml")
		if _, err := os.Stat(candidate); err != nil {
			fmt.Fprintln(os.Stderr, "ravel: Cargo resolver requires Cargo.toml")
			return 2
		}
		lock = candidate
	}
	if selected == "swiftpm" && *resolve && filepath.Base(lock) == "Package.resolved" {
		candidate := filepath.Join(filepath.Dir(lock), "Package.swift")
		if _, err := os.Stat(candidate); err != nil {
			fmt.Fprintln(os.Stderr, "ravel: SwiftPM resolver requires Package.swift")
			return 2
		}
		lock = candidate
	}
	protected := []string{lock, selectedInputLock}
	if selected == "go" && filepath.Base(lock) == "modules.txt" {
		protected = append(protected, filepath.Join(filepath.Dir(filepath.Dir(lock)), "go.mod"))
	}
	if selected == "maven" {
		protected = append(protected, filepath.Join(filepath.Dir(lock), "pom.xml"), filepath.Join(filepath.Dir(lock), "dependency-tree.json"))
	}
	if selected == "gradle" {
		base := filepath.Dir(lock)
		protected = append(protected, filepath.Join(base, "build.gradle"), filepath.Join(base, "build.gradle.kts"), filepath.Join(base, "gradle.lockfile"), filepath.Join(base, "buildscript-gradle.lockfile"))
	}
	if selected == "cargo" {
		base := filepath.Dir(lock)
		protected = append(protected, filepath.Join(base, "Cargo.toml"), filepath.Join(base, "Cargo.lock"))
	}
	if selected == "swiftpm" {
		protected = append(protected, filepath.Join(filepath.Dir(lock), "Package.swift"), filepath.Join(filepath.Dir(lock), "Package.resolved"))
	}
	unsafeOutput := *report == "-" || (*report != "" && samePath(*report, *output))
	for _, input := range protected {
		unsafeOutput = unsafeOutput || samePath(*output, input) || (*report != "" && samePath(*report, input))
	}
	if unsafeOutput {
		fmt.Fprintln(os.Stderr, "ravel: output and report must be distinct files and cannot overwrite the lockfile")
		return 2
	}
	var doc model.Document
	switch {
	case *resolve && selected == "go":
		doc, err = gomod.CollectResolved(lock, project, *network == "allow")
	case *resolve && selected == "maven":
		doc, err = maven.CollectResolved(lock, project, *network == "allow")
	case *resolve && selected == "gradle":
		doc, err = gradle.CollectResolved(lock, project, *configuration, *network == "allow")
	case *resolve && selected == "cargo":
		doc, err = cargo.CollectResolved(lock, project, *network == "allow")
	case *resolve && selected == "swiftpm":
		doc, err = swiftpm.CollectResolved(lock, project, *network == "allow")
	case selected == "go" && filepath.Base(lock) == "go.mod":
		doc, err = gomod.CollectManifest(lock, project)
	case selected == "gradle" && (filepath.Base(lock) == "build.gradle" || filepath.Base(lock) == "build.gradle.kts"):
		fmt.Fprintln(os.Stderr, "ravel: Gradle projects without lockfile require --resolve --allow-exec")
		return 2
	case selected == "cargo" && filepath.Base(lock) == "Cargo.toml":
		fmt.Fprintln(os.Stderr, "ravel: Cargo projects without Cargo.lock require --resolve --allow-exec")
		return 2
	case selected == "swiftpm" && filepath.Base(lock) == "Package.swift":
		fmt.Fprintln(os.Stderr, "ravel: Swift packages without Package.resolved require --resolve --allow-exec")
		return 2
	case selected == "java-archive":
		doc, err = javaarchive.Collect(lock, project)
	case selected == "deb-archive":
		doc, err = dpkg.CollectArchive(lock, project)
	case selected == "rpm-archive":
		doc, err = rpm.CollectArchive(lock, project)
	case selected == "ruby-gem":
		doc, err = bundler.CollectArchive(lock, project)
	case selected == "python-wheel":
		doc, err = python.CollectWheel(lock, project)
	case selected == "npm-archive":
		doc, err = npm.CollectArchive(lock, project)
	case selected == "oci":
		if info.IsDir() {
			doc, err = oci.Collect(filepath.Dir(lock), project, *platform)
		} else {
			doc, err = oci.CollectArchive(lock, project, *platform)
		}
	default:
		doc, err = collectStatic(selected, lock, project)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if repositoryManager(selected) {
		if !info.IsDir() {
			runtimeDeclarations = runtimeversion.CollectDirectory(filepath.Dir(path))
		}
		if err := attachRuntimeRequirements(&doc, runtimeDeclarations, *output, *report); err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 2
		}
	}
	for _, source := range doc.Sources {
		if samePath(*output, source) || *report != "" && samePath(*report, source) {
			fmt.Fprintln(os.Stderr, "ravel: output and report cannot overwrite an included input")
			return 2
		}
	}
	if repositoryManager(selected) {
		attachLocalGit(&doc, path)
	}
	return writeScanResult(doc, *format, *output, *report, *strict)
}

func writeScanResult(doc model.Document, format, output, reportPath string, strict bool) int {
	var data []byte
	var err error
	switch format {
	case "cyclonedx-json":
		data, err = export.CycloneDX(doc)
	case "spdx-json":
		data, err = export.SPDX23(doc)
	case "ravel-json":
		data, err = json.MarshalIndent(doc, "", "  ")
	default:
		fmt.Fprintln(os.Stderr, "ravel: unsupported format")
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if err := write(output, append(data, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if reportPath != "" {
		coverage, err := coverageReport(doc, format)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		if err := write(reportPath, append(coverage, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
	}
	fmt.Fprintf(os.Stderr, "ravel: %d packages, %d edges, %d runtime requirements, graph=%s, origin=%s\n", doc.Coverage.Packages, doc.Coverage.Edges, len(doc.Runtimes), doc.Coverage.GraphState, doc.Coverage.OriginState)
	if strict && len(doc.Coverage.Issues) > 0 {
		return 3
	}
	return 0
}

func write(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if path == "" {
		return errors.New("empty output path")
	}
	return os.WriteFile(path, data, 0o644)
}

func samePath(a, b string) bool {
	if a == "-" || b == "-" {
		return false
	}
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	if filepath.Clean(aa) == filepath.Clean(bb) {
		return true
	}
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}

func selectLock(input string, directory bool, requested string) (string, string, error) {
	managerForFile := func(name string) string {
		if isBundlerLockName(name) {
			return "bundler"
		}
		if strings.HasSuffix(name, ".gemspec") {
			return "gemspec"
		}
		if isWorkflowPath(input) {
			return "github-actions"
		}
		switch name {
		case "status":
			if filepath.Base(filepath.Dir(input)) == "dpkg" && filepath.Base(filepath.Dir(filepath.Dir(input))) == "lib" && filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(input)))) == "var" {
				return "dpkg"
			}
		case "package-lock.json", "npm-shrinkwrap.json":
			return "npm"
		case "bun.lock":
			return "bun"
		case "deno.lock":
			return "deno"
		case "Package.resolved", "Package.swift":
			return "swiftpm"
		case "packages.lock.json", "project.assets.json", "packages.config":
			return "nuget"
		case "uv.lock":
			return "uv"
		case "requirements.txt":
			return "requirements"
		case "pnpm-lock.yaml":
			return "pnpm"
		case "poetry.lock":
			return "poetry"
		case "Pipfile.lock":
			return "pipenv"
		case "pdm.lock":
			return "pdm"
		case "modules.txt":
			return "go"
		case "go.mod":
			return "go"
		case "pubspec.lock":
			return "pub"
		case "gradle.lockfile", "buildscript-gradle.lockfile", "build.gradle", "build.gradle.kts":
			return "gradle"
		case "dependency-tree.json", "pom.xml":
			return "maven"
		case "yarn.lock":
			return "yarn"
		case "Cargo.lock", "Cargo.toml":
			return "cargo"
		case "composer.lock":
			return "composer"
		case "conan.lock":
			return "conan"
		case "mix.lock":
			return "mix"
		case "rebar.lock":
			return "rebar"
		case "shard.lock":
			return "shards"
		case "cabal.project.freeze":
			return "cabal"
		case "Manifest.toml", "JuliaManifest.toml":
			return "julia"
		case "renv.lock":
			return "renv"
		case "conda-lock.yml", "conda-lock.yaml":
			return "conda-lock"
		case "pixi.lock":
			return "pixi"
		case "Podfile.lock":
			return "cocoapods"
		}
		if isPylockName(name) {
			return "pylock"
		}
		if isJuliaManifestName(name) {
			return "julia"
		}
		if isCondaLockName(name) {
			return "conda-lock"
		}
		if strings.HasSuffix(name, ".project.freeze") {
			return "cabal"
		}
		if strings.HasSuffix(name, ".yaml.lock") {
			return "stack"
		}
		if strings.HasSuffix(name, ".sbt.lock") {
			return "sbt"
		}
		if isRequirementsName(name) {
			return "requirements"
		}
		if strings.HasSuffix(strings.ToLower(name), ".oci.tar") || strings.HasSuffix(strings.ToLower(name), ".docker.tar") || strings.HasSuffix(strings.ToLower(name), ".oci.tar.gz") || strings.HasSuffix(strings.ToLower(name), ".docker.tar.gz") {
			return "oci"
		}
		if strings.HasSuffix(strings.ToLower(name), ".jar") || strings.HasSuffix(strings.ToLower(name), ".war") {
			return "java-archive"
		}
		if strings.HasSuffix(strings.ToLower(name), ".deb") || strings.HasSuffix(strings.ToLower(name), ".udeb") || strings.HasSuffix(strings.ToLower(name), ".ddeb") {
			return "deb-archive"
		}
		if strings.HasSuffix(strings.ToLower(name), ".rpm") {
			return "rpm-archive"
		}
		if strings.HasSuffix(strings.ToLower(name), ".nupkg") {
			return "nuget-archive"
		}
		if strings.HasSuffix(strings.ToLower(name), ".whl") {
			return "python-wheel"
		}
		if strings.HasSuffix(strings.ToLower(name), ".tgz") {
			return "npm-archive"
		}
		if strings.HasSuffix(strings.ToLower(name), ".gem") {
			return "ruby-gem"
		}
		return ""
	}
	if !directory {
		if requested == "oci" && (strings.HasSuffix(strings.ToLower(input), ".tar") || strings.HasSuffix(strings.ToLower(input), ".tar.gz")) {
			return input, "oci", nil
		}
		if requested == "rpm" || requested == "auto" && filepath.Base(filepath.Dir(input)) == "rpm" {
			for _, name := range []string{"rpmdb.sqlite", "Packages.db", "Packages"} {
				if filepath.Base(input) == name {
					return input, "rpm", nil
				}
			}
		}
		if (filepath.Base(input) == "installed" || filepath.Base(input) == "installed.adb") && filepath.Base(filepath.Dir(input)) == "db" && filepath.Base(filepath.Dir(filepath.Dir(input))) == "apk" && filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(input)))) == "lib" {
			if requested == "auto" || requested == "apk" {
				return input, "apk", nil
			}
		}
		selected := managerForFile(filepath.Base(input))
		if selected == "" || requested != "auto" && requested != selected {
			return "", "", errors.New("unsupported lockfile or manager mismatch")
		}
		return input, selected, nil
	}
	candidates := map[string]string{}
	for name, manager := range map[string]string{
		"Gemfile.lock": "bundler", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
		"bun.lock": "bun", "deno.lock": "deno", "Package.resolved": "swiftpm", "packages.lock.json": "nuget",
		"uv.lock": "uv", "pylock.toml": "pylock", "requirements.txt": "requirements",
		"pnpm-lock.yaml":       "pnpm",
		"poetry.lock":          "poetry",
		"Pipfile.lock":         "pipenv",
		"pdm.lock":             "pdm",
		"go.mod":               "go",
		"pubspec.lock":         "pub",
		"gradle.lockfile":      "gradle",
		"dependency-tree.json": "maven",
		"yarn.lock":            "yarn",
		"Cargo.lock":           "cargo",
		"composer.lock":        "composer",
		"conan.lock":           "conan",
		"mix.lock":             "mix",
		"rebar.lock":           "rebar",
		"shard.lock":           "shards",
		"cabal.project.freeze": "cabal",
		"stack.yaml.lock":      "stack",
		"renv.lock":            "renv",
		"pixi.lock":            "pixi",
		"Podfile.lock":         "cocoapods",
	} {
		candidate := filepath.Join(input, name)
		if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
			if manager == "npm" && name == "package-lock.json" {
				if _, err := os.Stat(filepath.Join(input, "npm-shrinkwrap.json")); err == nil {
					continue
				}
			}
			candidates[manager] = candidate
		}
	}
	if requested == "auto" || requested == "bundler" {
		locks, err := bundlerLockFiles(input)
		if err != nil {
			return "", "", err
		}
		if candidates["bundler"] == "" {
			switch len(locks) {
			case 0:
			case 1:
				candidates["bundler"] = locks[0]
			default:
				return "", "", errors.New("multiple Bundler lockfiles found; scan a specific file or use --all")
			}
		}
	}
	if candidates["nuget"] == "" {
		for _, name := range []string{"project.assets.json", filepath.Join("obj", "project.assets.json")} {
			candidate := filepath.Join(input, name)
			if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
				candidates["nuget"] = candidate
				break
			}
		}
	}
	if candidates["nuget"] == "" {
		candidate := filepath.Join(input, "packages.config")
		if stat, err := os.Stat(candidate); err == nil && stat.Mode().IsRegular() {
			candidates["nuget"] = candidate
		}
	}
	if candidates["gradle"] == "" {
		candidate := filepath.Join(input, "buildscript-gradle.lockfile")
		if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
			candidates["gradle"] = candidate
		}
	}
	if candidates["gradle"] == "" {
		for _, name := range []string{"build.gradle", "build.gradle.kts"} {
			candidate := filepath.Join(input, name)
			if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
				candidates["gradle"] = candidate
				break
			}
		}
	}
	if candidates["maven"] == "" {
		candidate := filepath.Join(input, "pom.xml")
		if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
			candidates["maven"] = candidate
		}
	}
	if candidates["cargo"] == "" {
		candidate := filepath.Join(input, "Cargo.toml")
		if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
			candidates["cargo"] = candidate
		}
	}
	if candidates["swiftpm"] == "" {
		candidate := filepath.Join(input, "Package.swift")
		if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
			candidates["swiftpm"] = candidate
		}
	}
	vendorManifest := filepath.Join(input, "vendor", "modules.txt")
	if stat, err := os.Stat(vendorManifest); err == nil && !stat.IsDir() {
		candidates["go"] = vendorManifest
	}
	ociLayout := filepath.Join(input, "oci-layout")
	if stat, err := os.Stat(ociLayout); err == nil && stat.Mode().IsRegular() {
		if index, err := os.Stat(filepath.Join(input, "index.json")); err == nil && index.Mode().IsRegular() {
			candidates["oci"] = ociLayout
		}
	}
	dpkgStatus := filepath.Join(input, "var", "lib", "dpkg", "status")
	if stat, err := os.Stat(dpkgStatus); err == nil && stat.Mode().IsRegular() {
		candidates["dpkg"] = dpkgStatus
	}
	for _, name := range []string{"installed", "installed.adb"} {
		apkInstalled := filepath.Join(input, "lib", "apk", "db", name)
		if stat, err := os.Stat(apkInstalled); err == nil && stat.Mode().IsRegular() {
			if candidates["apk"] != "" {
				return "", "", errors.New("multiple APK installed databases; active database is ambiguous")
			}
			candidates["apk"] = apkInstalled
		}
	}
	var rpmFiles []string
	var rpmInfos []os.FileInfo
	for _, name := range rpm.DatabasePaths {
		candidate := filepath.Join(input, filepath.FromSlash(name))
		if stat, err := os.Stat(candidate); err == nil && stat.Mode().IsRegular() {
			alias := false
			for _, previous := range rpmInfos {
				if os.SameFile(stat, previous) {
					alias = true
					break
				}
			}
			if !alias {
				rpmFiles = append(rpmFiles, candidate)
				rpmInfos = append(rpmInfos, stat)
			}
		}
	}
	if len(rpmFiles) > 1 && (requested == "auto" || requested == "rpm") {
		return "", "", errors.New("multiple RPM databases found; select a specific database file")
	}
	if len(rpmFiles) > 0 {
		candidates["rpm"] = rpmFiles[0]
	}
	if requested == "auto" || requested == "pylock" {
		entries, err := os.ReadDir(input)
		if err != nil {
			return "", "", err
		}
		var pylocks []string
		for _, entry := range entries {
			if !entry.IsDir() && isPylockName(entry.Name()) {
				pylocks = append(pylocks, entry.Name())
			}
		}
		if len(pylocks) > 1 {
			return "", "", errors.New("multiple pylock files found; scan a specific file")
		}
		if len(pylocks) == 1 {
			candidates["pylock"] = filepath.Join(input, pylocks[0])
		}
	}
	if requested == "auto" || requested == "cabal" {
		entries, err := os.ReadDir(input)
		if err != nil {
			return "", "", err
		}
		var freezes []string
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".project.freeze") {
				freezes = append(freezes, entry.Name())
			}
		}
		if len(freezes) > 1 {
			return "", "", errors.New("multiple Cabal freeze files found; scan a specific file")
		}
		if len(freezes) == 1 {
			candidates["cabal"] = filepath.Join(input, freezes[0])
		}
	}
	if requested == "auto" || requested == "stack" {
		entries, err := os.ReadDir(input)
		if err != nil {
			return "", "", err
		}
		var locks []string
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml.lock") {
				locks = append(locks, entry.Name())
			}
		}
		if len(locks) > 1 {
			return "", "", errors.New("multiple Stack lockfiles found; scan a specific file")
		}
		if len(locks) == 1 {
			candidates["stack"] = filepath.Join(input, locks[0])
		}
	}
	if requested == "auto" || requested == "sbt" {
		entries, err := os.ReadDir(input)
		if err != nil {
			return "", "", err
		}
		var locks []string
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sbt.lock") {
				locks = append(locks, entry.Name())
			}
		}
		if len(locks) > 1 {
			return "", "", errors.New("multiple sbt lockfiles found; scan a specific file")
		}
		if len(locks) == 1 {
			candidates["sbt"] = filepath.Join(input, locks[0])
		}
	}
	if requested == "auto" || requested == "julia" {
		var manifests []string
		entries, err := os.ReadDir(input)
		if err != nil {
			return "", "", err
		}
		for _, entry := range entries {
			if !entry.IsDir() && isJuliaManifestName(entry.Name()) {
				manifests = append(manifests, filepath.Join(input, entry.Name()))
			}
		}
		if len(manifests) > 1 {
			return "", "", errors.New("multiple Julia manifests found; scan a specific file")
		}
		if len(manifests) == 1 {
			candidates["julia"] = manifests[0]
		}
	}
	if requested == "auto" || requested == "conda-lock" {
		entries, err := os.ReadDir(input)
		if err != nil {
			return "", "", err
		}
		var locks []string
		for _, entry := range entries {
			if !entry.IsDir() && isCondaLockName(entry.Name()) {
				locks = append(locks, entry.Name())
			}
		}
		if len(locks) > 1 {
			return "", "", errors.New("multiple conda-lock files found; scan a specific file")
		}
		if len(locks) == 1 {
			candidates["conda-lock"] = filepath.Join(input, locks[0])
		}
	}
	if requested == "gemspec" || requested == "auto" && len(candidates) == 0 {
		files, err := gemspecFiles(input)
		if err != nil {
			return "", "", err
		}
		if len(files) > 1 {
			return "", "", errors.New("multiple gemspecs found; scan a specific file or use --all")
		}
		if len(files) == 1 {
			candidates["gemspec"] = files[0]
		}
	}
	if requested == "github-actions" || requested == "auto" && len(candidates) == 0 {
		files, err := workflowFiles(input)
		if err != nil {
			return "", "", err
		}
		if len(files) > 1 {
			return "", "", errors.New("multiple GitHub workflows found; scan a specific file or use --all")
		}
		if len(files) == 1 {
			candidates["github-actions"] = files[0]
		}
	}
	if requested != "auto" {
		if lock := candidates[requested]; lock != "" {
			return lock, requested, nil
		}
		return "", "", fmt.Errorf("no %s lockfile found", requested)
	}
	if len(candidates) == 1 {
		for manager, lock := range candidates {
			return lock, manager, nil
		}
	}
	if len(candidates) == 0 {
		if _, err := os.Stat(filepath.Join(input, "bun.lockb")); err == nil {
			return "", "", errors.New("legacy bun.lockb is not supported; create a text bun.lock with Bun before scanning")
		}
		return "", "", errors.New("no supported lockfile found")
	}
	if data, err := os.ReadFile(filepath.Join(input, "package.json")); err == nil {
		var metadata struct {
			PackageManager string `json:"packageManager"`
		}
		if json.Unmarshal(data, &metadata) == nil {
			for _, manager := range []string{"bun", "npm", "pnpm", "yarn"} {
				if strings.HasPrefix(metadata.PackageManager, manager+"@") && candidates[manager] != "" {
					return candidates[manager], manager, nil
				}
			}
		}
	}
	if candidates["deno"] != "" {
		for _, name := range []string{"deno.json", "deno.jsonc"} {
			if _, err := os.Stat(filepath.Join(input, name)); err == nil {
				return candidates["deno"], "deno", nil
			}
		}
	}
	return "", "", errors.New("multiple lockfile managers found; specify --manager")
}

var juliaManifestPattern = regexp.MustCompile(`^(?:Julia)?Manifest-v[0-9]+\.[0-9]+\.toml$`)

func isJuliaManifestName(name string) bool {
	return name == "Manifest.toml" || name == "JuliaManifest.toml" || juliaManifestPattern.MatchString(name)
}

func isCondaLockName(name string) bool {
	return name == "conda-lock.yml" || name == "conda-lock.yaml" || strings.HasSuffix(name, ".conda-lock.yml") || strings.HasSuffix(name, ".conda-lock.yaml")
}

func isPylockName(name string) bool {
	return name == "pylock.toml" || strings.HasPrefix(name, "pylock.") && strings.HasSuffix(name, ".toml")
}

func isRequirementsName(name string) bool {
	return strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
}
