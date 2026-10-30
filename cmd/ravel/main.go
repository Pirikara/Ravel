package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ravel/internal/collectors/bundler"
	"ravel/internal/collectors/cargo"
	"ravel/internal/collectors/gomod"
	"ravel/internal/collectors/gradle"
	"ravel/internal/collectors/javaarchive"
	"ravel/internal/collectors/maven"
	"ravel/internal/collectors/npm"
	"ravel/internal/collectors/python"
	"ravel/internal/collectors/swiftpm"
	"ravel/internal/export"
	"ravel/internal/merge"
	"ravel/internal/model"
	"ravel/internal/report"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	code := 2
	switch os.Args[1] {
	case "scan":
		code = runScan(os.Args[2:])
	case "explain":
		code = runExplain(os.Args[2:])
	case "diff":
		code = runDiff(os.Args[2:])
	case "merge":
		code = runMerge(os.Args[2:])
	case "enrich":
		code = runEnrich(os.Args[2:])
	default:
		usage()
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ravel scan PATH [--manager NAME|--all [--recursive]] [--format cyclonedx-json|spdx-json|ravel-json] [--output FILE] [--report FILE] [--strict] [--resolve --allow-exec --network deny|allow] [--configuration NAME]")
	fmt.Fprintln(os.Stderr, "       ravel explain PACKAGE --input ravel.json [--format text|json]")
	fmt.Fprintln(os.Stderr, "       ravel diff BEFORE.ravel.json AFTER.ravel.json [--format text|json]")
	fmt.Fprintln(os.Stderr, "       ravel merge [--name PROJECT] [--format cyclonedx-json|spdx-json|ravel-json] [--output FILE] [--report FILE] [--strict] INPUT.ravel.json...")
	fmt.Fprintln(os.Stderr, "       ravel enrich INPUT.ravel.json --network allow [--ecosystem rubygems|npm|pypi] [--registry HTTPS_URL] [--max-requests N] [--format ravel-json|cyclonedx-json|spdx-json] [--output FILE] [--report FILE] [--strict]")
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
	strict := fs.Bool("strict", false, "fail on partial coverage")
	resolve := fs.Bool("resolve", false, "resolve dependencies with a package manager command")
	allowExec := fs.Bool("allow-exec", false, "allow a package manager command")
	network := fs.String("network", "deny", "deny or allow")
	configuration := fs.String("configuration", "runtimeClasspath", "Gradle configuration to resolve")
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
	if *network != "deny" && *network != "allow" || *resolve && !*allowExec || *network == "allow" && !*resolve {
		fmt.Fprintln(os.Stderr, "ravel: --resolve requires --allow-exec; --network must be deny or allow")
		return 2
	}
	if *manager != "auto" && *manager != "bundler" && *manager != "ruby-gem" && *manager != "npm" && *manager != "bun" && *manager != "deno" && *manager != "swiftpm" && *manager != "nuget" && *manager != "nuget-archive" && *manager != "npm-archive" && *manager != "uv" && *manager != "pylock" && *manager != "requirements" && *manager != "pnpm" && *manager != "poetry" && *manager != "yarn" && *manager != "cargo" && *manager != "composer" && *manager != "cocoapods" && *manager != "pipenv" && *manager != "pdm" && *manager != "go" && *manager != "pub" && *manager != "gradle" && *manager != "maven" && *manager != "java-archive" && *manager != "python-wheel" {
		fmt.Fprintln(os.Stderr, "ravel: supported managers: bundler, ruby-gem, npm, bun, deno, swiftpm, nuget, nuget-archive, npm-archive, uv, pylock, requirements, pnpm, poetry, yarn, cargo, composer, cocoapods, pipenv, pdm, go, pub, gradle, maven, java-archive, python-wheel")
		return 2
	}
	if *all {
		if *manager != "auto" || *resolve || *allowExec || *configuration != "runtimeClasspath" {
			fmt.Fprintln(os.Stderr, "ravel: --all is static and cannot be combined with --manager, --resolve, --allow-exec, or --configuration")
			return 2
		}
		return runScanAll(path, *format, *output, *report, *strict, *recursive)
	}
	if *recursive {
		fmt.Fprintln(os.Stderr, "ravel: --recursive requires --all")
		return 2
	}
	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
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
	}
	lock, selected, err := selectLock(path, info.IsDir(), *manager)
	if err != nil {
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
	case selected == "go" && filepath.Base(lock) != "modules.txt":
		fmt.Fprintln(os.Stderr, "ravel: Go modules without vendor/modules.txt require --resolve --allow-exec")
		return 2
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
	case selected == "ruby-gem":
		doc, err = bundler.CollectArchive(lock, project)
	case selected == "python-wheel":
		doc, err = python.CollectWheel(lock, project)
	case selected == "npm-archive":
		doc, err = npm.CollectArchive(lock, project)
	default:
		doc, err = collectStatic(selected, lock, project)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	for _, source := range doc.Sources {
		if samePath(*output, source) || *report != "" && samePath(*report, source) {
			fmt.Fprintln(os.Stderr, "ravel: output and report cannot overwrite an included input")
			return 2
		}
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
	if *report != "" {
		coverage, err := coverageReport(doc, *format)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		if err := write(*report, append(coverage, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
	}
	fmt.Fprintf(os.Stderr, "ravel: %d packages, %d edges, graph=%s, origin=%s\n", doc.Coverage.Packages, doc.Coverage.Edges, doc.Coverage.GraphState, doc.Coverage.OriginState)
	if *strict && len(doc.Coverage.Issues) > 0 {
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
		switch name {
		case "Gemfile.lock":
			return "bundler"
		case "package-lock.json", "npm-shrinkwrap.json":
			return "npm"
		case "bun.lock":
			return "bun"
		case "deno.lock":
			return "deno"
		case "Package.resolved", "Package.swift":
			return "swiftpm"
		case "packages.lock.json", "project.assets.json":
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
		case "Podfile.lock":
			return "cocoapods"
		}
		if isPylockName(name) {
			return "pylock"
		}
		if isRequirementsName(name) {
			return "requirements"
		}
		if strings.HasSuffix(strings.ToLower(name), ".jar") || strings.HasSuffix(strings.ToLower(name), ".war") {
			return "java-archive"
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
	if candidates["nuget"] == "" {
		for _, name := range []string{"project.assets.json", filepath.Join("obj", "project.assets.json")} {
			candidate := filepath.Join(input, name)
			if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
				candidates["nuget"] = candidate
				break
			}
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

func isPylockName(name string) bool {
	return name == "pylock.toml" || strings.HasPrefix(name, "pylock.") && strings.HasSuffix(name, ".toml")
}

func isRequirementsName(name string) bool {
	return strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
}
