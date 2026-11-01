package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Pirikara/Ravel/internal/enrich"
	"github.com/Pirikara/Ravel/internal/export"
)

func runEnrich(args []string) int {
	input := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		input, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("enrich", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	network := fs.String("network", "deny", "allow registry metadata requests")
	ecosystem := fs.String("ecosystem", "rubygems", "rubygems, npm, or pypi")
	registry := fs.String("registry", "", "registry API origin")
	maxRequests := fs.Int("max-requests", 1000, "maximum registry metadata requests")
	format := fs.String("format", "ravel-json", "output format")
	output := fs.String("output", "-", "output file or -")
	reportPath := fs.String("report", "", "coverage report path")
	strict := fs.Bool("strict", false, "fail on coverage issues")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if input == "" && fs.NArg() == 1 {
		input = fs.Arg(0)
	} else if fs.NArg() != 0 {
		usage()
		return 2
	}
	if input == "" || *network != "allow" || *ecosystem != "rubygems" && *ecosystem != "npm" && *ecosystem != "pypi" || *reportPath == "-" || *reportPath != "" && samePath(*reportPath, *output) || *format != "ravel-json" && *format != "cyclonedx-json" && *format != "spdx-json" || *maxRequests < 1 || *maxRequests > 10000 {
		usage()
		return 2
	}
	if *registry == "" {
		if *ecosystem == "npm" {
			*registry = "https://registry.npmjs.org"
		} else if *ecosystem == "pypi" {
			*registry = "https://pypi.org"
		} else {
			*registry = "https://rubygems.org"
		}
	}
	doc, err := readRavelDocument(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	protected := append([]string{input, doc.Source}, doc.Sources...)
	for _, source := range protected {
		if source != "" && (samePath(*output, source) || *reportPath != "" && samePath(*reportPath, source)) {
			fmt.Fprintln(os.Stderr, "ravel: enrich output cannot overwrite an input or scanned source")
			return 2
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	options := enrich.Options{RegistryURL: *registry, MaxRequests: *maxRequests}
	if *ecosystem == "npm" {
		doc, err = enrich.NPM(ctx, doc, options)
	} else if *ecosystem == "pypi" {
		doc, err = enrich.PyPI(ctx, doc, options)
	} else {
		doc, err = enrich.RubyGems(ctx, doc, options)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 2
	}
	var data []byte
	switch *format {
	case "ravel-json":
		data, err = json.MarshalIndent(doc, "", "  ")
	case "cyclonedx-json":
		data, err = export.CycloneDX(doc)
	case "spdx-json":
		data, err = export.SPDX23(doc)
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
	fmt.Fprintf(os.Stderr, "ravel: %d packages, %d development sources after enrichment\n", len(doc.Components), len(doc.Development))
	if *strict && len(doc.Coverage.Issues) > 0 {
		return 3
	}
	return 0
}
