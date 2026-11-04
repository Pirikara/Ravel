package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Pirikara/Ravel/internal/vex"
)

func runVEX(args []string) int {
	fs := flag.NewFlagSet("vex", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "Ravel JSON input")
	vexPath := fs.String("vex", "", "OpenVEX v0.2.0 JSON input")
	format := fs.String("format", "text", "text or json")
	output := fs.String("output", "-", "output file or -")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *input == "" || *vexPath == "" || *input == "-" || *vexPath == "-" || (*format != "text" && *format != "json") || samePath(*output, *input) || samePath(*output, *vexPath) {
		usage()
		return 2
	}
	doc, err := readRavelDocument(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	data, err := os.ReadFile(*vexPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	result, err := vex.Correlate(doc, data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	var out []byte
	if *format == "json" {
		out, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		out = append(out, '\n')
	} else {
		out = []byte(vexText(result))
	}
	if err := write(*output, out); err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	return 0
}

func vexText(result vex.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OpenVEX %q\nauthor: %q\nissued: %s\ninput digest: %s\n", result.DocumentID, result.Author, result.Timestamp, result.InputDigest)
	for _, s := range result.Statements {
		fmt.Fprintf(&b, "\n%q: %s (issuer's status; %s)\n", s.Vulnerability, s.Status, s.Timestamp)
		if s.Justification != "" {
			fmt.Fprintf(&b, "  justification: %q\n", s.Justification)
		}
		if s.ImpactStatement != "" {
			fmt.Fprintf(&b, "  impact: %q\n", s.ImpactStatement)
		}
		if s.ActionStatement != "" {
			fmt.Fprintf(&b, "  action: %q\n", s.ActionStatement)
		}
		for _, p := range s.Products {
			identifier := p.PURL
			if identifier == "" {
				identifier = p.ID
			}
			if p.Matched {
				fmt.Fprintf(&b, "  matched product %q -> %q\n", identifier, strings.Join(p.ComponentIDs, ", "))
			} else {
				fmt.Fprintf(&b, "  unmatched product %q (%s)\n", identifier, p.Reason)
			}
			if len(p.SubcomponentPURLs) > 0 {
				fmt.Fprintf(&b, "    subcomponents listed by issuer (not correlated): %q\n", strings.Join(p.SubcomponentPURLs, ", "))
			}
		}
	}
	return b.String()
}
