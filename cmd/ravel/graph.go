package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Pirikara/Ravel/internal/graph"
)

func runGraph(args []string) int {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "Ravel JSON input")
	format := fs.String("format", "html", "html, dot, or text")
	output := fs.String("output", "-", "output file or -")
	focus := fs.String("focus", "", "component ID, unique name, PURL, or root")
	direction := fs.String("direction", "dependencies", "dependencies or dependents")
	depth := fs.Int("depth", -1, "maximum hops from focus; -1 means unlimited")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *input == "" || *output == "" || samePath(*input, *output) || (*format != "html" && *format != "dot" && *format != "text") {
		usage()
		return 2
	}
	doc, err := readRavelDocument(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	view, err := graph.Build(doc, graph.Options{Focus: *focus, Direction: *direction, Depth: *depth})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 2
	}
	var data []byte
	switch *format {
	case "html":
		data, err = graph.HTML(view)
	case "dot":
		data = graph.DOT(view)
	case "text":
		data = graph.Text(view)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 2
	}
	if err := write(*output, data); err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	return 0
}
