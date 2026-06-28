// modelvet — static security scanner for ML model artifacts.
// This is the ONLY package that may call os.Exit.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/report"
	"github.com/t3bik/modelvet/internal/scan"
)

// Build-time variables injected by goreleaser.
// defaultVersion is the version shown when the binary is built without ldflags.
const defaultVersion = "0.2.0"

var (
	version = defaultVersion
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printUsage(os.Stdout)
		return 0
	}

	switch args[0] {
	case "scan":
		return cmdScan(args[1:])
	case "version":
		fmt.Printf("modelvet %s (commit %s, built %s)\n", version, commit, date)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "modelvet: unknown command %q\n\n", args[0])
		printUsage(os.Stderr)
		return 2
	}
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("modelvet scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		format      = fs.String("format", "human", "output format: human|json|sarif")
		minSeverity = fs.String("min-severity", "info", "minimum severity to report: info|low|medium|high|critical")
		recurse     = fs.Bool("recurse", true, "recurse into directories")
		quiet       = fs.Bool("quiet", false, "suppress informational output")
	)

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: modelvet scan [flags] <path-or-dir> [paths...]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Scan ML model artifacts (GGUF, safetensors, pickle/PyTorch) for security issues.")
		fmt.Fprintln(os.Stderr, "Files are inspected statically; the model is NEVER loaded or executed.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Flags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Exit codes:")
		fmt.Fprintln(os.Stderr, "  0  no finding at or above High severity (among reported findings)")
		fmt.Fprintln(os.Stderr, "  1  at least one High or Critical finding reported")
		fmt.Fprintln(os.Stderr, "  2  usage or I/O error")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  modelvet scan model.gguf")
		fmt.Fprintln(os.Stderr, "  modelvet scan --format sarif --min-severity high ./models/")
		fmt.Fprintln(os.Stderr, "  modelvet scan --format json model.pt | jq '.findings[].rule_id'")
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "modelvet scan: requires at least one path argument")
		fs.Usage()
		return 2
	}

	// Parse min-severity.
	minSev, err := finding.ParseSeverity(*minSeverity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "modelvet: --min-severity: %v\n", err)
		return 2
	}

	// Parse format. For human output, --quiet suppresses per-file "OK" lines
	// but NEVER suppresses actual findings or the summary.
	// For JSON/SARIF, --quiet is a no-op.
	outFormat := report.Format(*format)
	w, err := report.NewWriterQuiet(outFormat, os.Stdout, *quiet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "modelvet: --format: %v\n", err)
		return 2
	}

	// Signal-aware context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := scan.Options{
		MinSeverity: minSev,
		Recurse:     *recurse,
	}

	eng := scan.NewEngine()
	var merged scan.Result

	for _, path := range paths {
		r, walkErr := eng.Walk(ctx, path, opts)
		if walkErr != nil {
			fmt.Fprintf(os.Stderr, "modelvet: %v\n", walkErr)
			return 2
		}
		merged.Findings = append(merged.Findings, r.Findings...)
		merged.Errors = append(merged.Errors, r.Errors...)
		merged.Scanned += r.Scanned
		merged.Skipped += r.Skipped
	}

	if err := w.Write(merged); err != nil {
		fmt.Fprintf(os.Stderr, "modelvet: write report: %v\n", err)
		return 2
	}

	return report.ExitCode(merged)
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "modelvet %s — static security scanner for ML model artifacts\n\n", version)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  modelvet scan [flags] <path-or-dir> [more paths...]")
	fmt.Fprintln(w, "  modelvet version")
	fmt.Fprintln(w, "  modelvet --help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'modelvet scan --help' for scan flags and exit-code semantics.")
}
