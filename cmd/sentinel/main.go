// Package main is the mcp-sentinel CLI entry point.
//
// Status: scaffold. The scanner is not implemented yet — this binary
// exists so the repo layout, build, and CI can be exercised end-to-end
// before any detection logic lands.
package main

import (
	"fmt"
	"os"
)

const version = "0.0.1-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("mcp-sentinel", version)
	case "scan":
		fmt.Fprintln(os.Stderr, "scan: not implemented yet (scaffold only)")
		os.Exit(1)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `mcp-sentinel — semantic scanner for MCP tool poisoning

Usage:
  mcp-sentinel <subcommand> [flags]

Subcommands:
  scan      Scan MCP tool definitions for poisoning patterns (not implemented)
  version   Print version and exit
  help      Show this message

This is a pre-release scaffold. See README.md for project status.`)
}
