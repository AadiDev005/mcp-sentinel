// Package report formats scanner findings for human or machine consumption.
//
// Status: stub. Output formats: text (default), json, sarif (CI).
package report

import "github.com/AadiDev005/mcp-sentinel/internal/scanner"

// Format is the report output format.
type Format string

const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// Write renders findings in the requested format.
func Write(findings []scanner.Finding, format Format) ([]byte, error) {
	return nil, nil
}
