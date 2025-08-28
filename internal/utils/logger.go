package utils

import (
	"encoding/json"
	"fmt"
	"os"
)

// ----------------- Types -----------------

type Severity string

const (
	HIGH   Severity = "HIGH"
	MEDIUM Severity = "MEDIUM"
	LOW    Severity = "LOW"
)

type ScanType string

const (
	CODE   ScanType = "CODE"
	GOSEC  ScanType = "GOSEC"
	DOCKER ScanType = "DOCKER"
	SECRET ScanType = "SECRET"
)

type ScanResult struct {
	ScanType ScanType `json:"scan_type"`         // GOSEC, DOCKER, SECRET
	Target   string   `json:"target"`            // file path or Docker image
	Line     int      `json:"line,omitempty"`    // code line
	Package  string   `json:"package,omitempty"` // Docker package
	Severity Severity `json:"severity"`          // HIGH, MEDIUM, LOW
	Details  string   `json:"details"`           // issue description
}

type UnifiedReport struct {
	Results []ScanResult `json:"results"`
}

// ----------------- Logging -----------------

func Info(msg string) {
	fmt.Println("INFO: " + msg)
}

func Warn(msg string) {
	fmt.Println("WARN: " + msg)
}

func Error(msg string) {
	fmt.Println("ERROR: " + msg)
}

// ----------------- JSON Export -----------------

func ExportJSON(results []ScanResult, filename string) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		Error("Failed to generate JSON: " + err.Error())
		return
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		Error("Failed to write JSON file: " + err.Error())
		return
	}
	Info("Results saved to " + filename)
}

// PrintMarkdownTable prints a Markdown table of scan results for CI logs
func PrintMarkdownTable(results []ScanResult) {
	if len(results) == 0 {
		fmt.Println("INFO: No issues found, nothing to display in table.")
		return
	}

	fmt.Println("\n| Severity | Scan Type | Target | Line | Package | Details |")
	fmt.Println("|---------|-----------|--------|------|---------|---------|")

	for _, r := range results {
		line := ""
		if r.Line > 0 {
			line = fmt.Sprint(r.Line)
		}
		pkg := ""
		if r.Package != "" {
			pkg = r.Package
		}

		fmt.Printf("| %s | %s | %s | %s | %s | %s |\n",
			r.Severity, r.ScanType, r.Target, line, pkg, r.Details)
	}
	fmt.Println()
}
