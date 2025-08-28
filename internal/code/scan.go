package code

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yourusername/devsecops-scan/internal/utils"
)

var patterns = []string{"password", "secret", "apikey", "token", "private_key"}

// GosecIssue represents a single issue from gosec with flexible line parsing
type GosecIssue struct {
	Severity string      `json:"severity"`
	Details  string      `json:"details"`
	File     string      `json:"file"`
	LineRaw  interface{} `json:"line"` // Can be string or int
}

// GetLine extracts the line number as an integer
func (g *GosecIssue) GetLine() int {
	switch v := g.LineRaw.(type) {
	case string:
		if line, err := strconv.Atoi(v); err == nil {
			return line
		}
		return 0
	case float64: // JSON numbers are parsed as float64
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

// RunGosec executes the gosec tool for static code analysis
func RunGosec(path string, failOnCritical bool, minSeverity string) ([]utils.ScanResult, int) {
	utils.Info("🔍 Running gosec on: " + path)

	jsonFile := "gosec_temp.json"
	cmd := exec.Command("gosec", "-fmt=json", "-out", jsonFile, "./...")
	cmd.Dir = path

	out, err := cmd.CombinedOutput()
	if err != nil && cmd.ProcessState.ExitCode() != 1 {
		utils.Error("Failed to run gosec: " + err.Error())
		fmt.Println(string(out))
		return nil, 2
	}

	data, readErr := os.ReadFile(jsonFile)
	if readErr != nil {
		utils.Error("Failed to read gosec JSON: " + readErr.Error())
		return nil, 2
	}

	// Clean up temp file
	defer func() {
		if removeErr := os.Remove(jsonFile); removeErr != nil {
			utils.Warn("Failed to remove temp file: " + removeErr.Error())
		}
	}()

	var result struct {
		Issues []GosecIssue `json:"Issues"`
	}

	if jsonErr := json.Unmarshal(data, &result); jsonErr != nil {
		utils.Error("Failed to parse gosec JSON: " + jsonErr.Error())
		// Debug: print the problematic JSON
		utils.Error("JSON content: " + string(data))
		return nil, 2
	}

	var results []utils.ScanResult
	high, med, low := 0, 0, 0

	for _, issue := range result.Issues {
		lineNum := issue.GetLine()

		results = append(results, utils.ScanResult{
			ScanType: utils.GOSEC,
			Target:   issue.File,
			Line:     lineNum,
			Severity: utils.Severity(issue.Severity),
			Details:  issue.Details,
		})

		utils.Warn(fmt.Sprintf("[%s] %s in %s (line %d)", issue.Severity, issue.Details, issue.File, lineNum))

		switch issue.Severity {
		case "HIGH":
			high++
		case "MEDIUM":
			med++
		case "LOW":
			low++
		}
	}

	utils.Info(fmt.Sprintf("Summary → HIGH: %d, MEDIUM: %d, LOW: %d", high, med, low))

	// Fail logic based on minSeverity
	fail := false
	switch minSeverity {
	case "HIGH":
		if high > 0 {
			fail = true
		}
	case "MEDIUM":
		if high+med > 0 {
			fail = true
		}
	case "LOW":
		if high+med+low > 0 {
			fail = true
		}
	}
	if fail && failOnCritical {
		utils.Error(" Failing due to issues at or above min severity: " + minSeverity)
		return results, 1
	}

	return results, 0
}

// Scan walks through files and checks for hardcoded secrets
func Scan(path string, failOnCritical bool) ([]utils.ScanResult, int) {
	utils.Info("🔍 Scanning code in: " + path)
	var results []utils.ScanResult

	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			utils.Error("Error accessing path: " + p + " - " + err.Error())
			return nil
		}

		if !info.IsDir() &&
			(strings.HasSuffix(p, ".go") ||
				strings.HasSuffix(p, ".js") ||
				strings.HasSuffix(p, ".py") ||
				strings.HasSuffix(p, ".yaml") ||
				strings.HasSuffix(p, ".json")) {
			results = append(results, scanFile(p)...)
		}
		return nil
	})
	if err != nil {
		utils.Error("Error walking path: " + err.Error())
		return results, 2
	}

	// Exit code handling
	exitCode := 0
	if failOnCritical && len(results) > 0 {
		utils.Error(" Critical issues found!")
		exitCode = 1
	}

	return results, exitCode
}

// scanFile checks a single file for sensitive patterns
func scanFile(filename string) []utils.ScanResult {
	file, err := os.Open(filename)
	if err != nil {
		utils.Error("Error opening file: " + filename + " - " + err.Error())
		return nil
	}
	defer file.Close()

	var results []utils.ScanResult
	scanner := bufio.NewScanner(file)
	lineNum := 1
	for scanner.Scan() {
		line := scanner.Text()
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(line), pattern) {
				utils.Warn(fmt.Sprintf("Found '%s' in %s (line %d)", pattern, filename, lineNum))
				results = append(results, utils.ScanResult{
					ScanType: "SECRET",
					Target:   filename,
					Line:     lineNum,
					Severity: "CRITICAL",
					Details:  fmt.Sprintf("Found pattern '%s'", pattern),
				})
			}
		}
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		utils.Error("Error reading file " + filename + ": " + err.Error())
	}

	return results
}
