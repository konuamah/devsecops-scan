package main

import (
	"encoding/json"
	"flag"
	"os"
	"strings"

	"github.com/yourusername/devsecops-scan/internal/code"
	"github.com/yourusername/devsecops-scan/internal/docker"
	"github.com/yourusername/devsecops-scan/internal/sbom"
	"github.com/yourusername/devsecops-scan/internal/utils"
)

func main() {
	// CLI flags
	gosecFlag := flag.Bool("gosec", false, "Run gosec scan")
	dockerFlag := flag.String("docker", "", "Comma-separated Docker images to scan")
	path := flag.String("path", ".", "Path to scan")
	jsonOut := flag.String("json", "", "Save unified results to JSON")
	failCritical := flag.Bool("fail-on-critical", false, "Exit with code 1 if issues found")
	sbomFlag := flag.String("sbom", "", "Generate SBOM JSON file (optional)")
	minSeverity := flag.String("min-severity", "HIGH", "Minimum severity to fail pipeline (HIGH, MEDIUM, LOW)")
	flag.Parse()

	utils.Info("Starting DevSecOps Scan...")

	var allResults []utils.ScanResult
	exitCode := 0

	// ----------------- Gosec Scan -----------------
	if *gosecFlag {
		gosecResults, codeExit := code.RunGosec(*path, *failCritical, *minSeverity)
		allResults = append(allResults, gosecResults...)
		if codeExit > exitCode {
			exitCode = codeExit
		}
	}

	// ----------------- Docker Scan -----------------
	if *dockerFlag != "" {
		images := strings.Split(*dockerFlag, ",")
		for _, img := range images {
			img = strings.TrimSpace(img)
			if img == "" {
				continue
			}
			utils.Info("Scanning Docker image: " + img)
			dockerResults, dockerExit := docker.ScanDockerImage(img, *path, *failCritical, *minSeverity)
			allResults = append(allResults, dockerResults...)
			if dockerExit > exitCode {
				exitCode = dockerExit
			}
		}
	}

	// ----------------- Secret Scan -----------------
	utils.Info("Running hardcoded secrets scan...")
	secretResults, secretExit := code.ScanSecrets(*path, *failCritical)
	allResults = append(allResults, secretResults...)
	if secretExit > exitCode {
		exitCode = secretExit
	}

	// ----------------- Print Markdown table -----------------
	utils.PrintMarkdownTable(allResults)

	// ----------------- Save unified JSON -----------------
	if *jsonOut != "" {
		data, err := json.MarshalIndent(allResults, "", "  ")
		if err != nil {
			utils.Error("Failed to marshal unified JSON: " + err.Error())
			exitCode = 2
		} else if err := os.WriteFile(*jsonOut, data, 0644); err != nil {
			utils.Error("Failed to write unified JSON: " + err.Error())
			exitCode = 2
		} else {
			utils.Info("Unified results saved to " + *jsonOut)
		}
	}

	// ----------------- Optional SBOM -----------------
	if *sbomFlag != "" {
		if err := sbom.GenerateSBOM(*path, *sbomFlag); err != nil {
			utils.Error(err.Error())
		}
	}

	// ----------------- Exit -----------------
	os.Exit(exitCode)
}
