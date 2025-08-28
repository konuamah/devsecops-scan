package code

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yourusername/devsecops-scan/internal/utils"
)

var secretPatterns = []string{"password", "secret", "apikey", "token", "private_key"}

// ScanSecrets walks a path and scans for hardcoded secrets
func ScanSecrets(path string, failOnCritical bool) ([]utils.ScanResult, int) {
	utils.Info("🔍 Scanning for hardcoded secrets in: " + path)
	var results []utils.ScanResult

	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			utils.Error("Error accessing path: " + p + " - " + err.Error())
			return nil // continue walking
		}

		if !info.IsDir() &&
			(strings.HasSuffix(p, ".go") ||
				strings.HasSuffix(p, ".js") ||
				strings.HasSuffix(p, ".py") ||
				strings.HasSuffix(p, ".yaml") ||
				strings.HasSuffix(p, ".json")) {

			file, err := os.Open(p)
			if err != nil {
				utils.Error("Error opening file: " + p + " - " + err.Error())
				return nil
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			lineNum := 1
			for scanner.Scan() {
				line := scanner.Text()
				for _, pattern := range secretPatterns {
					if strings.Contains(strings.ToLower(line), pattern) {
						utils.Warn("Found secret '" + pattern + "' in " + p)
						results = append(results, utils.ScanResult{
							ScanType: utils.SECRET,
							Target:   p,
							Line:     lineNum,
							Severity: utils.HIGH,
							Details:  "Hardcoded secret: " + pattern,
						})
					}
				}
				lineNum++
			}

			if err := scanner.Err(); err != nil {
				utils.Error("Error reading file " + p + ": " + err.Error())
			}
		}
		return nil
	})

	if err != nil {
		utils.Error("Error walking path: " + err.Error())
		return results, 2
	}

	exitCode := 0
	if failOnCritical && len(results) > 0 {
		utils.Error("❌ Critical secrets found!")
		exitCode = 1
	}

	utils.Info("✅ Secrets scan completed, found " + fmt.Sprint(len(results)) + " issues")
	return results, exitCode
}
