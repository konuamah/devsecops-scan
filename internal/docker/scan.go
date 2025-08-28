package docker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/yourusername/devsecops-scan/internal/utils"
)

// ScanDockerImage scans a Docker image for vulnerabilities
func ScanDockerImage(image string, path string, failOnCritical bool, minSeverity string) ([]utils.ScanResult, int) {
	utils.Info("Scanning Docker image: " + image)
	jsonFile := "trivy_temp.json"

	cmd := exec.Command("trivy", "image", "-f", "json", "-o", jsonFile, image)
	out, err := cmd.CombinedOutput()
	if err != nil {
		utils.Error("Failed to run Trivy: " + err.Error())
		fmt.Println(string(out))
		return nil, 2
	}

	data, err := os.ReadFile(jsonFile)
	if err != nil {
		utils.Error("Failed to read Trivy JSON: " + err.Error())
		return nil, 2
	}

	var trivyResult struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				PkgName  string `json:"PkgName"`
				Severity string `json:"Severity"`
				Title    string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(data, &trivyResult); err != nil {
		utils.Error("Failed to parse Trivy JSON: " + err.Error())
		return nil, 2
	}

	var results []utils.ScanResult
	high, med, low := 0, 0, 0

	for _, res := range trivyResult.Results {
		for _, v := range res.Vulnerabilities {
			results = append(results, utils.ScanResult{
				ScanType: utils.DOCKER,
				Target:   res.Target,
				Package:  v.PkgName,
				Severity: utils.Severity(v.Severity),
				Details:  v.Title,
			})

			utils.Warn(fmt.Sprintf("[%s] %s in %s (package %s)", v.Severity, v.Title, res.Target, v.PkgName))

			switch v.Severity {
			case "CRITICAL", "HIGH":
				high++
			case "MEDIUM":
				med++
			case "LOW":
				low++
			}
		}
	}

	exitCode := 0
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
		utils.Error("Failing due to Docker issues at or above min severity: " + minSeverity)
		exitCode = 1
	}

	utils.Info(fmt.Sprintf("Summary → HIGH: %d, MEDIUM: %d, LOW: %d", high, med, low))
	return results, exitCode
}
