package sbom

import (
	"fmt"
	"os/exec"
)

// GenerateSBOM generates an SBOM for a path or Docker image using Syft
func GenerateSBOM(target string, outputFile string) error {
	fmt.Println("ℹ️  Generating SBOM for: " + target)

	// Correct flags for Syft v1.32+
	cmd := exec.Command("syft", target, "-o", "json", "--file", outputFile)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to generate SBOM: %v\nOutput: %s", err, string(out))
	}

	fmt.Println("SBOM saved to: " + outputFile)
	return nil
}
