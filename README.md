# DevSecOps Scan CLI

A Go-based **DevSecOps CLI** to scan your projects and Docker images for vulnerabilities, hardcoded secrets, and generate SBOMs. Works locally or in CI/CD pipelines with JSON and Markdown reporting.

---

## Features

- Static code analysis using **Gosec** for Go projects  
- Docker image scanning for CVEs  
- Hardcoded secrets detection  
- Markdown table output for CI logs  
- Unified JSON reporting for dashboards or audit  
- Optional **SBOM generation** using **Syft**  
- Supports multiple Docker images  
- Configurable `min-severity` and `fail-on-critical` flags  

---

## Installation

Clone the repository and build the CLI:

```bash
git clone https://github.com/yourusername/devsecops-scan.git
cd devsecops-scan
go build -o devsecops-scan ./cmd/devsecops-scan
```

Ensure dependencies are installed:
- Gosec: `go install github.com/securego/gosec/v2/cmd/gosec@latest`
- Syft (for SBOM): `brew install syft` (macOS) or download binary from [Syft releases](https://github.com/anchore/syft/releases)

## Usage

Run the CLI locally:

```bash
./devsecops-scan --gosec --docker=myapp:latest,redis:7.0 --path=. --json=results.json --sbom=sbom.json --fail-on-critical
```

### Flags

| Flag | Description |
|------|-------------|
| `--gosec` | Run static code analysis with Gosec |
| `--docker` | Comma-separated Docker images to scan |
| `--path` | Path to scan (default .) |
| `--json` | File to save unified JSON results |
| `--sbom` | Generate SBOM JSON file (optional) |
| `--fail-on-critical` | Exit with code 1 if issues ≥ --min-severity |
| `--min-severity` | Minimum severity to fail pipeline (HIGH, MEDIUM, LOW) |

### Example Run

```bash
./devsecops-scan \
  --gosec \
  --docker=myapp:latest,redis:7.0 \
  --path=. \
  --json=results.json \
  --sbom=sbom.json \
  --fail-on-critical \
  --min-severity=HIGH
```

**Sample Console Output:**

```
Starting DevSecOps Scan...
Running gosec on: .
[MEDIUM] Potential file inclusion in ./internal/code/scan.go
Summary → HIGH: 0, MEDIUM: 1, LOW: 0
Scanning Docker image: myapp:latest
[HIGH] CVE-2023-xxxx detected in openssl package
Running hardcoded secrets scan...
Found secret 'password' in ./internal/code/scan.go (line 42)

| Severity | Scan Type | Target | Line | Package | Details |
|---------|-----------|--------|------|---------|---------|
| MEDIUM  | GOSEC     | ./internal/code/scan.go | 172 |  | Potential file inclusion |
| HIGH    | DOCKER    | myapp:latest |  | openssl | CVE-2023-xxxx detected |
| HIGH    | SECRET    | ./internal/code/scan.go | 42 |  | Hardcoded secret: password |

Unified results saved to results.json
Generating SBOM for: .
SBOM saved to: sbom.json
exit status 1
```

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
jobs:
  security_scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build CLI
        run: go build -o devsecops-scan ./cmd/devsecops-scan
      - name: Run DevSecOps Scan
        run: |
          ./devsecops-scan \
            --gosec \
            --docker=myapp:latest \
            --path=. \
            --json=results.json \
            --sbom=sbom.json \
            --fail-on-critical
      - name: Upload Scan Report
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-report
          path: results.json
```

## Workflow Diagram

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│ Local Scan  │───▶│   Analysis   │───▶│    Reporting    │
│             │    │              │    │                 │
│ • Go Code   │    │ • Gosec      │    │ • JSON Output   │
│ • Docker    │    │ • CVE Scan   │    │ • Markdown      │
│ • Secrets   │    │ • Secret Det │    │ • SBOM          │
└─────────────┘    └──────────────┘    └─────────────────┘
                                                │
                                       ┌────────▼─────────┐
                                       │   CI/CD Pipeline │
                                       │                  │
                                       │ • Fail on Issues │
                                       │ • Upload Reports │
                                       │ • Security Gates │
                                       └──────────────────┘
```

## License

MIT License – free to use and modify.
