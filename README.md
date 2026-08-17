# 🛡️ AWS Sentinel: Automated Security Compliance Auditor

[![CI](https://github.com/MelvinjoseC/AWS-Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MelvinjoseC/AWS-Sentinel/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AWS Boto3](https://img.shields.io/badge/AWS-Boto3-orange.svg)](https://aws.amazon.com/sdk-for-python/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📌 Project Overview
**AWS Sentinel** is a production-grade, enterprise-ready cloud security compliance auditing and auto-remediation tool. It checks AWS environments against core security baselines and automatically repairs key vulnerabilities, protecting your infrastructure from leaks and unauthorized access.

It scans the following key resources and configurations:
1. **S3 Bucket Security:**
   - Detects and remediates buckets without `Public Access Block` enabled.
   - Detects and remediates buckets missing default `AES256/KMS` server-side encryption.
   - Detects and remediates buckets missing default `Bucket Versioning`.
2. **IAM Credential Protection & Hygiene:**
   - Audits all IAM users to ensure Multi-Factor Authentication (MFA) is active.
   - Identifies active IAM user Access Keys older than 90 days.
   - Audits and deactivates unused IAM Access Keys (unused for > 90 days).
   - Audits the account-wide IAM Password Policy against production-grade settings.
3. **Network Ingress Protection (Security Groups):**
   - Scans EC2 Security Groups for publicly open ports (`0.0.0.0/0` or `::/0`).
   - Supports scanning and auto-revoking open rules for Port 22 (SSH), Port 3389 (RDP), Port 21 (FTP), and other custom ports.
   - Identifies and revokes rules exposing "All Traffic" (protocol `-1`) to the public internet.
4. **KMS Key Rotation:**
   - Audits KMS Customer Managed Keys (CMKs) to ensure key rotation is enabled. Auto-remediates by enabling rotation.
5. **EBS Volume Encryption:**
   - Checks if EBS Encryption by Default is enabled in all regions. Auto-remediates by enabling default encryption.
   - Audits individual EBS volumes in all active regions to verify they are encrypted.
6. **CloudTrail Auditing:**
   - Verifies if at least one active, multi-region CloudTrail is configured and logging.

---

## 🛠️ Features

- **Multi-Region Capabilities:** Scan a single region, a custom list of regions, or scan all active AWS regions (`--regions all`).
- **Flexible Declarative Configuration:** Control checks, exclude specific resources (e.g. S3 bucket exclusions), and custom port scans via `config.yaml`.
- **Auto-Remediation with Dry-Run Safety:** Automatically repair insecure resources (`--remediate`). Use `--dry-run` to preview changes before making destructive edits.
- **Structured Reporting:** Export audit findings to JSON, CSV, or formatted ASCII table to files or console.
- **Enterprise-Grade Logging:** Supports standard human-readable logging and structured JSON logging (`--json-logging`) for ELK, Datadog, or Splunk ingestion.
- **CI/CD Security Gates:** Includes built-in pytest suite, code linter (Ruff), security scan (Bandit), and dependency audit (pip-audit) integrated into GitHub Actions.
- **Containerized Execution:** Ready to run inside Kubernetes CronJobs or CI runners using the included `Dockerfile` and `docker-compose.yml`.
- **Infrastructure as Code (IaC):** Terraform module to deploy AWS Sentinel as a scheduled AWS Lambda function triggered daily via EventBridge.

---

## ⚙️ Configuration (`config.yaml`)

Control Sentinel auditing behavior using the declarative `config.yaml` file:

```yaml
# AWS Sentinel Compliance Configuration File

# Customize severity overrides for finding reporting
severity_overrides:
  "S3.Public Access Block is not enabled": "High"
  "EC2.Port 22 (SSH) is open to the public internet (0.0.0.0/0)": "Critical"
  "IAM.Multi-Factor Authentication (MFA) is disabled": "High"

s3:
  exclude_buckets:
    - "my-safe-public-assets-bucket" # Buckets to exclude from audits
  check_encryption: true
  check_versioning: true

iam:
  max_access_key_age_days: 90
  max_unused_access_key_days: 90
  password_policy:
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_symbols: true
    minimum_length: 14

ec2:
  ports_to_check:
    - port: 22
      protocol: "tcp"
      severity: "Critical"
    - port: 3389
      protocol: "tcp"
      severity: "Critical"
    - port: 21
      protocol: "tcp"
      severity: "High"
```

---

## 🚀 Deployment & Usage

### 1. Local CLI Execution

```bash
# Clone the repository
git clone https://github.com/MelvinjoseC/AWS-Sentinel.git
cd AWS-Sentinel

# Setup virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run a standard audit scan using the configuration file
python sentinel.py --config config.yaml

# Run with custom profile and JSON logging
python sentinel.py --config config.yaml --profile my-prod-profile --json-logging
```

### 2. Containerized Execution (Docker)

```bash
# Build the multi-stage minimal Docker image
docker build -t aws-sentinel .

# Run the auditor using your host AWS credentials
docker run --rm -v ~/.aws:/root/.aws:ro aws-sentinel --config config.yaml

# Run tests or run audit using Docker Compose
docker-compose run auditor
docker-compose run tester
```

### 3. Scheduled AWS Lambda Deployment (Terraform)

Deploy AWS Sentinel as a serverless scheduled task that runs daily inside your AWS account and alerts you on compliance failures via webhooks:

```bash
cd terraform

# Initialize and preview deployment
terraform init
terraform plan -var="slack_webhook_url=https://hooks.slack.com/services/..."

# Apply configuration
terraform apply -var="slack_webhook_url=https://hooks.slack.com/services/..."
```

---

## 🛡️ Audit Rules & Remediation

| Service | Check | Severity | Auto-Remediation Action |
| --- | --- | --- | --- |
| **S3** | Public Access Block | High | Applies standard public block configuration. |
| **S3** | Server-Side Encryption | Medium | Enables default `AES256` encryption. |
| **S3** | Bucket Versioning | Medium | Enables bucket versioning. |
| **IAM** | MFA Compliance | High | *Manual Action.* Requires user manual configuration. |
| **IAM** | Access Key Age | Medium | *Manual Action.* Prompts key rotation if age > 90 days. |
| **IAM** | Password Policy | Medium | *Manual Action.* Highlights non-compliant configuration values. |
| **IAM** | Unused Access Keys | Medium | Deactivates access keys unused for > 90 days. |
| **EC2** | Open SG Ingress Rules | Critical/High | Revokes open `0.0.0.0/0` or `::/0` rule for the target port. |
| **EC2** | Open SG All Traffic | Critical | Revokes open rule exposing all protocols (protocol `-1`). |
| **KMS** | CMK Key Rotation | Medium | Enables automatic rotation for customer managed keys. |
| **EBS** | Default Encryption | Medium | Enables account-level default EBS volume encryption. |
| **EBS** | Unencrypted Volumes | High | *Manual Action.* Prompts encryption for active volumes. |
| **CloudTrail** | Active Logging Trail | High | *Manual Action.* Prompts creation of multi-region active trail. |

---

## 🧪 Testing & Code Quality

We use `pytest` and `moto` to run unit tests without incurring charges or requiring AWS credentials.

```bash
# Run test suite
pytest -v

# Run linting
ruff check .

# Run security static analysis
bandit -r . -x ./tests,./venv
```

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.