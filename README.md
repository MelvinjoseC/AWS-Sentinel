# 🛡️ AWS Sentinel: Automated Security Compliance Auditor

[![CI](https://github.com/MelvinjoseC/AWS-Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MelvinjoseC/AWS-Sentinel/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AWS Boto3](https://img.shields.io/badge/AWS-Boto3-orange.svg)](https://aws.amazon.com/sdk-for-python/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📌 Project Overview
**AWS Sentinel** is a production-grade cloud security compliance auditing and auto-remediation CLI tool. It scans AWS environments for critical misconfigurations that lead to data breaches and unauthorized access, specifically targeting the three most exploited cloud vulnerabilities:
1. **S3 Bucket Leak Prevention:** Detects and auto-remediates buckets without 'Public Access Block' enabled.
2. **IAM MFA Compliance:** Audits all IAM users (with pagination support) to ensure Multi-Factor Authentication is active.
3. **Network Hardening (Port 22):** Scans EC2 Security Groups across multiple AWS regions to detect and revoke open SSH rules exposing Port 22 to `0.0.0.0/0`.

---

## 🛠️ Features

- **Multi-Region Capabilities:** Scan a single region, a custom list of regions, or scan all active AWS regions (`--regions all`).
- **Pagination Support:** Built-in boto3 pagination handling for IAM users and EC2 Security Groups, making the tool enterprise-ready.
- **Auto-Remediation with Dry-Run Safety:** Fix insecure resources automatically (`--remediate`). Use `--dry-run` to preview remediation actions before making any destructive changes.
- **Structured Reporting:** Export findings to JSON or CSV formats, or print a formatted ASCII table directly to console or file (`--format` and `--output-file`).
- **Production Logging:** Replaced raw `print` statements with standard, configurable python `logging`.
- **CI/CD Integrated:** Packaged with automated unit tests (`pytest` and `moto`) and a GitHub Actions workflow for continuous integration.

---

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MelvinjoseC/AWS-Sentinel.git
   cd AWS-Sentinel
   ```

2. **Set up a Virtual Environment & Install Dependencies:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate

   pip install -r requirements.txt
   ```

3. **Configure AWS Credentials:**
   Ensure your local environment has active AWS credentials configured via the AWS CLI:
   ```bash
   aws configure
   ```

---

## 💻 CLI Usage

Execute audits and view findings with flexible options.

### Run a Standard Audit (Prints ASCII Table)
```bash
python sentinel.py
```

### Scan Specific Services and Regions
```bash
# Scan only S3 and EC2 Security Groups in us-east-1 and us-west-2
python sentinel.py --services s3 ec2 --regions us-east-1 us-west-2
```

### Scan All Active Regions
```bash
python sentinel.py --services ec2 --regions all
```

### Export Findings to JSON or CSV Report
```bash
# Save to JSON
python sentinel.py --format json --output-file audit-report.json

# Save to CSV
python sentinel.py --format csv --output-file audit-report.csv
```

### Run Remediation in Dry-Run Mode (Preview Fixes)
```bash
python sentinel.py --remediate --dry-run
```

### Execute Auto-Remediation (Apply Fixes)
```bash
python sentinel.py --remediate
```
### Dispatch ChatOps Webhook Notifications (Slack & MS Teams)
```bash
# Send alerts to Slack on compliance failures
python sentinel.py --slack-webhook "https://hooks.slack.com/services/YOUR_WORKSPACE/YOUR_CHANNEL/YOUR_TOKEN"

# Send alerts to MS Teams on compliance failures
python sentinel.py --teams-webhook "https://outlook.office.com/webhook/YOUR_WEBHOOK_TOKEN"
```

---

## 🧪 Development & Testing

We use `pytest` and `moto` to mock AWS environments. This allows running the full test suite locally without requiring active AWS credentials or incurring charges.

### Run Tests
```bash
pytest -v
```

### Run Linting and Formatting
```bash
# Run Ruff lint check
ruff check .

# Run Ruff code formatter check
ruff format --check .
```

---

## 🛡️ Remediation Details

| Service | Risk | Auto-Remediation Action |
| --- | --- | --- |
| **S3** | Publicly accessible bucket configuration | Applies a strict `PublicAccessBlockConfiguration` to block all public ACLs and Policies. |
| **EC2** | SSH (Port 22) open to `0.0.0.0/0` | Revokes the insecure ingress rule from the security group in that specific region. |
| **IAM** | MFA disabled on user accounts | *Manual Action required.* Logs warning and marks status as `Manual Intervention Required`. |

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.