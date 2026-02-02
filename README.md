# 🛡️ AWS Sentinel: Automated Security Compliance Auditor

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AWS Boto3](https://img.shields.io/badge/AWS-Boto3-orange.svg)](https://aws.amazon.com/sdk-for-python/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📌 Project Overview
As a Developer transitioning into Cloud Security, I built **AWS Sentinel** to bridge the gap between rapid deployment and infrastructure security. This Python-based automation tool scans AWS environments for critical misconfigurations that lead to data breaches and unauthorized access.

By leveraging the `boto3` SDK, this tool provides an instant audit of a company's "Security Posture," focusing on the three most exploited cloud vulnerabilities.

## 🚀 Key Security Audits
- **S3 Bucket Leak Prevention:** Identifies buckets without 'Public Access Block' enabled to prevent accidental data exposure.
- **IAM Compliance (MFA):** Scans all IAM users to ensure Multi-Factor Authentication is active, mitigating credential theft risks.
- **Network Hardening (Port 22):** Detects Security Groups with SSH (Port 22) open to the public internet (`0.0.0.0/0`), a primary vector for brute-force attacks.

## 🛠️ Tech Stack
- **Language:** Python 3.x
- **SDK:** AWS Boto3 (Infrastructure as Code & Automation)
- **Environment:** AWS IAM, S3, EC2

## 📦 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/aws-sentinel.git](https://github.com/YOUR_USERNAME/aws-sentinel.git)
   cd aws-sentinel
   