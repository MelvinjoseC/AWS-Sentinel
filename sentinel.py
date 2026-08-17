import argparse
import csv
import datetime
import io
import json
import logging
import sys
import urllib.request

try:
    import yaml
except ImportError:
    yaml = None

import boto3
from botocore.exceptions import ClientError, ProfileNotFound


class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "logger": record.name,
            "level": record.levelname,
            "message": record.getMessage()
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

# Setup logging
def setup_logging(level, json_format=False):
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)
    root_logger.setLevel(level)


logger = logging.getLogger("aws-sentinel")

class AWSSentinelAuditor:
    def __init__(self, session=None, dry_run=False, config_path=None):
        from botocore.config import Config
        self.session = session or boto3.Session()
        self.dry_run = dry_run
        self.config = self._load_config(config_path)

        # Configure retry strategy with exponential backoff
        self.botocore_config = Config(
            retries={
                'max_attempts': 5,
                'mode': 'standard'
            }
        )

        self.s3_client = self.session.client('s3', config=self.botocore_config)
        self.iam_client = self.session.client('iam', config=self.botocore_config)
        # EC2 client for default region to discover active regions
        default_region = self.session.region_name or 'us-east-1'
        self.ec2_client = self.session.client('ec2', region_name=default_region, config=self.botocore_config)

    def _load_config(self, config_path):
        default_config = {
            "severity_overrides": {},
            "s3": {"exclude_buckets": [], "check_encryption": True, "check_versioning": True},
            "iam": {
                "max_access_key_age_days": 90,
                "password_policy": {
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_numbers": True,
                    "require_symbols": True,
                    "minimum_length": 14
                }
            },
            "ec2": {
                "ports_to_check": [
                    {"port": 22, "protocol": "tcp", "severity": "Critical"}
                ]
            }
        }
        if not config_path:
            return default_config

        try:
            with open(config_path, 'r') as f:
                if yaml:
                    loaded = yaml.safe_load(f) or {}
                else:
                    loaded = json.load(f) or {}

                # Merge loaded config with default_config structure
                for key, val in loaded.items():
                    if isinstance(val, dict) and key in default_config:
                        default_config[key].update(val)
                    else:
                        default_config[key] = val
                logger.info(f"Configuration loaded successfully from {config_path}")
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}. Using defaults.")
        return default_config

    def get_active_regions(self):
        """Retrieves a list of all active AWS regions."""
        try:
            regions_response = self.ec2_client.describe_regions()
            return [r['RegionName'] for r in regions_response['Regions']]
        except ClientError as e:
            logger.error(f"Failed to describe regions: {e}. Defaulting to session region.")
            return [self.session.region_name or 'us-east-1']

    def audit_s3(self, remediate=False):
        """Audits S3 buckets for Public Access Block settings and remediates if requested."""
        logger.info("Starting S3 bucket audit...")
        findings = []
        try:
            buckets = self.s3_client.list_buckets().get('Buckets', [])
        except ClientError as e:
            logger.error(f"Failed to list S3 buckets: {e}")
            return findings

        for bucket in buckets:
            name = bucket['Name']
            if name in self.config.get('s3', {}).get('exclude_buckets', []):
                logger.info(f"Skipping S3 Bucket '{name}' as per exclusion list.")
                continue

            # 1. Public Access Block Check
            remediation_status = "N/A"
            try:
                self.s3_client.get_public_access_block(Bucket=name)
                logger.info(f"✅ S3 Bucket '{name}': Secure (Public Access Blocked)")
                findings.append({
                    "Service": "S3",
                    "Region": "global",
                    "ResourceID": name,
                    "ResourceName": name,
                    "Status": "PASS",
                    "Finding": "Public Access Block is enabled",
                    "Severity": "Low",
                    "RemediationStatus": remediation_status
                })
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    logger.warning(f"❌ S3 Bucket '{name}': WARNING - Public Access NOT Blocked!")

                    if remediate:
                        if self.dry_run:
                            logger.info(f"[DRY-RUN] Would enable Public Access Block for S3 bucket '{name}'")
                            remediation_status = "Dry-Run: Enable Public Access Block"
                        else:
                            try:
                                logger.info(f"Remediating S3 bucket '{name}': Enabling Public Access Block...")
                                self.s3_client.put_public_access_block(
                                    Bucket=name,
                                    PublicAccessBlockConfiguration={
                                        'BlockPublicAcls': True,
                                        'IgnorePublicAcls': True,
                                        'BlockPublicPolicy': True,
                                        'RestrictPublicBuckets': True
                                    }
                                )
                                logger.info(f"✅ S3 Bucket '{name}': Successfully Remediated")
                                remediation_status = "Remediated"
                            except ClientError as re:
                                logger.error(f"Failed to remediate S3 bucket '{name}': {re}")
                                remediation_status = f"Remediation Failed: {re.response['Error']['Message']}"
                    else:
                        remediation_status = "None (Remediation not requested)"

                    findings.append({
                        "Service": "S3",
                        "Region": "global",
                        "ResourceID": name,
                        "ResourceName": name,
                        "Status": "FAIL",
                        "Finding": "Public Access Block is not enabled",
                        "Severity": "High",
                        "RemediationStatus": remediation_status
                    })
                else:
                    logger.error(f"Error checking public access block for bucket '{name}': {e}")
                    findings.append({
                        "Service": "S3",
                        "Region": "global",
                        "ResourceID": name,
                        "ResourceName": name,
                        "Status": "ERROR",
                        "Finding": f"Failed to retrieve configuration: {e.response['Error']['Message']}",
                        "Severity": "Medium",
                        "RemediationStatus": remediation_status
                    })

            # 2. Server-side Encryption Check
            if self.config.get('s3', {}).get('check_encryption', True):
                enc_remediation_status = "N/A"
                try:
                    self.s3_client.get_bucket_encryption(Bucket=name)
                    logger.info(f"✅ S3 Bucket '{name}': Secure (Default Encryption Enabled)")
                    findings.append({
                        "Service": "S3",
                        "Region": "global",
                        "ResourceID": name,
                        "ResourceName": name,
                        "Status": "PASS",
                        "Finding": "Default encryption is enabled",
                        "Severity": "Low",
                        "RemediationStatus": enc_remediation_status
                    })
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        logger.warning(f"❌ S3 Bucket '{name}': WARNING - Default Encryption NOT Enabled!")

                        if remediate:
                            if self.dry_run:
                                logger.info(f"[DRY-RUN] Would enable default AES256 encryption for S3 bucket '{name}'")
                                enc_remediation_status = "Dry-Run: Enable AES256 Encryption"
                            else:
                                try:
                                    logger.info(f"Remediating S3 bucket '{name}': Enabling default AES256 encryption...")
                                    self.s3_client.put_bucket_encryption(
                                        Bucket=name,
                                        ServerSideEncryptionConfiguration={
                                            'Rules': [
                                                {
                                                    'ApplyServerSideEncryptionByDefault': {
                                                        'SSEAlgorithm': 'AES256'
                                                    }
                                                }
                                            ]
                                        }
                                    )
                                    logger.info(f"✅ S3 Bucket '{name}': Default Encryption Enabled")
                                    enc_remediation_status = "Remediated"
                                except ClientError as re:
                                    logger.error(f"Failed to enable encryption for S3 bucket '{name}': {re}")
                                    enc_remediation_status = f"Remediation Failed: {re.response['Error']['Message']}"
                        else:
                            enc_remediation_status = "None (Remediation not requested)"

                        findings.append({
                            "Service": "S3",
                            "Region": "global",
                            "ResourceID": name,
                            "ResourceName": name,
                            "Status": "FAIL",
                            "Finding": "Default encryption is not enabled",
                            "Severity": "Medium",
                            "RemediationStatus": enc_remediation_status
                        })
                    else:
                        logger.error(f"Error checking encryption for bucket '{name}': {e}")
                        findings.append({
                            "Service": "S3",
                            "Region": "global",
                            "ResourceID": name,
                            "ResourceName": name,
                            "Status": "ERROR",
                            "Finding": f"Failed to retrieve default encryption: {e.response['Error']['Message']}",
                            "Severity": "Medium",
                            "RemediationStatus": "N/A"
                        })

            # 3. Versioning Check
            if self.config.get('s3', {}).get('check_versioning', True):
                try:
                    versioning = self.s3_client.get_bucket_versioning(Bucket=name)
                    status = versioning.get('Status', 'Disabled')
                    if status == 'Enabled':
                        logger.info(f"✅ S3 Bucket '{name}': Secure (Versioning Enabled)")
                        findings.append({
                            "Service": "S3",
                            "Region": "global",
                            "ResourceID": name,
                            "ResourceName": name,
                            "Status": "PASS",
                            "Finding": "Bucket versioning is enabled",
                            "Severity": "Low",
                            "RemediationStatus": "N/A"
                        })
                    else:
                        logger.warning(f"❌ S3 Bucket '{name}': WARNING - Versioning is {status.upper()}!")

                        if remediate:
                            if self.dry_run:
                                logger.info(f"[DRY-RUN] Would enable versioning for S3 bucket '{name}'")
                                ver_remediation_status = "Dry-Run: Enable Versioning"
                            else:
                                try:
                                    logger.info(f"Remediating S3 bucket '{name}': Enabling bucket versioning...")
                                    self.s3_client.put_bucket_versioning(
                                        Bucket=name,
                                        VersioningConfiguration={
                                            'Status': 'Enabled'
                                        }
                                    )
                                    logger.info(f"✅ S3 Bucket '{name}': Versioning Enabled")
                                    ver_remediation_status = "Remediated"
                                except ClientError as re:
                                    logger.error(f"Failed to enable versioning for S3 bucket '{name}': {re}")
                                    ver_remediation_status = f"Remediation Failed: {re.response['Error']['Message']}"
                        else:
                            ver_remediation_status = "None (Remediation not requested)"

                        findings.append({
                            "Service": "S3",
                            "Region": "global",
                            "ResourceID": name,
                            "ResourceName": name,
                            "Status": "FAIL",
                            "Finding": f"Bucket versioning is {status.lower()}",
                            "Severity": "Medium",
                            "RemediationStatus": ver_remediation_status
                        })
                except ClientError as e:
                    logger.error(f"Error checking versioning for bucket '{name}': {e}")
                    findings.append({
                        "Service": "S3",
                        "Region": "global",
                        "ResourceID": name,
                        "ResourceName": name,
                        "Status": "ERROR",
                        "Finding": f"Failed to retrieve versioning configuration: {e.response['Error']['Message']}",
                        "Severity": "Medium",
                        "RemediationStatus": "N/A"
                    })
        return findings

    def audit_iam(self, remediate=False):
        """Audits IAM users for MFA compliance using pagination. Remediation is manual."""
        logger.info("Starting IAM audit...")
        findings = []
        try:
            paginator = self.iam_client.get_paginator('list_users')
            pages = paginator.paginate()
        except ClientError as e:
            logger.error(f"Failed to initialize IAM list_users paginator: {e}")
            return findings

        for page in pages:
            for user in page.get('Users', []):
                username = user['UserName']
                remediation_status = "N/A"
                try:
                    mfa_devices = self.iam_client.list_mfa_devices(UserName=username).get('MFADevices', [])
                    if not mfa_devices:
                        logger.warning(f"❌ IAM User '{username}': MFA is DISABLED!")
                        if remediate:
                            logger.info(f"Remediation for IAM User '{username}': MFA requires manual setup by user.")
                            remediation_status = "Manual Intervention Required"
                        else:
                            remediation_status = "None (Remediation not requested)"

                        findings.append({
                            "Service": "IAM",
                            "Region": "global",
                            "ResourceID": user['Arn'],
                            "ResourceName": username,
                            "Status": "FAIL",
                            "Finding": "Multi-Factor Authentication (MFA) is disabled",
                            "Severity": "High",
                            "RemediationStatus": remediation_status
                        })
                    else:
                        logger.info(f"✅ IAM User '{username}': MFA is Active")
                        findings.append({
                            "Service": "IAM",
                            "Region": "global",
                            "ResourceID": user['Arn'],
                            "ResourceName": username,
                            "Status": "PASS",
                            "Finding": "Multi-Factor Authentication (MFA) is active",
                            "Severity": "Low",
                            "RemediationStatus": remediation_status
                        })
                except ClientError as e:
                    logger.error(f"Error checking MFA for user '{username}': {e}")
                    findings.append({
                        "Service": "IAM",
                        "Region": "global",
                        "ResourceID": user['Arn'],
                        "ResourceName": username,
                        "Status": "ERROR",
                        "Finding": f"Failed to retrieve MFA devices: {e.response['Error']['Message']}",
                        "Severity": "Medium",
                        "RemediationStatus": remediation_status
                    })

                # 2. Access Key Age Check
                max_age_days = self.config.get('iam', {}).get('max_access_key_age_days', 90)
                try:
                    keys = self.iam_client.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                    now = datetime.datetime.now(datetime.timezone.utc)
                    for key in keys:
                        key_id = key['AccessKeyId']
                        create_date = key['CreateDate']
                        age_days = (now - create_date).days
                        if age_days > max_age_days:
                            logger.warning(f"❌ IAM User '{username}': Access Key '{key_id}' is {age_days} days old (Limit: {max_age_days} days)!")
                            findings.append({
                                "Service": "IAM",
                                "Region": "global",
                                "ResourceID": key_id,
                                "ResourceName": username,
                                "Status": "FAIL",
                                "Finding": f"Access Key is older than {max_age_days} days ({age_days} days)",
                                "Severity": "Medium",
                                "RemediationStatus": "Manual Intervention Required"
                            })
                        else:
                            logger.info(f"✅ IAM User '{username}': Access Key '{key_id}' is active and compliant ({age_days} days old)")
                            findings.append({
                                "Service": "IAM",
                                "Region": "global",
                                "ResourceID": key_id,
                                "ResourceName": username,
                                "Status": "PASS",
                                "Finding": f"Access Key is active and compliant ({age_days} days old)",
                                "Severity": "Low",
                                "RemediationStatus": "N/A"
                            })

                        # 3. Unused Access Key Check
                        max_unused_days = self.config.get('iam', {}).get('max_unused_access_key_days', 90)
                        unused_remediation_status = "N/A"
                        try:
                            last_used_resp = self.iam_client.get_access_key_last_used(AccessKeyId=key_id)
                            last_used_info = last_used_resp.get('AccessKeyLastUsed', {})
                            last_used_date = last_used_info.get('LastUsedDate')

                            if last_used_date:
                                unused_days = (now - last_used_date).days
                                is_unused = unused_days > max_unused_days
                                finding_msg = f"Access Key has not been used in {unused_days} days (Limit: {max_unused_days} days)"
                            else:
                                unused_days = age_days
                                is_unused = unused_days > max_unused_days
                                finding_msg = f"Access Key has never been used and is {unused_days} days old (Limit: {max_unused_days} days)"

                            if is_unused:
                                logger.warning(f"❌ IAM User '{username}': Access Key '{key_id}' is unused for {unused_days} days!")
                                if remediate:
                                    if self.dry_run:
                                        logger.info(f"[DRY-RUN] Would deactivate unused Access Key '{key_id}' for user '{username}'")
                                        unused_remediation_status = "Dry-Run: Deactivate Access Key"
                                    else:
                                        try:
                                            logger.info(f"Remediating IAM User '{username}': Deactivating unused Access Key '{key_id}'...")
                                            self.iam_client.update_access_key(
                                                UserName=username,
                                                AccessKeyId=key_id,
                                                Status='Inactive'
                                            )
                                            logger.info(f"✅ IAM Access Key '{key_id}': Successfully Deactivated")
                                            unused_remediation_status = "Remediated (Deactivated)"
                                        except ClientError as re:
                                            logger.error(f"Failed to deactivate Access Key '{key_id}': {re}")
                                            unused_remediation_status = f"Remediation Failed: {re.response['Error']['Message']}"
                                else:
                                    unused_remediation_status = "None (Remediation not requested)"

                                findings.append({
                                    "Service": "IAM",
                                    "Region": "global",
                                    "ResourceID": key_id,
                                    "ResourceName": username,
                                    "Status": "FAIL",
                                    "Finding": finding_msg,
                                    "Severity": "Medium",
                                    "RemediationStatus": unused_remediation_status
                                })
                            else:
                                usage_str = f"last used {unused_days} days ago" if last_used_date else "never used"
                                logger.info(f"✅ IAM User '{username}': Access Key '{key_id}' usage is compliant ({usage_str})")
                                findings.append({
                                    "Service": "IAM",
                                    "Region": "global",
                                    "ResourceID": key_id,
                                    "ResourceName": username,
                                    "Status": "PASS",
                                    "Finding": f"Access Key usage is compliant ({usage_str})",
                                    "Severity": "Low",
                                    "RemediationStatus": "N/A"
                                })
                        except ClientError as e:
                            logger.error(f"Error checking last used time for access key '{key_id}': {e}")
                            findings.append({
                                "Service": "IAM",
                                "Region": "global",
                                "ResourceID": key_id,
                                "ResourceName": username,
                                "Status": "ERROR",
                                "Finding": f"Failed to check access key last used time: {e.response['Error']['Message']}",
                                "Severity": "Medium",
                                "RemediationStatus": "N/A"
                            })
                except ClientError as e:
                    logger.error(f"Error checking access keys for user '{username}': {e}")
                    findings.append({
                        "Service": "IAM",
                        "Region": "global",
                        "ResourceID": user['Arn'],
                        "ResourceName": username,
                        "Status": "ERROR",
                        "Finding": f"Failed to retrieve access keys: {e.response['Error']['Message']}",
                        "Severity": "Medium",
                        "RemediationStatus": "N/A"
                    })
        findings.extend(self.audit_iam_password_policy())
        return findings

    def audit_iam_password_policy(self):
        """Audits the account-wide IAM Password Policy against security baselines."""
        logger.info("Auditing IAM Password Policy...")
        policy_config = self.config.get('iam', {}).get('password_policy', {})
        findings = []

        try:
            policy = self.iam_client.get_account_password_policy().get('PasswordPolicy', {})

            # Map of config key to policy attribute and readable name
            checks = {
                'minimum_length': ('MinimumPasswordLength', 'Minimum Length'),
                'require_symbols': ('RequireSymbols', 'Require Symbols'),
                'require_numbers': ('RequireNumbers', 'Require Numbers'),
                'require_uppercase': ('RequireUppercaseCharacters', 'Require Uppercase'),
                'require_lowercase': ('RequireLowercaseCharacters', 'Require Lowercase')
            }

            failures = []
            for config_key, (policy_attr, name) in checks.items():
                expected = policy_config.get(config_key)
                if expected is None:
                    continue

                actual = policy.get(policy_attr)
                if config_key == 'minimum_length':
                    if actual is None or actual < expected:
                        failures.append(f"{name} (Expected: >= {expected}, Actual: {actual})")
                else:
                    if not actual:
                        failures.append(f"{name} (Expected: {expected}, Actual: {actual})")

            if failures:
                logger.warning(f"❌ IAM Password Policy is not compliant: {', '.join(failures)}!")
                findings.append({
                    "Service": "IAM",
                    "Region": "global",
                    "ResourceID": "AccountPasswordPolicy",
                    "ResourceName": "Account Password Policy",
                    "Status": "FAIL",
                    "Finding": f"Password policy is non-compliant: {', '.join(failures)}",
                    "Severity": "Medium",
                    "RemediationStatus": "Manual Intervention Required"
                })
            else:
                logger.info("✅ IAM Password Policy is compliant with security baseline settings.")
                findings.append({
                    "Service": "IAM",
                    "Region": "global",
                    "ResourceID": "AccountPasswordPolicy",
                    "ResourceName": "Account Password Policy",
                    "Status": "PASS",
                    "Finding": "Password policy is compliant with baseline settings",
                    "Severity": "Low",
                    "RemediationStatus": "N/A"
                })

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                logger.warning("❌ IAM Password Policy is NOT defined for this account!")
                findings.append({
                    "Service": "IAM",
                    "Region": "global",
                    "ResourceID": "AccountPasswordPolicy",
                    "ResourceName": "Account Password Policy",
                    "Status": "FAIL",
                    "Finding": "No IAM password policy is defined for this AWS account",
                    "Severity": "High",
                    "RemediationStatus": "Manual Intervention Required"
                })
            else:
                logger.error(f"Error retrieving IAM Password Policy: {e}")
                findings.append({
                    "Service": "IAM",
                    "Region": "global",
                    "ResourceID": "AccountPasswordPolicy",
                    "ResourceName": "Account Password Policy",
                    "Status": "ERROR",
                    "Finding": f"Failed to retrieve password policy: {e.response['Error']['Message']}",
                    "Severity": "Medium",
                    "RemediationStatus": "N/A"
                })
        return findings

    def audit_security_groups(self, regions, remediate=False):
        """Audits EC2 Security Groups for open SSH (Port 22) across specified regions and remediates open rules."""
        findings = []
        logger.info(f"Starting EC2 Security Groups audit for regions: {regions}...")

        for region in regions:
            logger.info(f"Scanning EC2 Security Groups in region: {region}...")
            try:
                regional_ec2 = self.session.client('ec2', region_name=region, config=self.botocore_config)
                paginator = regional_ec2.get_paginator('describe_security_groups')
                pages = paginator.paginate()
            except ClientError as e:
                logger.error(f"Failed to scan EC2 Security Groups in region {region}: {e}")
                continue

            for page in pages:
                for sg in page.get('SecurityGroups', []):
                    group_id = sg['GroupId']
                    group_name = sg['GroupName']
                    failed_ports = set()

                    ports_to_check = self.config.get('ec2', {}).get('ports_to_check', [
                        {"port": 22, "protocol": "tcp", "severity": "Critical"}
                    ])

                    for rule in sg.get('IpPermissions', []):
                        from_port = rule.get('FromPort')
                        to_port = rule.get('ToPort')
                        ip_protocol = rule.get('IpProtocol')

                        for target in ports_to_check:
                            target_port = target.get('port')
                            target_proto = target.get('protocol', 'tcp')
                            target_severity = target.get('severity', 'High')

                            port_exposed = False
                            # Check if protocol matches or rule protocol is all ('-1')
                            protocol_match = (ip_protocol == '-1') or (ip_protocol == target_proto)

                            if protocol_match:
                                if from_port is not None and to_port is not None:
                                    if from_port <= target_port <= to_port:
                                        port_exposed = True
                                elif ip_protocol == '-1':
                                    port_exposed = True

                            if port_exposed:
                                for ip in rule.get('IpRanges', []):
                                    if ip.get('CidrIp') == '0.0.0.0/0':
                                        logger.warning(f"❌ SG {group_name} ({group_id}) [{region}]: Port {target_port} ({target_proto}) is OPEN to everyone!")
                                        failed_ports.add(target_port)

                                        remediation_status = "N/A"
                                        if remediate:
                                            if self.dry_run:
                                                logger.info(f"[DRY-RUN] Would revoke Port {target_port} open rule from '0.0.0.0/0' for SG {group_name} ({group_id})")
                                                remediation_status = f"Dry-Run: Revoke Port {target_port} open to public"
                                            else:
                                                try:
                                                    logger.info(f"Remediating SG {group_name} ({group_id}): Revoking Port {target_port} public ingress rule...")
                                                    # Build exact rule to revoke
                                                    rule_to_revoke = {
                                                        'IpProtocol': rule.get('IpProtocol'),
                                                        'FromPort': rule.get('FromPort'),
                                                        'ToPort': rule.get('ToPort'),
                                                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                                                    }
                                                    if from_port is None:
                                                        del rule_to_revoke['FromPort']
                                                    if to_port is None:
                                                        del rule_to_revoke['ToPort']

                                                    regional_ec2.revoke_security_group_ingress(
                                                        GroupId=group_id,
                                                        IpPermissions=[rule_to_revoke]
                                                    )
                                                    logger.info(f"✅ SG {group_name} ({group_id}): Successfully Remediated Port {target_port}")
                                                    remediation_status = "Remediated"
                                                except ClientError as re:
                                                    logger.error(f"Failed to remediate SG {group_name} ({group_id}) for Port {target_port}: {re}")
                                                    remediation_status = f"Remediation Failed: {re.response['Error']['Message']}"
                                        else:
                                            remediation_status = "None (Remediation not requested)"

                                        findings.append({
                                            "Service": "EC2",
                                            "Region": region,
                                            "ResourceID": group_id,
                                            "ResourceName": group_name,
                                            "Status": "FAIL",
                                            "Finding": f"Port {target_port} ({target_proto.upper()}) is open to the public internet (0.0.0.0/0)",
                                            "Severity": target_severity,
                                            "RemediationStatus": remediation_status
                                        })

                    for target in ports_to_check:
                        target_port = target.get('port')
                        target_proto = target.get('protocol', 'tcp')
                        if target_port not in failed_ports:
                            findings.append({
                                "Service": "EC2",
                                "Region": region,
                                "ResourceID": group_id,
                                "ResourceName": group_name,
                                "Status": "PASS",
                                "Finding": f"Port {target_port} ({target_proto.upper()}) is restricted",
                                "Severity": "Low",
                                "RemediationStatus": "N/A"
                            })
        return findings

def print_table(findings):
    """Formats and prints findings as a text table."""
    if not findings:
        logger.info("No findings to display.")
        return

    headers = ["Service", "Region", "ResourceID", "Status", "Severity", "RemediationStatus", "Finding"]
    widths = {h: len(h) for h in headers}

    for f in findings:
        for h in headers:
            val = str(f.get(h, ''))
            if len(val) > widths[h]:
                widths[h] = len(val)

    row_format = " | ".join([f"{{:<{widths[h]}}}" for h in headers])
    border = "-+-".join(["-" * widths[h] for h in headers])

    print("\n" + border)
    print(row_format.format(*headers))
    print(border)
    for f in findings:
        print(row_format.format(*[str(f.get(h, '')) for h in headers]))
    print(border + "\n")

def export_findings(findings, filename, fmt):
    """Exports findings to a file in the specified format."""
    try:
        fields = ["Service", "Region", "ResourceID", "ResourceName", "Status", "Severity", "RemediationStatus", "Finding"]
        if fmt == "json":
            with open(filename, 'w') as f:
                json.dump(findings, f, indent=4)
        elif fmt == "csv":
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for r in findings:
                    row = {k: r.get(k, '') for k in fields}
                    writer.writerow(row)
        elif fmt == "table":
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            print_table(findings)
            table_content = sys.stdout.getvalue()
            sys.stdout = old_stdout
            with open(filename, 'w') as f:
                f.write(table_content)
        logger.info(f"Report successfully saved to {filename} in {fmt.upper()} format.")
    except Exception as e:
        logger.error(f"Failed to export report to {filename}: {e}")

def send_slack_notification(webhook_url, findings):
    """Sends failed findings alert to Slack webhook."""
    failed = [f for f in findings if f["Status"] == "FAIL"]
    if not failed:
        logger.info("No compliance failures detected. Skipping Slack notification.")
        return

    text = f"🚨 *AWS Sentinel Security Alert*\nAudit completed with *{len(failed)}* compliance failures."
    blocks = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": text}
        },
        {"type": "divider"}
    ]

    for f in failed[:10]:
        item_text = (
            f"• *{f['Service']}* | {f['Region']} | *{f['Severity']}*\n"
            f"  Resource: `{f['ResourceID']}`\n"
            f"  Finding: {f['Finding']}\n"
            f"  Remediation: `{f['RemediationStatus']}`"
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": item_text}
        })

    if len(failed) > 10:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"...and {len(failed) - 10} more findings."}
        })

    payload = {"blocks": blocks}

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                logger.info("Slack notification sent successfully.")
            else:
                logger.error(f"Failed to send Slack notification: Status {response.status}")
    except Exception as e:
        logger.error(f"Error sending Slack notification: {e}")

def send_teams_notification(webhook_url, findings):
    """Sends failed findings alert to Microsoft Teams webhook."""
    failed = [f for f in findings if f["Status"] == "FAIL"]
    if not failed:
        logger.info("No compliance failures detected. Skipping MS Teams notification.")
        return

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "D70000",
        "summary": "AWS Sentinel Security Alert",
        "title": "🚨 AWS Sentinel Security Compliance Alerts",
        "text": f"Audit completed with **{len(failed)}** compliance failures.",
        "sections": []
    }

    section = {
        "activityTitle": "Critical & High Severity Findings",
        "facts": []
    }

    for f in failed[:15]:
        section["facts"].append({
            "name": f"{f['Service']} ({f['Region']}) - {f['Severity']}",
            "value": f"**Resource:** `{f['ResourceID']}`\n**Finding:** {f['Finding']}\n**Remediation:** {f['RemediationStatus']}"
        })

    payload["sections"].append(section)

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as response:
            if response.status in [200, 201]:
                logger.info("MS Teams notification sent successfully.")
            else:
                logger.error(f"Failed to send MS Teams notification: Status {response.status}")
    except Exception as e:
        logger.error(f"Error sending MS Teams notification: {e}")

def main():
    parser = argparse.ArgumentParser(description="AWS Sentinel: Automated Security Compliance Auditor")
    parser.add_argument(
        "--services",
        nargs="+",
        choices=["s3", "iam", "ec2"],
        default=["s3", "iam", "ec2"],
        help="AWS services to audit (default: all)"
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=[],
        help="AWS regions to scan (e.g. us-east-1 us-west-2). Use 'all' to scan all active regions. Default: session region."
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help="Attempt auto-remediation of detected compliance failures."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate remediation actions without applying them (must be used with --remediate)."
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "--output-file",
        help="Path to save the findings report"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set the logging level (default: INFO)"
    )
    parser.add_argument(
        "--slack-webhook",
        help="Slack Webhook URL to send alert notifications for compliance failures"
    )
    parser.add_argument(
        "--teams-webhook",
        help="Microsoft Teams Webhook URL to send alert notifications for compliance failures"
    )
    parser.add_argument(
        "--config",
        help="Path to YAML/JSON configuration file"
    )
    parser.add_argument(
        "--profile",
        help="AWS profile name to use for authentication"
    )
    parser.add_argument(
        "--json-logging",
        action="store_true",
        help="Output logs in structured JSON format"
    )
    args = parser.parse_args()

    setup_logging(args.log_level, json_format=args.json_logging)
    logger.info("AWS Sentinel auditor initialized.")

    if args.dry_run and not args.remediate:
        logger.warning("--dry-run specified without --remediate. It will have no effect on audit findings.")

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else None
    except ProfileNotFound as e:
        logger.error(f"AWS Profile Error: {e}")
        sys.exit(1)

    auditor = AWSSentinelAuditor(session=session, dry_run=args.dry_run, config_path=args.config)

    # Determine regions to scan
    scan_regions = []
    if "ec2" in args.services:
        if not args.regions:
            session_region = auditor.session.region_name or 'us-east-1'
            scan_regions = [session_region]
        elif 'all' in [r.lower() for r in args.regions]:
            scan_regions = auditor.get_active_regions()
        else:
            scan_regions = args.regions

    all_findings = []

    if "s3" in args.services:
        all_findings.extend(auditor.audit_s3(remediate=args.remediate))
    if "iam" in args.services:
        all_findings.extend(auditor.audit_iam(remediate=args.remediate))
    if "ec2" in args.services:
        all_findings.extend(auditor.audit_security_groups(scan_regions, remediate=args.remediate))

    failed_count = sum(1 for f in all_findings if f["Status"] == "FAIL")
    logger.info(f"Audit completed. Total findings: {len(all_findings)}. Failures found: {failed_count}.")

    if args.output_file:
        export_findings(all_findings, args.output_file, args.format)
    else:
        if args.format == "table":
            print_table(all_findings)
        elif args.format == "json":
            print(json.dumps(all_findings, indent=4))
        elif args.format == "csv":
            output = io.StringIO()
            fields = ["Service", "Region", "ResourceID", "ResourceName", "Status", "Severity", "RemediationStatus", "Finding"]
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for r in all_findings:
                row = {k: r.get(k, '') for k in fields}
                writer.writerow(row)
            print(output.getvalue())

    if args.slack_webhook:
        send_slack_notification(args.slack_webhook, all_findings)
    if args.teams_webhook:
        send_teams_notification(args.teams_webhook, all_findings)

def lambda_handler(event, context):
    """AWS Lambda entrypoint handler."""
    import os
    logger.info("AWS Sentinel auditor triggered via Lambda.")
    dry_run = os.environ.get("DRY_RUN", "False").lower() in ["true", "1", "yes"]
    slack_webhook = os.environ.get("SLACK_WEBHOOK")
    teams_webhook = os.environ.get("TEAMS_WEBHOOK")

    config_file = os.environ.get("CONFIG_FILE", "config.yaml")
    config_path = config_file if os.path.exists(config_file) else None

    auditor = AWSSentinelAuditor(dry_run=dry_run, config_path=config_path)

    scan_regions = auditor.get_active_regions()

    all_findings = []
    all_findings.extend(auditor.audit_s3(remediate=True))
    all_findings.extend(auditor.audit_iam(remediate=True))
    all_findings.extend(auditor.audit_security_groups(scan_regions, remediate=True))

    failed_count = sum(1 for f in all_findings if f["Status"] == "FAIL")
    logger.info(f"Lambda Audit completed. Total findings: {len(all_findings)}. Failures found: {failed_count}.")

    if slack_webhook:
        send_slack_notification(slack_webhook, all_findings)
    if teams_webhook:
        send_teams_notification(teams_webhook, all_findings)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "total_findings": len(all_findings),
            "failures": failed_count
        })
    }

if __name__ == "__main__":
    main()
