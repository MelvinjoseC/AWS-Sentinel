import argparse
import logging
import sys
import json
import csv
import io
import boto3
from botocore.exceptions import ClientError

# Setup logging
def setup_logging(level):
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=level, format=log_format)

logger = logging.getLogger("aws-sentinel")

class AWSSentinelAuditor:
    def __init__(self, session=None, dry_run=False):
        self.session = session or boto3.Session()
        self.dry_run = dry_run
        self.s3_client = self.session.client('s3')
        self.iam_client = self.session.client('iam')
        # EC2 client for default region to discover active regions
        default_region = self.session.region_name or 'us-east-1'
        self.ec2_client = self.session.client('ec2', region_name=default_region)

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
        return findings

    def audit_security_groups(self, regions, remediate=False):
        """Audits EC2 Security Groups for open SSH (Port 22) across specified regions and remediates open rules."""
        findings = []
        logger.info(f"Starting EC2 Security Groups audit for regions: {regions}...")

        for region in regions:
            logger.info(f"Scanning EC2 Security Groups in region: {region}...")
            try:
                regional_ec2 = self.session.client('ec2', region_name=region)
                paginator = regional_ec2.get_paginator('describe_security_groups')
                pages = paginator.paginate()
            except ClientError as e:
                logger.error(f"Failed to scan EC2 Security Groups in region {region}: {e}")
                continue

            for page in pages:
                for sg in page.get('SecurityGroups', []):
                    group_id = sg['GroupId']
                    group_name = sg['GroupName']
                    is_secure = True
                    remediation_status = "N/A"

                    for rule in sg.get('IpPermissions', []):
                        from_port = rule.get('FromPort')
                        to_port = rule.get('ToPort')
                        
                        port_22_exposed = False
                        if from_port is not None and to_port is not None:
                            if from_port <= 22 <= to_port:
                                port_22_exposed = True
                        elif rule.get('IpProtocol') == '-1': # All protocols
                            port_22_exposed = True

                        if port_22_exposed:
                            for ip in rule.get('IpRanges', []):
                                if ip.get('CidrIp') == '0.0.0.0/0':
                                    logger.warning(f"❌ SG {group_name} ({group_id}) [{region}]: Port 22 is OPEN to everyone!")
                                    is_secure = False
                                    
                                    if remediate:
                                        if self.dry_run:
                                            logger.info(f"[DRY-RUN] Would revoke Port 22 open rule from '0.0.0.0/0' for SG {group_name} ({group_id})")
                                            remediation_status = "Dry-Run: Revoke SSH open to public"
                                        else:
                                            try:
                                                logger.info(f"Remediating SG {group_name} ({group_id}): Revoking Port 22 public ingress rule...")
                                                # Build exact rule to revoke
                                                rule_to_revoke = {
                                                    'IpProtocol': rule.get('IpProtocol'),
                                                    'FromPort': rule.get('FromPort'),
                                                    'ToPort': rule.get('ToPort'),
                                                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                                                }
                                                # Handle case where ports might be None for protocol '-1'
                                                if from_port is None:
                                                    del rule_to_revoke['FromPort']
                                                if to_port is None:
                                                    del rule_to_revoke['ToPort']
                                                    
                                                regional_ec2.revoke_security_group_ingress(
                                                    GroupId=group_id,
                                                    IpPermissions=[rule_to_revoke]
                                                )
                                                logger.info(f"✅ SG {group_name} ({group_id}): Successfully Remediated")
                                                remediation_status = "Remediated"
                                            except ClientError as re:
                                                logger.error(f"Failed to remediate SG {group_name} ({group_id}): {re}")
                                                remediation_status = f"Remediation Failed: {re.response['Error']['Message']}"
                                    else:
                                        remediation_status = "None (Remediation not requested)"

                                    findings.append({
                                        "Service": "EC2",
                                        "Region": region,
                                        "ResourceID": group_id,
                                        "ResourceName": group_name,
                                        "Status": "FAIL",
                                        "Finding": "Port 22 (SSH) is open to the public internet (0.0.0.0/0)",
                                        "Severity": "Critical",
                                        "RemediationStatus": remediation_status
                                    })

                    if is_secure:
                        logger.debug(f"✅ SG {group_name} ({group_id}) [{region}]: Port 22 is not publicly open")
                        findings.append({
                            "Service": "EC2",
                            "Region": region,
                            "ResourceID": group_id,
                            "ResourceName": group_name,
                            "Status": "PASS",
                            "Finding": "Port 22 (SSH) is restricted",
                            "Severity": "Low",
                            "RemediationStatus": remediation_status
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
    args = parser.parse_args()

    setup_logging(args.log_level)
    logger.info("AWS Sentinel auditor initialized.")

    if args.dry_run and not args.remediate:
        logger.warning("--dry-run specified without --remediate. It will have no effect on audit findings.")

    auditor = AWSSentinelAuditor(dry_run=args.dry_run)
    
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

if __name__ == "__main__":
    main()