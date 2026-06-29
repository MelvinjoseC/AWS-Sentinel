import argparse
import logging
import sys
import boto3
from botocore.exceptions import ClientError

# Setup logging
def setup_logging(level):
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=level, format=log_format)

logger = logging.getLogger("aws-sentinel")

class AWSSentinelAuditor:
    def __init__(self, session=None):
        self.session = session or boto3.Session()
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

    def audit_s3(self):
        """Audits S3 buckets for Public Access Block settings."""
        logger.info("Starting S3 bucket audit...")
        findings = []
        try:
            buckets = self.s3_client.list_buckets().get('Buckets', [])
        except ClientError as e:
            logger.error(f"Failed to list S3 buckets: {e}")
            return findings

        for bucket in buckets:
            name = bucket['Name']
            try:
                self.s3_client.get_public_access_block(Bucket=name)
                logger.info(f"✅ S3 Bucket '{name}': Secure (Public Access Blocked)")
                findings.append({
                    "Service": "S3",
                    "ResourceID": name,
                    "ResourceName": name,
                    "Status": "PASS",
                    "Finding": "Public Access Block is enabled",
                    "Severity": "Low",
                    "Region": "global"
                })
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    logger.warning(f"❌ S3 Bucket '{name}': WARNING - Public Access NOT Blocked!")
                    findings.append({
                        "Service": "S3",
                        "ResourceID": name,
                        "ResourceName": name,
                        "Status": "FAIL",
                        "Finding": "Public Access Block is not enabled",
                        "Severity": "High",
                        "Region": "global"
                    })
                else:
                    logger.error(f"Error checking public access block for bucket '{name}': {e}")
                    findings.append({
                        "Service": "S3",
                        "ResourceID": name,
                        "ResourceName": name,
                        "Status": "ERROR",
                        "Finding": f"Failed to retrieve configuration: {e.response['Error']['Message']}",
                        "Severity": "Medium",
                        "Region": "global"
                    })
        return findings

    def audit_iam(self):
        """Audits IAM users for MFA compliance using pagination."""
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
                try:
                    mfa_devices = self.iam_client.list_mfa_devices(UserName=username).get('MFADevices', [])
                    if not mfa_devices:
                        logger.warning(f"❌ IAM User '{username}': MFA is DISABLED!")
                        findings.append({
                            "Service": "IAM",
                            "ResourceID": user['Arn'],
                            "ResourceName": username,
                            "Status": "FAIL",
                            "Finding": "Multi-Factor Authentication (MFA) is disabled",
                            "Severity": "High",
                            "Region": "global"
                        })
                    else:
                        logger.info(f"✅ IAM User '{username}': MFA is Active")
                        findings.append({
                            "Service": "IAM",
                            "ResourceID": user['Arn'],
                            "ResourceName": username,
                            "Status": "PASS",
                            "Finding": "Multi-Factor Authentication (MFA) is active",
                            "Severity": "Low",
                            "Region": "global"
                        })
                except ClientError as e:
                    logger.error(f"Error checking MFA for user '{username}': {e}")
                    findings.append({
                        "Service": "IAM",
                        "ResourceID": user['Arn'],
                        "ResourceName": username,
                        "Status": "ERROR",
                        "Finding": f"Failed to retrieve MFA devices: {e.response['Error']['Message']}",
                        "Severity": "Medium",
                        "Region": "global"
                    })
        return findings

    def audit_security_groups(self, regions):
        """Audits EC2 Security Groups for open SSH (Port 22) across specified regions with pagination."""
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

                    for rule in sg.get('IpPermissions', []):
                        from_port = rule.get('FromPort')
                        to_port = rule.get('ToPort')
                        
                        # Check if SSH (Port 22) is included in the port range
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
                                    findings.append({
                                        "Service": "EC2",
                                        "ResourceID": group_id,
                                        "ResourceName": group_name,
                                        "Status": "FAIL",
                                        "Finding": "Port 22 (SSH) is open to the public internet (0.0.0.0/0)",
                                        "Severity": "Critical",
                                        "Region": region
                                    })

                    if is_secure:
                        logger.debug(f"✅ SG {group_name} ({group_id}) [{region}]: Port 22 is not publicly open")
                        findings.append({
                            "Service": "EC2",
                            "ResourceID": group_id,
                            "ResourceName": group_name,
                            "Status": "PASS",
                            "Finding": "Port 22 (SSH) is restricted",
                            "Severity": "Low",
                            "Region": region
                        })
        return findings

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
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set the logging level (default: INFO)"
    )
    args = parser.parse_args()

    setup_logging(args.log_level)
    logger.info("AWS Sentinel auditor initialized.")

    auditor = AWSSentinelAuditor()
    
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
        all_findings.extend(auditor.audit_s3())
    if "iam" in args.services:
        all_findings.extend(auditor.audit_iam())
    if "ec2" in args.services:
        all_findings.extend(auditor.audit_security_groups(scan_regions))

    failed_count = sum(1 for f in all_findings if f["Status"] == "FAIL")
    logger.info(f"Audit completed. Total findings: {len(all_findings)}. Failures found: {failed_count}.")

if __name__ == "__main__":
    main()