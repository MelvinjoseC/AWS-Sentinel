from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

from sentinel import AWSSentinelAuditor, send_slack_notification, send_teams_notification


@mock_aws
def test_audit_s3_secure_and_insecure():
    # Setup mock S3
    s3 = boto3.client('s3', region_name='us-east-1')

    # Bucket 1: no public access block (insecure)
    s3.create_bucket(Bucket='insecure-bucket')

    # Bucket 2: public access block (secure)
    s3.create_bucket(Bucket='secure-bucket')
    s3.put_public_access_block(
        Bucket='secure-bucket',
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

    auditor = AWSSentinelAuditor()
    auditor.config['s3']['check_encryption'] = False
    auditor.config['s3']['check_versioning'] = False
    findings = auditor.audit_s3(remediate=False)

    # Assertions
    assert len(findings) == 2

    insecure_finding = next(f for f in findings if f['ResourceID'] == 'insecure-bucket')
    assert insecure_finding['Status'] == 'FAIL'
    assert insecure_finding['Severity'] == 'High'

    secure_finding = next(f for f in findings if f['ResourceID'] == 'secure-bucket')
    assert secure_finding['Status'] == 'PASS'
    assert secure_finding['Severity'] == 'Low'

@mock_aws
def test_audit_s3_remediation():
    s3 = boto3.client('s3', region_name='us-east-1')
    s3.create_bucket(Bucket='remediate-bucket')

    # Run audit with remediation
    auditor = AWSSentinelAuditor()
    auditor.config['s3']['check_encryption'] = False
    auditor.config['s3']['check_versioning'] = False
    findings = auditor.audit_s3(remediate=True)

    assert len(findings) == 1
    assert findings[0]['Status'] == 'FAIL'
    assert findings[0]['RemediationStatus'] == 'Remediated'

    # Verify the bucket is now secure
    pab = s3.get_public_access_block(Bucket='remediate-bucket')
    assert pab['PublicAccessBlockConfiguration']['BlockPublicAcls'] is True

@mock_aws
def test_audit_s3_encryption_and_remediation():
    s3 = boto3.client('s3', region_name='us-east-1')
    
    s3.create_bucket(Bucket='no-encryption-bucket')
    s3.create_bucket(Bucket='encrypted-bucket')
    s3.put_bucket_encryption(
        Bucket='encrypted-bucket',
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
    
    auditor = AWSSentinelAuditor()
    auditor.config['s3']['check_versioning'] = False
    
    findings = auditor.audit_s3(remediate=False)
    enc_findings = [f for f in findings if "encryption" in f['Finding'].lower()]
    assert len(enc_findings) == 2
    
    no_enc_finding = next(f for f in enc_findings if f['ResourceID'] == 'no-encryption-bucket')
    assert no_enc_finding['Status'] == 'FAIL'
    
    enc_finding = next(f for f in enc_findings if f['ResourceID'] == 'encrypted-bucket')
    assert enc_finding['Status'] == 'PASS'
    
    findings_rem = auditor.audit_s3(remediate=True)
    no_enc_finding_rem = next(f for f in findings_rem if f['ResourceID'] == 'no-encryption-bucket' and "encryption" in f['Finding'].lower())
    assert no_enc_finding_rem['RemediationStatus'] == 'Remediated'
    
    enc_config = s3.get_bucket_encryption(Bucket='no-encryption-bucket')
    assert enc_config['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'AES256'

@mock_aws
def test_audit_s3_versioning_and_remediation():
    s3 = boto3.client('s3', region_name='us-east-1')
    
    s3.create_bucket(Bucket='no-versioning-bucket')
    s3.create_bucket(Bucket='versioned-bucket')
    s3.put_bucket_versioning(
        Bucket='versioned-bucket',
        VersioningConfiguration={'Status': 'Enabled'}
    )
    
    auditor = AWSSentinelAuditor()
    auditor.config['s3']['check_encryption'] = False
    
    findings = auditor.audit_s3(remediate=False)
    ver_findings = [f for f in findings if "versioning" in f['Finding'].lower()]
    assert len(ver_findings) == 2
    
    no_ver_finding = next(f for f in ver_findings if f['ResourceID'] == 'no-versioning-bucket')
    assert no_ver_finding['Status'] == 'FAIL'
    
    ver_finding = next(f for f in ver_findings if f['ResourceID'] == 'versioned-bucket')
    assert ver_finding['Status'] == 'PASS'
    
    findings_rem = auditor.audit_s3(remediate=True)
    no_ver_finding_rem = next(f for f in findings_rem if f['ResourceID'] == 'no-versioning-bucket' and "versioning" in f['Finding'].lower())
    assert no_ver_finding_rem['RemediationStatus'] == 'Remediated'
    
    ver_status = s3.get_bucket_versioning(Bucket='no-versioning-bucket')
    assert ver_status['Status'] == 'Enabled'

@mock_aws
def test_audit_iam():
    iam = boto3.client('iam')

    # User 1: No MFA (insecure)
    iam.create_user(UserName='insecure-user')

    # User 2: With MFA (secure)
    iam.create_user(UserName='secure-user')
    mfa_response = iam.create_virtual_mfa_device(VirtualMFADeviceName='secure-user-mfa')
    serial = mfa_response['VirtualMFADevice']['SerialNumber']
    iam.enable_mfa_device(
        UserName='secure-user',
        SerialNumber=serial,
        AuthenticationCode1='123456',
        AuthenticationCode2='789012'
    )
    
    # Setup compliant password policy
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True
    )

    auditor = AWSSentinelAuditor()
    findings = auditor.audit_iam(remediate=False)

    assert len(findings) == 3

    insecure_finding = next(f for f in findings if f['ResourceName'] == 'insecure-user')
    assert insecure_finding['Status'] == 'FAIL'

    secure_finding = next(f for f in findings if f['ResourceName'] == 'secure-user')
    assert secure_finding['Status'] == 'PASS'
    
    pwd_finding = next(f for f in findings if f['ResourceID'] == 'AccountPasswordPolicy')
    assert pwd_finding['Status'] == 'PASS'

@mock_aws
def test_audit_iam_access_key_age():
    iam = boto3.client('iam')
    username = 'key-test-user'
    iam.create_user(UserName=username)
    
    key_response = iam.create_access_key(UserName=username)
    key_id = key_response['AccessKey']['AccessKeyId']
    
    # Non-compliant key age
    auditor = AWSSentinelAuditor()
    auditor.config['iam']['max_access_key_age_days'] = -1
    with patch.object(auditor, 'audit_iam_password_policy', return_value=[]):
        findings = auditor.audit_iam(remediate=False)
        key_findings = [f for f in findings if f['ResourceID'] == key_id]
        assert len(key_findings) == 1
        assert key_findings[0]['Status'] == 'FAIL'
        assert "older than" in key_findings[0]['Finding'].lower()

    # Compliant key age
    auditor2 = AWSSentinelAuditor()
    auditor2.config['iam']['max_access_key_age_days'] = 90
    with patch.object(auditor2, 'audit_iam_password_policy', return_value=[]):
        findings2 = auditor2.audit_iam(remediate=False)
        key_findings2 = [f for f in findings2 if f['ResourceID'] == key_id]
        assert len(key_findings2) == 1
        assert key_findings2[0]['Status'] == 'PASS'

@mock_aws
def test_audit_iam_password_policy_non_compliant():
    iam = boto3.client('iam')
    
    iam.update_account_password_policy(
        MinimumPasswordLength=6,
        RequireSymbols=False,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True
    )
    
    auditor = AWSSentinelAuditor()
    findings = auditor.audit_iam_password_policy()
    assert len(findings) == 1
    assert findings[0]['Status'] == 'FAIL'
    assert "non-compliant" in findings[0]['Finding'].lower()

@mock_aws
def test_audit_iam_password_policy_missing():
    auditor = AWSSentinelAuditor()
    findings = auditor.audit_iam_password_policy()
    assert len(findings) == 1
    assert findings[0]['Status'] == 'FAIL'
    assert "no iam password policy is defined" in findings[0]['Finding'].lower()

@mock_aws
def test_audit_security_groups_and_remediation():
    ec2 = boto3.client('ec2', region_name='us-east-1')

    # Create VPC
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    vpc_id = vpc['Vpc']['VpcId']

    # Insecure security group (open SSH)
    sg_insecure = ec2.create_security_group(
        GroupName='insecure-sg',
        Description='Allow SSH from everywhere',
        VpcId=vpc_id
    )
    sg_insecure_id = sg_insecure['GroupId']

    ec2.authorize_security_group_ingress(
        GroupId=sg_insecure_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )

    # Secure security group
    ec2.create_security_group(
        GroupName='secure-sg',
        Description='No public SSH',
        VpcId=vpc_id
    )

    # Audit EC2 SGs (dry-run remediation)
    auditor = AWSSentinelAuditor(dry_run=True)
    findings = auditor.audit_security_groups(regions=['us-east-1'], remediate=True)

    insecure_finding = next(f for f in findings if f['ResourceID'] == sg_insecure_id)
    assert insecure_finding['Status'] == 'FAIL'
    assert insecure_finding['RemediationStatus'] == 'Dry-Run: Revoke Port 22 open to public'

    # Audit and Remediate (actually revoke)
    auditor_real = AWSSentinelAuditor(dry_run=False)
    findings_real = auditor_real.audit_security_groups(regions=['us-east-1'], remediate=True)

    insecure_finding_real = next(f for f in findings_real if f['ResourceID'] == sg_insecure_id)
    assert insecure_finding_real['Status'] == 'FAIL'
    assert insecure_finding_real['RemediationStatus'] == 'Remediated'

    # Re-describe security groups and verify rule is revoked
    sg_details = ec2.describe_security_groups(GroupIds=[sg_insecure_id])['SecurityGroups'][0]
    rules = sg_details['IpPermissions']
    port_22_exposed = False
    for rule in rules:
        if rule.get('FromPort') == 22:
            for ip in rule.get('IpRanges', []):
                if ip.get('CidrIp') == '0.0.0.0/0':
                    port_22_exposed = True
    assert not port_22_exposed


def test_send_slack_notification_no_failures():
    findings = [
        {"Service": "S3", "Status": "PASS", "ResourceID": "b1", "Region": "global", "Finding": "Secure", "Severity": "Low", "RemediationStatus": "N/A"}
    ]
    with patch('urllib.request.urlopen') as mock_urlopen:
        send_slack_notification("http://mock-webhook", findings)
        mock_urlopen.assert_not_called()

def test_send_slack_notification_with_failures():
    findings = [
        {"Service": "S3", "Status": "FAIL", "ResourceID": "b1", "Region": "global", "Finding": "Insecure", "Severity": "High", "RemediationStatus": "None"}
    ]
    mock_response = MagicMock()
    mock_response.status = 200
    with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
        send_slack_notification("http://mock-webhook", findings)
        mock_urlopen.assert_called_once()
        args, kwargs = mock_urlopen.call_args
        req = args[0]
        assert req.full_url == "http://mock-webhook"
        assert req.get_header("Content-type") == "application/json"

def test_send_teams_notification_no_failures():
    findings = [
        {"Service": "S3", "Status": "PASS", "ResourceID": "b1", "Region": "global", "Finding": "Secure", "Severity": "Low", "RemediationStatus": "N/A"}
    ]
    with patch('urllib.request.urlopen') as mock_urlopen:
        send_teams_notification("http://mock-webhook", findings)
        mock_urlopen.assert_not_called()

def test_send_teams_notification_with_failures():
    findings = [
        {"Service": "S3", "Status": "FAIL", "ResourceID": "b1", "Region": "global", "Finding": "Insecure", "Severity": "High", "RemediationStatus": "None"}
    ]
    mock_response = MagicMock()
    mock_response.status = 200
    with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
        send_teams_notification("http://mock-webhook", findings)
        mock_urlopen.assert_called_once()
        args, kwargs = mock_urlopen.call_args
        req = args[0]
        assert req.full_url == "http://mock-webhook"
        assert req.get_header("Content-type") == "application/json"

@mock_aws
def test_audit_security_groups_custom_ports():
    ec2 = boto3.client('ec2', region_name='us-east-1')
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    vpc_id = vpc['Vpc']['VpcId']
    
    sg = ec2.create_security_group(
        GroupName='custom-sg',
        Description='Allow RDP and FTP',
        VpcId=vpc_id
    )
    sg_id = sg['GroupId']
    
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 3389,
                'ToPort': 3389,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 21,
                'ToPort': 21,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    
    auditor = AWSSentinelAuditor()
    auditor.config['ec2']['ports_to_check'] = [
        {"port": 3389, "protocol": "tcp", "severity": "Critical"},
        {"port": 21, "protocol": "tcp", "severity": "High"},
        {"port": 80, "protocol": "tcp", "severity": "Medium"}
    ]
    
    findings = auditor.audit_security_groups(regions=['us-east-1'], remediate=False)
    custom_findings = [f for f in findings if f['ResourceID'] == sg_id]
    
    assert len(custom_findings) == 3
    
    rdp_finding = next(f for f in custom_findings if "3389" in f['Finding'])
    assert rdp_finding['Status'] == 'FAIL'
    assert rdp_finding['Severity'] == 'Critical'
    
    ftp_finding = next(f for f in custom_findings if "21" in f['Finding'])
    assert ftp_finding['Status'] == 'FAIL'
    assert ftp_finding['Severity'] == 'High'
    
    http_finding = next(f for f in custom_findings if "80" in f['Finding'])
    assert http_finding['Status'] == 'PASS'

def test_json_logging_formatter():
    import io
    import logging
    import json
    from sentinel import setup_logging, JSONFormatter
    
    log_capture = io.StringIO()
    root_logger = logging.getLogger()
    
    old_level = root_logger.level
    old_handlers = root_logger.handlers[:]
    
    for h in old_handlers:
        root_logger.removeHandler(h)
        
    handler = logging.StreamHandler(log_capture)
    handler.setFormatter(JSONFormatter())
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)
    
    test_logger = logging.getLogger("test-json-logger")
    test_logger.info("This is a test message")
    
    root_logger.removeHandler(handler)
    for h in old_handlers:
        root_logger.addHandler(h)
    root_logger.setLevel(old_level)
    
    log_content = log_capture.getvalue().strip()
    parsed = json.loads(log_content)
    assert parsed['logger'] == 'test-json-logger'
    assert parsed['level'] == 'INFO'
    assert parsed['message'] == 'This is a test message'
    assert 'timestamp' in parsed
