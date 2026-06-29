import pytest
import boto3
from moto import mock_s3, mock_iam, mock_ec2
from sentinel import AWSSentinelAuditor

@mock_s3
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
    findings = auditor.audit_s3(remediate=False)
    
    # Assertions
    assert len(findings) == 2
    
    insecure_finding = next(f for f in findings if f['ResourceID'] == 'insecure-bucket')
    assert insecure_finding['Status'] == 'FAIL'
    assert insecure_finding['Severity'] == 'High'
    
    secure_finding = next(f for f in findings if f['ResourceID'] == 'secure-bucket')
    assert secure_finding['Status'] == 'PASS'
    assert secure_finding['Severity'] == 'Low'

@mock_s3
def test_audit_s3_remediation():
    s3 = boto3.client('s3', region_name='us-east-1')
    s3.create_bucket(Bucket='remediate-bucket')
    
    # Run audit with remediation
    auditor = AWSSentinelAuditor()
    findings = auditor.audit_s3(remediate=True)
    
    assert len(findings) == 1
    assert findings[0]['Status'] == 'FAIL'
    assert findings[0]['RemediationStatus'] == 'Remediated'
    
    # Verify the bucket is now secure
    pab = s3.get_public_access_block(Bucket='remediate-bucket')
    assert pab['PublicAccessBlockConfiguration']['BlockPublicAcls'] is True

@mock_iam
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
    
    auditor = AWSSentinelAuditor()
    findings = auditor.audit_iam(remediate=False)
    
    assert len(findings) == 2
    
    insecure_finding = next(f for f in findings if f['ResourceName'] == 'insecure-user')
    assert insecure_finding['Status'] == 'FAIL'
    
    secure_finding = next(f for f in findings if f['ResourceName'] == 'secure-user')
    assert secure_finding['Status'] == 'PASS'

@mock_ec2
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
    sg_secure = ec2.create_security_group(
        GroupName='secure-sg',
        Description='No public SSH',
        VpcId=vpc_id
    )
    sg_secure_id = sg_secure['GroupId']
    
    # Audit EC2 SGs (dry-run remediation)
    auditor = AWSSentinelAuditor(dry_run=True)
    findings = auditor.audit_security_groups(regions=['us-east-1'], remediate=True)
    
    assert len(findings) == 2
    
    insecure_finding = next(f for f in findings if f['ResourceID'] == sg_insecure_id)
    assert insecure_finding['Status'] == 'FAIL'
    assert insecure_finding['RemediationStatus'] == 'Dry-Run: Revoke SSH open to public'
    
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
