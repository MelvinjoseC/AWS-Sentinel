import boto3

def audit_s3():
    print("\n--- Scanning S3 Buckets ---")
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    for b in buckets:
        name = b['Name']
        try:
            public_access = s3.get_public_access_block(Bucket=name)
            print(f"✅ {name}: Secure (Public Access Blocked)")
        except:
            print(f"❌ {name}: WARNING - Public Access NOT Blocked!")

def audit_iam():
    print("\n--- Scanning IAM Users for MFA ---")
    iam = boto3.client('iam')
    users = iam.list_users()['Users']
    for u in users:
        mfa = iam.list_mfa_devices(UserName=u['UserName'])['MFADevices']
        if not mfa:
            print(f"❌ {u['UserName']}: MFA is DISABLED!")
        else:
            print(f"✅ {u['UserName']}: MFA is Active.")

def audit_security_groups():
    print("\n--- Scanning Security Groups for Open SSH (Port 22) ---")
    ec2 = boto3.client('ec2')
    groups = ec2.describe_security_groups()['SecurityGroups']
    for sg in groups:
        for rule in sg['IpPermissions']:
            if rule.get('FromPort') == 22:
                for ip in rule['IpRanges']:
                    if ip['CidrIp'] == '0.0.0.0/0':
                        print(f"❌ SG {sg['GroupId']} ({sg['GroupName']}): Port 22 is OPEN to everyone!")

if __name__ == "__main__":
    # Ensure you have 'aws configure' set up before running
    audit_s3()
    audit_iam()
    audit_security_groups()