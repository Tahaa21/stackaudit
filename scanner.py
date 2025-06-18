import boto3
from botocore.exceptions import ClientError
from utils.aws_helpers import get_iam_client, get_s3_client, get_sts_client, get_cloudtrail_client, get_guardduty_client

# --- BASE CHECKS ---

def check_iam_admins(profile_name):
    findings = []
    iam = get_iam_client(profile_name)

    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for policy in attached_policies:
                if policy['PolicyArn'] == 'arn:aws:iam::aws:policy/AdministratorAccess':
                    print(f"⚠️  User with admin policy: {username}")
                    findings.append({
                        "Check": "IAM Admin",
                        "Resource": username,
                        "Issue": "Attached to AdministratorAccess policy",
                        "Severity": "High"
                    })
    except ClientError as e:
        findings.append({
            "Check": "IAM Admin",
            "Resource": "IAM",
            "Issue": f"Check Failed: {str(e)}",
            "Severity": "Error"
        })

    if not findings:
        print("✅ User without admin policy: All IAM users checked.")
    return findings

def check_mfa_enabled(profile_name):
    findings = []
    iam = get_iam_client(profile_name)

    try:
        users = iam.list_users()['Users']
        for user in users:
            mfa = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
            if not mfa:
                print(f"⚠️  MFA not enabled for user: {user['UserName']}")
                findings.append({
                    "Check": "MFA",
                    "Resource": user['UserName'],
                    "Issue": "User does not have MFA enabled",
                    "Severity": "Medium"
                })
    except ClientError as e:
        findings.append({
            "Check": "MFA",
            "Resource": "IAM",
            "Issue": f"Check Failed: {str(e)}",
            "Severity": "Error"
        })

    if not findings:
        print("✅ All IAM users have MFA enabled.")
    return findings

def check_cloudtrail_enabled(profile_name):
    findings = []
    ct = get_cloudtrail_client(profile_name)

    try:
        trails = ct.describe_trails()['trailList']
        if not trails:
            print("⚠️  No CloudTrails found.")
            findings.append({
                "Check": "CloudTrail",
                "Resource": "AWS Account",
                "Issue": "No CloudTrail trails found",
                "Severity": "High"
            })
        else:
            print("✅ CloudTrail is enabled.")
    except ClientError as e:
        findings.append({
            "Check": "CloudTrail",
            "Resource": "AWS Account",
            "Issue": f"Check Failed: {str(e)}",
            "Severity": "Error"
        })

    return findings

def check_guardduty_enabled(profile_name):
    findings = []
    gd = get_guardduty_client(profile_name)

    try:
        detectors = gd.list_detectors()['DetectorIds']
        if not detectors:
            print("⚠️  GuardDuty is not enabled.")
            findings.append({
                "Check": "GuardDuty",
                "Resource": "AWS Account",
                "Issue": "GuardDuty is not enabled",
                "Severity": "High"
            })
        else:
            print("✅ GuardDuty is enabled.")
    except ClientError as e:
        findings.append({
            "Check": "GuardDuty",
            "Resource": "AWS Account",
            "Issue": f"Check Failed: {str(e)}",
            "Severity": "Error"
        })

    return findings

def check_root_key_usage(profile_name):
    findings = []
    iam = get_iam_client(profile_name)

    try:
        root_key = iam.get_account_summary()['SummaryMap'].get('AccountAccessKeysPresent', 0)
        if root_key > 0:
            print("⚠️  Root user has active access keys.")
            findings.append({
                "Check": "Root Access Key",
                "Resource": "Root User",
                "Issue": "Root user has active access keys",
                "Severity": "Critical"
            })
        else:
            print("✅ No root access key present.")
    except ClientError as e:
        findings.append({
            "Check": "Root Access Key",
            "Resource": "IAM",
            "Issue": f"Check Failed: {str(e)}",
            "Severity": "Error"
        })

    return findings

# --- PRO FEATURES ---

def check_s3_encryption_enabled_pro(profile_name):
    findings = []
    s3 = get_s3_client(profile_name)

    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings.append({
                        "Check": "S3 Encryption",
                        "Resource": bucket_name,
                        "Issue": "No default encryption configured",
                        "Severity": "Medium"
                    })
    except ClientError as e:
        findings.append({
            "Check": "S3 Encryption",
            "Resource": "S3",
            "Issue": f"Check Failed: {str(e)}",
            "Severity": "Error"
        })

    return findings

def check_inactive_iam_users_pro(profile_name):
    findings = []
    iam = get_iam_client(profile_name)

    try:
        users = iam.list_users()['Users']
        for user in users:
            login_profile = None
            try:
                login_profile = iam.get_login_profile(UserName=user['UserName'])
            except ClientError:
                continue  # user may not have console login
            if login_profile:
                access = iam.get_user(UserName=user['UserName'])['User']
                if 'PasswordLastUsed' not in access:
                    findings.append({
                        "Check": "Inactive IAM User",
                        "Resource": user['UserName'],
                        "Issue": "Never logged in",
                        "Severity": "Low"
                    })
    except ClientError as e:
        findings.append({
            "Check": "Inactive IAM User",
            "Resource": "IAM",
            "Issue": f"Check Failed: {str(e)}",
            "Severity": "Error"
        })

    return findings

def check_password_policy_pro(profile_name):
    findings = []
    iam = get_iam_client(profile_name)

    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
        weak = []
        if not policy.get('RequireSymbols'):
            weak.append("missing symbols")
        if not policy.get('RequireNumbers'):
            weak.append("missing numbers")
        if policy.get('MinimumPasswordLength', 0) < 12:
            weak.append("length < 12")
        if weak:
            findings.append({
                "Check": "Password Policy",
                "Resource": "AWS Account",
                "Issue": f"Weak password policy: {', '.join(weak)}",
                "Severity": "Low"
            })
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            findings.append({
                "Check": "Password Policy",
                "Resource": "AWS Account",
                "Issue": "No password policy configured",
                "Severity": "Medium"
            })
        else:
            findings.append({
                "Check": "Password Policy",
                "Resource": "AWS Account",
                "Issue": f"Check Failed: {str(e)}",
                "Severity": "Error"
            })

    return findings
