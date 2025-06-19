import boto3
from botocore.exceptions import ClientError
from .utils.aws_helpers import (
    get_iam_client,
    get_s3_client,
    get_sts_client,
    get_cloudtrail_client,
    get_guardduty_client,
)


def check_iam_admins(profile_name):
    findings = []
    client = get_iam_client(profile_name)
    paginator = client.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        users.extend(page["Users"])

    for user in users:
        user_name = user["UserName"]
        attached_policies = client.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
        is_admin = any("AdministratorAccess" in policy["PolicyArn"] for policy in attached_policies)
        if is_admin:
            findings.append({
                "Check": "IAM Admin Policy",
                "Resource": user_name,
                "Issue": "User has AdministratorAccess policy attached",
                "Severity": "High"
            })
        else:
            print(f"✅ User without admin policy: {user_name}")

    return findings


def check_mfa_enabled(profile_name):
    findings = []
    client = get_iam_client(profile_name)
    paginator = client.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        users.extend(page["Users"])

    for user in users:
        user_name = user["UserName"]
        mfa = client.list_mfa_devices(UserName=user_name)
        if not mfa["MFADevices"]:
            print(f"⚠️  MFA not enabled for user: {user_name}")
            findings.append({
                "Check": "MFA",
                "Resource": user_name,
                "Issue": "User does not have MFA enabled",
                "Severity": "Medium"
            })

    return findings


def check_cloudtrail_enabled(profile_name):
    findings = []
    client = get_cloudtrail_client(profile_name)
    trails = client.describe_trails().get("trailList", [])
    if not trails:
        print("⚠️  No CloudTrails found.")
        findings.append({
            "Check": "CloudTrail",
            "Resource": "AWS Account",
            "Issue": "No CloudTrail trails found",
            "Severity": "High"
        })
    return findings


def check_guardduty_enabled(profile_name):
    findings = []
    client = get_guardduty_client(profile_name)
    detectors = client.list_detectors().get("DetectorIds", [])
    if not detectors:
        print("⚠️  GuardDuty is not enabled.")
        findings.append({
            "Check": "GuardDuty",
            "Resource": "AWS Account",
            "Issue": "GuardDuty is not enabled",
            "Severity": "High"
        })
    return findings


def check_root_access_keys(profile_name):
    findings = []
    client = get_iam_client(profile_name)
    try:
        response = client.get_account_summary()
        if response["SummaryMap"].get("AccountAccessKeysPresent", 0) > 0:
            findings.append({
                "Check": "Root Access Key",
                "Resource": "Root User",
                "Issue": "Root access key is enabled",
                "Severity": "Critical"
            })
        else:
            print("✅ No root access key present.")
    except ClientError as e:
        print(f"Error checking root access keys: {e}")
    return findings


def check_s3_encryption_enabled(profile_name=None):
    findings = []
    session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
    s3 = session.client("s3")

    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not rules:
                raise Exception("No encryption rules")
        except Exception:
            findings.append({
                "Check": "S3 Encryption",
                "Resource": bucket_name,
                "Issue": "Bucket is not encrypted",
                "Severity": "High"
            })
    return findings



def check_s3_encryption(profile_name):
    findings = []
    client = get_s3_client(profile_name)
    buckets = client.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        try:
            client.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append({
                    "Check": "S3 Encryption",
                    "Resource": name,
                    "Issue": "Bucket is not encrypted",
                    "Severity": "Medium"
                })
    return findings
