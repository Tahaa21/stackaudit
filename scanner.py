import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def check_public_s3_buckets(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    s3 = session.client('s3')
    results = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False

            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        is_public = True
                        break
            except ClientError as e:
                print(f"❌ Error checking ACL for {bucket_name}: {e}")

            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                if '"Effect":"Allow"' in policy['Policy'] and '"Principal":"*"' in policy['Policy']:
                    is_public = True
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    print(f"❌ Error checking policy for {bucket_name}: {e}")

            if is_public:
                print(f"⚠️  Public bucket found: {bucket_name}")
                results.append({
                    "Check": "Public S3 Bucket",
                    "Resource": bucket_name,
                    "Issue": "S3 bucket is publicly accessible",
                    "Severity": "High"
                })
            else:
                print(f"✅ Private bucket: {bucket_name}")

    except Exception as e:
        print("❌ Failed to list S3 buckets:", e)

    return results


def check_admin_iam_users(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    iam = session.client('iam')
    results = []

    try:
        users = iam.list_users().get('Users', [])
        for user in users:
            username = user['UserName']
            has_admin = False

            attached_policies = iam.list_attached_user_policies(UserName=username).get('AttachedPolicies', [])
            for policy in attached_policies:
                if policy['PolicyName'] == 'AdministratorAccess':
                    has_admin = True

            groups = iam.list_groups_for_user(UserName=username).get('Groups', [])
            for group in groups:
                group_policies = iam.list_attached_group_policies(GroupName=group['GroupName']).get('AttachedPolicies', [])
                for policy in group_policies:
                    if policy['PolicyName'] == 'AdministratorAccess':
                        has_admin = True

            if has_admin:
                print(f"⚠️  Admin policy detected for user: {username}")
                results.append({
                    "Check": "IAM Admin Access",
                    "Resource": username,
                    "Issue": "User has AdministratorAccess policy",
                    "Severity": "High"
                })
            else:
                print(f"✅ User without admin policy: {username}")

    except Exception as e:
        print("❌ Failed to scan IAM users:", e)

    return results


def check_iam_users_without_mfa(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    iam = session.client('iam')
    results = []

    try:
        users = iam.list_users().get('Users', [])
        for user in users:
            username = user['UserName']
            mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
            if not mfa_devices:
                print(f"⚠️  MFA not enabled for user: {username}")
                results.append({
                    "Check": "IAM MFA Missing",
                    "Resource": username,
                    "Issue": "User does not have MFA enabled",
                    "Severity": "Medium"
                })
            else:
                print(f"✅ MFA enabled for user: {username}")

    except Exception as e:
        print("❌ Failed to scan IAM MFA status:", e)

    return results


def check_inactive_access_keys(profile_name='default', threshold_days=90):
    session = boto3.Session(profile_name=profile_name)
    iam = session.client('iam')
    results = []

    try:
        users = iam.list_users().get('Users', [])
        for user in users:
            username = user['UserName']
            keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
            for key in keys:
                key_id = key['AccessKeyId']
                last_used_info = iam.get_access_key_last_used(AccessKeyId=key_id)
                last_used_date = last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate')

                if last_used_date:
                    age_days = (datetime.now(timezone.utc) - last_used_date).days
                    if age_days > threshold_days:
                        print(f"⚠️  Inactive access key found: {key_id} (User: {username})")
                        results.append({
                            "Check": "Inactive Access Key",
                            "Resource": f"{username}/{key_id}",
                            "Issue": f"Access key inactive for {age_days} days",
                            "Severity": "Medium"
                        })

    except Exception as e:
        print("❌ Failed to check IAM access keys:", e)

    return results


def check_open_security_groups(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    ec2 = session.client('ec2')
    results = []

    try:
        response = ec2.describe_security_groups().get('SecurityGroups', [])
        for sg in response:
            group_name = sg['GroupName']
            group_id = sg['GroupId']
            for permission in sg.get('IpPermissions', []):
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    if cidr == '0.0.0.0/0':
                        print(f"⚠️  Open SG: {group_name} ({group_id}) allows {permission.get('FromPort')} from 0.0.0.0/0")
                        results.append({
                            "Check": "Open Security Group",
                            "Resource": group_id,
                            "Issue": f"Allows inbound from 0.0.0.0/0 on port {permission.get('FromPort')}",
                            "Severity": "High"
                        })

    except Exception as e:
        print("❌ Failed to scan EC2 security groups:", e)

    return results


def check_cloudtrail_enabled(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    ct = session.client('cloudtrail')
    results = []

    try:
        trails = ct.describe_trails().get('trailList', [])
        if not trails:
            print("⚠️  No CloudTrails found.")
            results.append({
                "Check": "CloudTrail",
                "Resource": "AWS Account",
                "Issue": "No CloudTrail trails found",
                "Severity": "High"
            })
        else:
            print("✅ CloudTrail(s) found.")
    except Exception as e:
        print("❌ Failed to check CloudTrail status:", e)

    return results


def check_guardduty_enabled(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    gd = session.client('guardduty')
    results = []

    try:
        detectors = gd.list_detectors().get('DetectorIds', [])
        if not detectors:
            print("⚠️  GuardDuty is not enabled.")
            results.append({
                "Check": "GuardDuty",
                "Resource": "AWS Account",
                "Issue": "GuardDuty is not enabled",
                "Severity": "High"
            })
        else:
            print("✅ GuardDuty is enabled.")

    except Exception as e:
        print("❌ Failed to check GuardDuty:", e)

    return results


def check_root_account_usage(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    iam = session.client('iam')
    results = []

    try:
        response = iam.get_account_summary()
        if response['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
            print("⚠️  Root access key present")
            results.append({
                "Check": "Root Account Usage",
                "Resource": "Root",
                "Issue": "Root access key present — possible recent usage",
                "Severity": "High"
            })
        else:
            print("✅ No root access key present.")

    except Exception as e:
        print("❌ Failed to check root account usage:", e)

    return results


def check_unencrypted_s3_buckets(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    s3 = session.client('s3')
    results = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc['ServerSideEncryptionConfiguration']['Rules']
                if not rules:
                    raise Exception("No encryption rules")
                print(f"✅ Bucket encrypted: {bucket_name}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    print(f"⚠️  Unencrypted S3 bucket: {bucket_name}")
                    results.append({
                        "Check": "S3 Encryption Missing",
                        "Resource": bucket_name,
                        "Issue": "Bucket lacks default encryption",
                        "Severity": "High"
                    })
                else:
                    print(f"❌ Error checking encryption for {bucket_name}: {e}")
    except Exception as e:
        print("❌ Failed to check S3 encryption:", e)

    return results


def check_unused_iam_users(profile_name='default', threshold_days=90):
    session = boto3.Session(profile_name=profile_name)
    iam = session.client('iam')
    results = []

    try:
        users = iam.list_users().get('Users', [])
        for user in users:
            username = user['UserName']
            last_activity = None

            # 1. Console login time
            try:
                login_profile = iam.get_login_profile(UserName=username)
                access = iam.get_user(UserName=username)
                last_used = access.get('User', {}).get('PasswordLastUsed')
                if last_used:
                    last_activity = last_used
            except iam.exceptions.NoSuchEntityException:
                pass

            # 2. Access key usage time
            keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
            for key in keys:
                key_id = key['AccessKeyId']
                last_used_info = iam.get_access_key_last_used(AccessKeyId=key_id)
                key_last_used = last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                if key_last_used and (not last_activity or key_last_used > last_activity):
                    last_activity = key_last_used

            if last_activity:
                age = (datetime.now(timezone.utc) - last_activity).days
                if age > threshold_days:
                    print(f"⚠️  Inactive user: {username} (Last active {age} days ago)")
                    results.append({
                        "Check": "Unused IAM User",
                        "Resource": username,
                        "Issue": f"No activity for {age} days",
                        "Severity": "Medium"
                    })
                else:
                    print(f"✅ Active user: {username} (Last used {age} days ago)")
            else:
                print(f"⚠️  User {username} has no recorded activity")
                results.append({
                    "Check": "Unused IAM User",
                    "Resource": username,
                    "Issue": "No recorded activity",
                    "Severity": "Medium"
                })

    except Exception as e:
        print("❌ Failed to check IAM user activity:", e)

    return results


def check_iam_password_policy(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    iam = session.client('iam')
    results = []

    try:
        policy = iam.get_account_password_policy().get('PasswordPolicy', {})
        issues = []

        if policy.get('MinimumPasswordLength', 0) < 14:
            issues.append("Minimum password length is less than 14")

        if not policy.get('RequireUppercaseCharacters'):
            issues.append("Uppercase characters not required")

        if not policy.get('RequireLowercaseCharacters'):
            issues.append("Lowercase characters not required")

        if not policy.get('RequireNumbers'):
            issues.append("Numbers not required")

        if not policy.get('RequireSymbols'):
            issues.append("Symbols not required")

        if not policy.get('PasswordReusePrevention') or policy.get('PasswordReusePrevention', 0) < 5:
            issues.append("Password reuse prevention is less than 5")

        if issues:
            print("⚠️  Weak password policy found:")
            for i in issues:
                print("   -", i)
            results.append({
                "Check": "IAM Password Policy",
                "Resource": "Account",
                "Issue": "; ".join(issues),
                "Severity": "High"
            })
        else:
            print("✅ Strong password policy in place")

    except iam.exceptions.NoSuchEntityException:
        print("⚠️  No password policy found")
        results.append({
            "Check": "IAM Password Policy",
            "Resource": "Account",
            "Issue": "No password policy configured",
            "Severity": "High"
        })

    except Exception as e:
        print("❌ Failed to check password policy:", e)

    return results