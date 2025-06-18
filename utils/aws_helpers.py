import boto3
from botocore.exceptions import ProfileNotFound

def get_boto3_session(profile_name):
    try:
        return boto3.Session(profile_name=profile_name)
    except ProfileNotFound:
        print(f"❌ Error: AWS profile '{profile_name}' not found.")
        exit(1)

def get_iam_client(profile_name):
    return get_boto3_session(profile_name).client("iam")

def get_s3_client(profile_name):
    return get_boto3_session(profile_name).client("s3")

def get_sts_client(profile_name):
    return get_boto3_session(profile_name).client("sts")

def get_cloudtrail_client(profile_name):
    return get_boto3_session(profile_name).client("cloudtrail")

def get_guardduty_client(profile_name):
    return get_boto3_session(profile_name).client("guardduty")
