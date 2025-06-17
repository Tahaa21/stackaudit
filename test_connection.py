import boto3

# Connect using named profile
session = boto3.Session(profile_name='stackaudit-test')
s3 = session.client('s3')

# List S3 buckets
try:
    buckets = s3.list_buckets()
    print("✅ Connected! Found the following S3 buckets:")
    for bucket in buckets['Buckets']:
        print(f"  - {bucket['Name']}")
except Exception as e:
    print("❌ Error connecting to AWS:", e)
