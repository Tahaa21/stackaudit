from scanner import check_public_s3_buckets

public_buckets = check_public_s3_buckets(profile_name='stackaudit-test')

print("\n--- Summary ---")
if public_buckets:
    print(f"{len(public_buckets)} public bucket(s) found:")
    for b in public_buckets:
        print(f" - {b}")
else:
    print("No public buckets found.")
