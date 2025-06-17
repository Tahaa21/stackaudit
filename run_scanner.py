import os
from report_generator import generate_excel_report, generate_pdf_report
from scanner import (
    check_public_s3_buckets,
    check_admin_iam_users,
    check_iam_users_without_mfa,
    check_inactive_access_keys,
    check_open_security_groups,
    check_cloudtrail_enabled,
    check_guardduty_enabled,
    check_root_account_usage,
    check_unencrypted_s3_buckets,
    check_unused_iam_users,
    check_iam_password_policy
)

pro_enabled = os.path.exists(".stackaudit_license")

def main():
    profile = 'stackaudit-test'
    scan_results = []

    # Run each check and collect results
    scan_results.extend(check_public_s3_buckets(profile_name=profile))
    scan_results.extend(check_admin_iam_users(profile_name=profile))
    scan_results.extend(check_iam_users_without_mfa(profile_name=profile))
    scan_results.extend(check_inactive_access_keys(profile_name=profile))
    scan_results.extend(check_open_security_groups(profile_name=profile))
    scan_results.extend(check_cloudtrail_enabled(profile_name=profile))
    scan_results.extend(check_guardduty_enabled(profile_name=profile))
    scan_results.extend(check_root_account_usage(profile_name=profile))
    if pro_enabled:
        scan_results.extend(check_unencrypted_s3_buckets(profile_name=profile))
        scan_results.extend(check_unused_iam_users(profile_name=profile))
        scan_results.extend(check_iam_password_policy(profile_name=profile))
    else:
        print("\n🔒 Pro Feature Locked: S3 Encryption Check")
        print("👉 Upgrade to StackAudit Pro to detect unencrypted S3 buckets.\n")
        print("🔒 Pro Feature Locked: Unused IAM Users Check")
        print("👉 Upgrade to StackAudit Pro to detect inactive IAM users.\n")
        print("🔒 Pro Feature Locked: IAM Password Policy Check")
        print("👉 Upgrade to StackAudit Pro to detect weak or missing password policies.\n")


    # Final summary
    print("\n--- 🔍 StackAudit Scan Summary ---")
    if scan_results:
        for item in scan_results:
            print(f"[{item['Severity']}] {item['Check']} – {item['Resource']}: {item['Issue']}")
        print(f"\n⚠️  {len(scan_results)} total finding(s) detected.")
    else:
        print("✅ No misconfigurations found.")

    generate_excel_report(scan_results)
    generate_pdf_report(scan_results)

if __name__ == "__main__":
    main()
