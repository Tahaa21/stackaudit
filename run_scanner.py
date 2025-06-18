import argparse
import os
import datetime
from scanner import (
    check_iam_admins,
    check_mfa_enabled,
    check_cloudtrail_enabled,
    check_guardduty_enabled,
    check_root_key_usage,
    check_s3_encryption_enabled_pro,
    check_inactive_iam_users_pro,
    check_password_policy_pro
)
from report_generator import generate_excel_report, generate_pdf_report

def main():
    parser = argparse.ArgumentParser(description="🔍 StackAudit - Scan AWS for common security misconfigurations.")
    parser.add_argument("--profile", required=True, help="AWS CLI profile name (e.g., --profile dev)")
    parser.add_argument("--report", choices=["excel", "pdf", "all"], default="all", help="Report format to generate")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--pro", action="store_true", help="Enable Pro-only advanced checks")

    args = parser.parse_args()

    profile_name = args.profile
    report_format = args.report
    output_dir = args.output
    pro_enabled = args.pro

    os.makedirs(output_dir, exist_ok=True)

    scan_results = []
    scan_results.extend(check_iam_admins(profile_name))
    scan_results.extend(check_mfa_enabled(profile_name))
    scan_results.extend(check_cloudtrail_enabled(profile_name))
    scan_results.extend(check_guardduty_enabled(profile_name))
    scan_results.extend(check_root_key_usage(profile_name))

    if pro_enabled:
        scan_results.extend(check_s3_encryption_enabled_pro(profile_name))
        scan_results.extend(check_inactive_iam_users_pro(profile_name))
        scan_results.extend(check_password_policy_pro(profile_name))
    else:
        print("\n🔒 Pro Feature Locked: S3 Encryption Check")
        print("👉 Upgrade to StackAudit Pro to detect unencrypted S3 buckets.\n")

    # Summary
    print("\n--- 🔍 StackAudit Scan Summary ---")
    if scan_results:
        for finding in scan_results:
            print(f"[{finding['Severity']}] {finding['Check']} – {finding['Resource']}: {finding['Issue']}")
        print(f"\n⚠️  {len(scan_results)} total finding(s) detected.")
    else:
        print("✅ No misconfigurations found.")

    # Generate report(s)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if report_format in ("excel", "all"):
        generate_excel_report(scan_results, output_dir, timestamp)
    if report_format in ("pdf", "all"):
        generate_pdf_report(scan_results, output_dir, timestamp)

if __name__ == "__main__":
    main()
