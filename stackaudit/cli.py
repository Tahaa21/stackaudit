import argparse
import os
from datetime import datetime

from .scanner import (
    check_iam_admins,
    check_mfa_enabled,
    check_cloudtrail_enabled,
    check_guardduty_enabled,
    check_root_access_keys,
    check_s3_encryption_enabled,
)
from .report_generator import generate_excel_report, generate_pdf_report

def main():
    parser = argparse.ArgumentParser(
        description="StackAudit – Scan your AWS account for common misconfigurations."
    )
    parser.add_argument(
        "--profile", required=True, help="AWS CLI profile name to use for the scan"
    )
    parser.add_argument(
        "--report",
        choices=["excel", "pdf", "all"],
        help="Generate a report (Excel, PDF, or both)",
    )

    args = parser.parse_args()
    profile_name = args.profile
    report_type = args.report

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = "reports"
    os.makedirs(output_dir, exist_ok=True)

    pro_enabled = os.path.exists(".stackaudit_license")
    scan_results = []

    # === Run checks ===
    scan_results.extend(check_iam_admins(profile_name))
    scan_results.extend(check_mfa_enabled(profile_name))
    scan_results.extend(check_cloudtrail_enabled(profile_name))
    scan_results.extend(check_guardduty_enabled(profile_name))
    scan_results.extend(check_root_access_keys(profile_name))

    if pro_enabled:
        scan_results.extend(check_s3_encryption_enabled(profile_name))
    else:
        print("\n🔒 Pro Feature Locked: S3 Encryption Check")
        print("👉 Upgrade to StackAudit Pro to detect unencrypted S3 buckets.\n")

    # === Generate Reports ===
    if report_type == "excel":
        generate_excel_report(scan_results, output_dir, timestamp)
    elif report_type == "pdf":
        generate_pdf_report(scan_results, output_dir, timestamp)
    elif report_type == "all":
        generate_excel_report(scan_results, output_dir, timestamp)
        generate_pdf_report(scan_results, output_dir, timestamp)

if __name__ == "__main__":
    main()
