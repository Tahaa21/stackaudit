# StackAudit

**Audit your AWS misconfigurations in minutes.**  
StackAudit is a lightweight CLI tool that scans AWS environments for common security misconfigurations — no agents, no fluff.

---

## 🔍 What It Does

StackAudit currently checks for:

- Publicly accessible S3 buckets
- IAM users with `AdministratorAccess`
- IAM users without MFA
- Inactive IAM access keys
- Open ports in EC2 security groups (`0.0.0.0/0`)
- Missing CloudTrail configuration
- Disabled GuardDuty
- Recent root account usage

All results are exported to:
- ✅ Human-readable **PDF Report**
- ✅ Flexible **Excel Spreadsheet**

---

## 🚀 How It Works

1. Configure AWS credentials locally using:

   ```bash
   aws configure --profile stackaudit-test
Run the scanner:

bash
Copy
Edit
python3 scanner.py --profile stackaudit-test
Get clean, downloadable reports for your records or audits.

📦 Coming Soon
Streamlit dashboard UI (SaaS version)

Organization-wide IAM risk scoring

GitHub Actions integration

Automated AWS hardening suggestions

💡 Who It's For
Startups on AWS

Freelance DevOps/SecOps engineers

MSPs and vCISOs

Anyone who wants fast AWS visibility without enterprise pricing

🛠 Tech Stack
Python + Boto3

xlsxwriter for Excel output

fpdf2 for PDF generation

📬 Contact
Built by @tahaaK21
DM me on LinkedIn if you’d like to collaborate or request features.

