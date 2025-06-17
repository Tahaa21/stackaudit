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
