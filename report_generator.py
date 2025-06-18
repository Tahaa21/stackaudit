import os
import pandas as pd
from fpdf import FPDF
from datetime import datetime

TOOL_NAME = "StackAudit"
VERSION = "v1.0"

SEVERITY_COLORS = {
    "Critical": (255, 0, 0),        # Red
    "High":     (255, 102, 0),      # Orange
    "Medium":   (218, 165, 32),     # Goldenrod
    "Low":      (0, 128, 0),        # Green
    "Info":     (30, 144, 255),     # Blue
}

def summarize_findings(findings):
    summary = {}
    for f in findings:
        sev = f.get("Severity", "Info")
        summary[sev] = summary.get(sev, 0) + 1
    return summary

def generate_excel_report(findings, output_dir="reports", timestamp=None):
    if not timestamp:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, f"StackAudit_Report_{timestamp}.xlsx")

    df = pd.DataFrame(findings)
    if not df.empty:
        df = df[["Check", "Resource", "Issue", "Severity"]]

    summary = summarize_findings(findings)

    with pd.ExcelWriter(filename, engine="xlsxwriter") as writer:
        # Write findings
        df.to_excel(writer, sheet_name="Findings", index=False)
        workbook = writer.book
        worksheet = writer.sheets["Findings"]

        # Apply row color by severity
        for row_num, severity in enumerate(df["Severity"], start=1):
            color = {
                "Critical": "#FF0000",
                "High": "#FF6600",
                "Medium": "#DAA520",
                "Low": "#008000",
                "Info": "#1E90FF"
            }.get(severity, "#000000")

            format = workbook.add_format({'bg_color': color, 'font_color': 'white'})
            worksheet.set_row(row_num, cell_format=format)

        # Add summary in new sheet
        summary_df = pd.DataFrame(list(summary.items()), columns=["Severity", "Count"])
        summary_df.to_excel(writer, sheet_name="Summary", index=False)

    print(f"📁 Excel report generated: {filename}")


def generate_pdf_report(findings, output_dir="reports", timestamp=None):
    from fpdf import FPDF
    import os

    def safe_text(s):
        """Ensure string is latin-1 safe."""
        return (
            str(s)
            .replace("–", "-")
            .replace("—", "-")
            .replace("“", '"')
            .replace("”", '"')
            .replace("‘", "'")
            .replace("’", "'")
            .replace("•", "-")
            .encode("latin-1", "replace")
            .decode("latin-1")
        )

    if not timestamp:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, f"StackAudit_Report_{timestamp}.pdf")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add logo
    logo_path = "assets/logo.png"
    if os.path.exists(logo_path):
        pdf.image(logo_path, x=150, y=10, w=40)
        pdf.ln(30)
    else:
        pdf.ln(10)

    # Title + Version
    pdf.set_text_color(0, 0, 0)
    pdf.cell(200, 10, txt=safe_text("StackAudit - Scan Report"), ln=True)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt=safe_text("Version: v1.0"), ln=True)
    pdf.ln(5)

    # Summary Section
    summary = summarize_findings(findings)
    if not findings:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(200, 10, txt=safe_text("✅ No misconfigurations found."), ln=True)
    else:
        pdf.set_text_color(0, 0, 0)
        summary_line = " | ".join([f"{v} {k}" for k, v in summary.items()])
        pdf.cell(200, 10, txt=safe_text(f"Findings Summary: {summary_line}"), ln=True)
        pdf.ln(4)

        for f in findings:
            severity = f.get("Severity", "Info")
            color = SEVERITY_COLORS.get(severity, (0, 0, 0))
            pdf.set_text_color(*color)

            check = safe_text(f.get("Check", ""))
            resource = safe_text(f.get("Resource", ""))
            issue = safe_text(f.get("Issue", ""))
            line = f"[{severity}] {check} - {resource}: {issue}"

            pdf.multi_cell(0, 8, txt=safe_text(line))
            pdf.ln(1)

    # Footer
    pdf.set_text_color(120, 120, 120)
    pdf.set_y(-15)
    pdf.set_font("Arial", size=8)
    pdf.cell(0, 10, txt=safe_text(f"StackAudit v1.0 – Generated on {timestamp}"), ln=True, align="C")

    pdf.output(filename)
    print(f"📄 PDF report generated: {filename}")
