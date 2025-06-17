import pandas as pd
from datetime import datetime

def generate_excel_report(scan_results, output_folder='reports'):
    if not scan_results:
        print("✅ No results to export — skipping report.")
        return

    # Create reports folder if needed
    import os
    os.makedirs(output_folder, exist_ok=True)

    # Build DataFrame
    df = pd.DataFrame(scan_results)
    df = df[["Check", "Resource", "Issue", "Severity"]]  # Column order
    df.sort_values(by="Severity", ascending=False, inplace=True)

    # Timestamped filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{output_folder}/StackAudit_Report_{timestamp}.xlsx"

    # Export
    df.to_excel(filename, index=False)
    print(f"📁 Excel report generated: {filename}")

from fpdf import FPDF

def generate_pdf_report(scan_results, output_folder='reports'):
    if not scan_results:
        print("✅ No results to export — skipping PDF report.")
        return

    import os
    os.makedirs(output_folder, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"{output_folder}/StackAudit_Report_{timestamp.replace(':','-').replace(' ', '_')}.pdf"

    # Init PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # 🖼️ Add logo to top-right
    logo_path = "assets/logo.png"
    if os.path.exists(logo_path):
        logo_width = 50  # adjust as needed
        logo_x = 210 - logo_width - 10  # page_width - logo_width - right_margin
        logo_y = 8

        pdf.image(logo_path, x=logo_x, y=logo_y, w=logo_width)
        pdf.set_y(25)  # Adjust this if your title overlaps the logo

    # Title
    pdf.set_font("Helvetica", 'B', 16)
    pdf.cell(0, 10, "StackAudit Security Scan Report", ln=True)
    pdf.set_font("Helvetica", '', 12)
    pdf.cell(0, 10, f"Generated: {timestamp}", ln=True)
    pdf.ln(10)

    # Summary
    severities = [r['Severity'] for r in scan_results]
    total = len(severities)
    high = severities.count("High")
    medium = severities.count("Medium")
    low = severities.count("Low")

    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(0, 10, f"Summary:", ln=True)
    pdf.set_font("Helvetica", '', 12)
    pdf.cell(0, 10, f"- Total Findings: {total}", ln=True)
    pdf.cell(0, 10, f"- High: {high}   Medium: {medium}   Low: {low}", ln=True)
    pdf.ln(10)

    # Table Header
    pdf.set_font("Helvetica", 'B', 11)
    pdf.cell(50, 10, "Check", 1)
    pdf.cell(50, 10, "Resource", 1)
    pdf.cell(90, 10, "Issue", 1, ln=True)

    # Table Rows
    pdf.set_font("Helvetica", '', 10)
    for r in scan_results:
        pdf.cell(50, 10, r['Check'][:30], 1)
        pdf.cell(50, 10, r['Resource'][:30], 1)
        pdf.cell(90, 10, r['Issue'][:40], 1, ln=True)

    pdf.output(filename)
    print(f"📄 PDF report generated: {filename}")
