from fpdf import FPDF
from datetime import datetime


class SecurityReport(FPDF):

    def header(self):

        self.set_font(
            "Arial",
            "B",
            16
        )

        self.cell(
            0,
            10,
            "Security Log Analysis Report",
            ln=True,
            align="C"
        )

        self.ln(5)


    def footer(self):

        self.set_y(-15)

        self.set_font(
            "Arial",
            "",
            8
        )

        self.cell(
            0,
            10,
            f"Page {self.page_no()}",
            align="C"
        )


def clean_text(text):

    return str(text).encode(
        "latin-1",
        "replace"
    ).decode(
        "latin-1"
    )


def create_report(
    logs,
    findings,
    statistics,
    output_file
):

    pdf = SecurityReport()

    pdf.set_auto_page_break(
        auto=True,
        margin=15
    )

    pdf.add_page()


    # REPORT INFORMATION

    pdf.set_font(
        "Arial",
        "B",
        12
    )

    pdf.cell(
        0,
        8,
        "Report Information",
        ln=True
    )

    pdf.set_font(
        "Arial",
        "",
        10
    )

    pdf.cell(
        0,
        7,
        clean_text(
            "Generated: "
            + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ),
        ln=True
    )

    pdf.cell(
        0,
        7,
        f"Total Logs: {statistics['total_logs']}",
        ln=True
    )

    pdf.cell(
        0,
        7,
        f"Total Findings: {statistics['total_findings']}",
        ln=True
    )

    pdf.ln(5)


    # SECURITY SUMMARY

    pdf.set_font(
        "Arial",
        "B",
        12
    )

    pdf.cell(
        0,
        8,
        "Security Summary",
        ln=True
    )

    pdf.set_font(
        "Arial",
        "",
        10
    )

    pdf.cell(
        0,
        7,
        f"Critical: {statistics['critical']}",
        ln=True
    )

    pdf.cell(
        0,
        7,
        f"High: {statistics['high']}",
        ln=True
    )

    pdf.cell(
        0,
        7,
        f"Medium: {statistics['medium']}",
        ln=True
    )

    pdf.cell(
        0,
        7,
        f"Low: {statistics['low']}",
        ln=True
    )

    pdf.ln(5)


    # SUSPICIOUS IPS

    pdf.set_font(
        "Arial",
        "B",
        12
    )

    pdf.cell(
        0,
        8,
        "Top Suspicious IP Addresses",
        ln=True
    )

    pdf.set_font(
        "Arial",
        "",
        10
    )


    for item in statistics["ip_risk"]:

        text = (
            f"{item['ip']} | "
            f"Events: {item['events']} | "
            f"Score: {item['score']} | "
            f"Risk: {item['risk']}"
        )

        pdf.cell(
            0,
            7,
            clean_text(text),
            ln=True
        )


    pdf.ln(5)


    # SECURITY FINDINGS

    pdf.set_font(
        "Arial",
        "B",
        12
    )

    pdf.cell(
        0,
        8,
        "Security Findings",
        ln=True
    )

    pdf.set_font(
        "Arial",
        "",
        9
    )


    for finding in findings:

        pdf.multi_cell(
            0,
            6,
            clean_text(
                f"[{finding['severity']}] "
                f"{finding['type']} | "
                f"IP: {finding['ip']} | "
                f"Score: {finding['score']}/10\n"
                f"Time: {finding['timestamp']}\n"
                f"Message: {finding['message']}"
            )
        )

        pdf.ln(2)


    # RECOMMENDATIONS

    pdf.add_page()

    pdf.set_font(
        "Arial",
        "B",
        12
    )

    pdf.cell(
        0,
        8,
        "Security Recommendations",
        ln=True
    )

    pdf.set_font(
        "Arial",
        "",
        10
    )


    recommendations = [

        "Investigate all Critical security findings immediately.",

        "Review repeated authentication failures.",

        "Monitor high-risk IP addresses.",

        "Consider temporary blocking of confirmed malicious IPs.",

        "Enable multi-factor authentication for sensitive accounts.",

        "Review authentication and access-control policies.",

        "Continue monitoring logs for repeated suspicious activity."

    ]


    for number, recommendation in enumerate(
        recommendations,
        start=1
    ):

        pdf.multi_cell(
            0,
            7,
            clean_text(
                f"{number}. {recommendation}"
            )
        )


    pdf.output(output_file)