from fpdf import FPDF
from datetime import datetime
import os
import re


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(text):
    """
    Clean text before sending it to FPDF.
    """

    if text is None:
        return ""

    text = str(text)

    replacements = {
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2022": "-",
        "\u2026": "...",
        "\u00a0": " ",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    # Remove unsupported control characters
    text = re.sub(
        r"[\x00-\x08\x0b\x0c\x0e-\x1f]",
        "",
        text
    )

    return text


# ============================================================
# PDF CLASS
# ============================================================

class SecurityReport(FPDF):

    def header(self):

        if self.page_no() > 1:

            self.set_font(
                "Helvetica",
                "B",
                10
            )

            self.set_text_color(
                70,
                70,
                70
            )

            self.set_x(
                self.l_margin
            )

            self.cell(
                0,
                8,
                "Log Analysis Dashboard"
            )

            self.ln(8)

    def footer(self):

        self.set_y(-15)

        self.set_font(
            "Helvetica",
            "",
            8
        )

        self.set_text_color(
            100,
            100,
            100
        )

        self.cell(
            0,
            10,
            f"Page {self.page_no()}",
            align="C"
        )

    def section_title(self, title):

        self.ln(5)

        self.set_x(
            self.l_margin
        )

        self.set_fill_color(
            230,
            235,
            240
        )

        self.set_text_color(
            25,
            45,
            75
        )

        self.set_font(
            "Helvetica",
            "B",
            13
        )

        available_width = (
            self.w
            - self.l_margin
            - self.r_margin
        )

        self.cell(
            available_width,
            9,
            clean_text(title),
            fill=True
        )

        self.ln(12)

        self.set_text_color(
            30,
            30,
            30
        )

    def safe_multicell(
        self,
        text,
        height=7
    ):
        """
        Safe wrapper around multi_cell.
        """

        text = clean_text(text)

        self.set_x(
            self.l_margin
        )

        available_width = (
            self.w
            - self.l_margin
            - self.r_margin
        )

        # Prevent zero/negative width
        if available_width <= 5:
            self.add_page()

            available_width = (
                self.w
                - self.l_margin
                - self.r_margin
            )

        self.multi_cell(
            available_width,
            height,
            text
        )

    def add_key_value(
        self,
        key,
        value
    ):

        self.set_x(
            self.l_margin
        )

        self.set_font(
            "Helvetica",
            "B",
            10
        )

        self.cell(
            50,
            7,
            clean_text(key)
        )

        self.set_font(
            "Helvetica",
            "",
            10
        )

        remaining_width = (
            self.w
            - self.l_margin
            - self.r_margin
            - 50
        )

        if remaining_width <= 5:

            self.ln(7)

            remaining_width = (
                self.w
                - self.l_margin
                - self.r_margin
            )

        self.multi_cell(
            remaining_width,
            7,
            clean_text(value)
        )


# ============================================================
# REPORT CREATION
# ============================================================

def create_report(
    logs,
    findings,
    statistics,
    output_file
):

    """
    Generate Security Log Analysis PDF.

    Parameters:
        logs        -> parsed log entries
        findings    -> detected suspicious events
        statistics  -> analysis statistics
        output_file -> PDF output path
    """

    # --------------------------------------------------------
    # Prepare output directory
    # --------------------------------------------------------

    output_directory = os.path.dirname(
        output_file
    )

    if output_directory:

        os.makedirs(
            output_directory,
            exist_ok=True
        )

    # --------------------------------------------------------
    # Create PDF
    # --------------------------------------------------------

    pdf = SecurityReport()

    pdf.set_auto_page_break(
        auto=True,
        margin=20
    )

    pdf.set_margins(
        left=15,
        top=15,
        right=15
    )

    # --------------------------------------------------------
    # TITLE PAGE
    # --------------------------------------------------------

    pdf.add_page()

    pdf.set_fill_color(
        25,
        45,
        75
    )

    pdf.rect(
        0,
        0,
        pdf.w,
        45,
        "F"
    )

    pdf.set_text_color(
        255,
        255,
        255
    )

    pdf.set_font(
        "Helvetica",
        "B",
        22
    )

    pdf.set_y(14)

    pdf.cell(
        0,
        10,
        "LOG ANALYSIS DASHBOARD",
        align="C"
    )

    pdf.set_font(
        "Helvetica",
        "",
        11
    )

    pdf.set_y(28)

    pdf.cell(
        0,
        8,
        "Security Log Analysis Report",
        align="C"
    )

    # --------------------------------------------------------
    # REPORT INFORMATION
    # --------------------------------------------------------

    pdf.set_y(65)

    pdf.set_text_color(
        30,
        30,
        30
    )

    pdf.set_font(
        "Helvetica",
        "B",
        14
    )

    pdf.cell(
        0,
        10,
        "Report Information"
    )

    pdf.ln(14)

    pdf.set_font(
        "Helvetica",
        "",
        10
    )

    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    pdf.safe_multicell(
        f"Generated: {generated_time}",
        7
    )

    pdf.safe_multicell(
        f"Total Log Entries: {len(logs) if logs else 0}",
        7
    )

    pdf.safe_multicell(
        f"Detected Findings: {len(findings) if findings else 0}",
        7
    )

       # --------------------------------------------------------
    # SECURITY STATISTICS
    # --------------------------------------------------------

    pdf.add_page()

    pdf.section_title(
        "Security Statistics"
    )

    if isinstance(statistics, dict):

        statistic_items = [
            ("Total Logs", statistics.get("total_logs", 0)),
            ("Security Findings", statistics.get("total_findings", 0)),
            ("Critical", statistics.get("critical", 0)),
            ("High", statistics.get("high", 0)),
            ("Medium", statistics.get("medium", 0)),
            ("Low", statistics.get("low", 0)),
        ]

        for key, value in statistic_items:

            pdf.add_key_value(
                f"{key}:",
                str(value)
            )

        # ----------------------------------------------------
        # TOP SUSPICIOUS IPS
        # ----------------------------------------------------

        pdf.section_title(
            "Top Suspicious IPs"
        )

        top_ips = statistics.get(
            "ip_risk",
            []
        )

        if top_ips:

            pdf.set_font(
                "Helvetica",
                "B",
                9
            )

            pdf.cell(
                55,
                7,
                "IP Address"
            )

            pdf.cell(
                25,
                7,
                "Events"
            )

            pdf.cell(
                25,
                7,
                "Score"
            )

            pdf.cell(
                35,
                7,
                "Risk"
            )

            pdf.ln(7)

            pdf.set_font(
                "Helvetica",
                "",
                9
            )

            for item in top_ips:

                pdf.cell(
                    55,
                    7,
                    clean_text(
                        item.get("ip", "")
                    )
                )

                pdf.cell(
                    25,
                    7,
                    str(
                        item.get("events", 0)
                    )
                )

                pdf.cell(
                    25,
                    7,
                    str(
                        item.get("score", 0)
                    )
                )

                pdf.cell(
                    35,
                    7,
                    clean_text(
                        item.get("risk", "")
                    )
                )

                pdf.ln(7)

        else:

            pdf.safe_multicell(
                "No suspicious IP information available.",
                7
            )

        # ----------------------------------------------------
        # MITRE ATT&CK SUMMARY
        # ----------------------------------------------------

        pdf.section_title(
            "MITRE ATT&CK Summary"
        )

        mitre_summary = statistics.get(
            "mitre_summary",
            []
        )

        if mitre_summary:

            pdf.set_font(
                "Helvetica",
                "B",
                9
            )

            pdf.cell(
                30,
                7,
                "ID"
            )

            pdf.cell(
                90,
                7,
                "Technique"
            )

            pdf.cell(
                25,
                7,
                "Events"
            )

            pdf.ln(7)

            pdf.set_font(
                "Helvetica",
                "",
                9
            )

            for item in mitre_summary:

                pdf.cell(
                    30,
                    7,
                    clean_text(
                        item.get("id", "")
                    )
                )

                pdf.cell(
                    90,
                    7,
                    clean_text(
                        item.get("technique", "")
                    )
                )

                pdf.cell(
                    25,
                    7,
                    str(
                        item.get("events", 0)
                    )
                )

                pdf.ln(7)

        else:

            pdf.safe_multicell(
                "No MITRE ATT&CK mappings available.",
                7
            )

    else:

        pdf.safe_multicell(
            "No statistics available.",
            7
        )
    # --------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------

    pdf.section_title(
        "Security Findings"
    )

    if findings:

        for number, finding in enumerate(
            findings,
            start=1
        ):

            if isinstance(
                finding,
                dict
            ):

                finding_parts = []

                for key, value in finding.items():

                    finding_parts.append(
                        f"{key}: {value}"
                    )

                finding_text = (
                    f"{number}. "
                    + " | ".join(
                        finding_parts
                    )
                )

            else:

                finding_text = (
                    f"{number}. {finding}"
                )

            pdf.safe_multicell(
                finding_text,
                7
            )

            pdf.ln(2)

    else:

        pdf.safe_multicell(
            "No suspicious findings detected.",
            7
        )

    # --------------------------------------------------------
    # LOG SAMPLE
    # --------------------------------------------------------

    pdf.section_title(
        "Log Entries"
    )

    if logs:

        # Show maximum 100 entries
        # to prevent extremely large PDFs.

        display_logs = logs[:100]

        for number, log_entry in enumerate(
            display_logs,
            start=1
        ):

            if isinstance(
                log_entry,
                dict
            ):

                parts = []

                for key, value in log_entry.items():

                    parts.append(
                        f"{key}: {value}"
                    )

                log_text = (
                    f"{number}. "
                    + " | ".join(parts)
                )

            else:

                log_text = (
                    f"{number}. {log_entry}"
                )

            pdf.safe_multicell(
                log_text,
                6
            )

            pdf.ln(1)

        if len(logs) > 100:

            pdf.ln(3)

            pdf.safe_multicell(
                f"Only the first 100 log entries "
                f"are displayed. Total entries: {len(logs)}.",
                6
            )

    else:

        pdf.safe_multicell(
            "No log entries available.",
            7
        )

    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    pdf.section_title(
        "Security Recommendations"
    )

    recommendations = [

        "Review failed login attempts and investigate repeated authentication failures.",

        "Investigate suspicious IP addresses and unusual access patterns.",

        "Consider temporary blocking of confirmed malicious IP addresses.",

        "Enable multi-factor authentication for sensitive accounts.",

        "Review authentication and access-control policies.",

        "Continue monitoring logs for repeated suspicious activity.",

    ]

    for number, recommendation in enumerate(
        recommendations,
        start=1
    ):

        pdf.safe_multicell(
            f"{number}. {recommendation}",
            7
        )

        pdf.ln(1)

    # --------------------------------------------------------
    # DISCLAIMER
    # --------------------------------------------------------

    pdf.ln(8)

    pdf.set_font(
        "Helvetica",
        "I",
        8
    )

    pdf.set_text_color(
        100,
        100,
        100
    )

    pdf.safe_multicell(
        "This report is generated for educational "
        "and defensive cybersecurity analysis purposes.",
        5
    )

    # --------------------------------------------------------
    # SAVE PDF
    # --------------------------------------------------------

    pdf.output(
        output_file
    )

    return output_file