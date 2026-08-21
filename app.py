from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file
)

from log_parser import parse_log_file

from analyzer import (
    analyze_logs,
    get_statistics
)

from report import create_report

import os


app = Flask(__name__)


LOG_FILE = "data/sample.log"


# ==========================================
# LOAD DASHBOARD DATA
# ==========================================

def load_dashboard_data():

    logs = parse_log_file(
        LOG_FILE
    )

    findings = analyze_logs(
        logs
    )

    statistics = get_statistics(
        logs,
        findings
    )

    return (
        logs,
        findings,
        statistics
    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/")
def dashboard():

    logs, findings, statistics = (
        load_dashboard_data()
    )

    return render_template(
        "dashboard.html",
        logs=logs,
        findings=findings,
        statistics=statistics
    )


# ==========================================
# UPLOAD LOG FILE
# ==========================================

@app.route(
    "/upload",
    methods=["POST"]
)
def upload_log():

    if "logfile" not in request.files:

        return redirect(
            url_for("dashboard")
        )


    file = request.files["logfile"]


    if file.filename == "":

        return redirect(
            url_for("dashboard")
        )


    os.makedirs(
        "data",
        exist_ok=True
    )


    file.save(
        LOG_FILE
    )


    return redirect(
        url_for("dashboard")
    )


# ==========================================
# GENERATE PDF REPORT
# ==========================================

@app.route("/report")
def generate_report():

    logs, findings, statistics = (
        load_dashboard_data()
    )


    os.makedirs(
        "reports",
        exist_ok=True
    )


    report_file = os.path.join(
        "reports",
        "Security_Log_Report.pdf"
    )


    create_report(
        logs,
        findings,
        statistics,
        report_file
    )


    return redirect(
        url_for("download_report")
    )


# ==========================================
# DOWNLOAD PDF REPORT
# ==========================================

@app.route("/download-report")
def download_report():

    report_file = os.path.join(
        "reports",
        "Security_Log_Report.pdf"
    )


    if not os.path.exists(
        report_file
    ):

        return redirect(
            url_for("dashboard")
        )


    return send_file(
        report_file,
        as_attachment=True,
        download_name="Security_Log_Report.pdf"
    )


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )