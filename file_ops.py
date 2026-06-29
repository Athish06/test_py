"""
File Operation Vulnerabilities
Contains: ZipSlip Path Traversal, Unrestricted File Upload, TOCTOU Race Condition, ReDoS
"""
import os
import re
import zipfile
import shutil
import time
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/var/uploads"
EXTRACT_DIR = "/var/extracted"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}


# ============================================================================
# VULN 9: Path Traversal via ZIP File Extraction (ZipSlip)
# Extracts ZIP files without validating that member paths stay within
# the target directory. A malicious ZIP can contain entries like:
#   ../../../../etc/cron.d/backdoor
# which writes files outside the intended extraction directory.
# ============================================================================
@app.route("/api/upload/archive", methods=["POST"])
def upload_and_extract_archive():
    file = request.files.get("archive")
    if not file or not file.filename.endswith(".zip"):
        return jsonify({"error": "ZIP file required"}), 400

    zip_path = os.path.join(UPLOAD_DIR, file.filename)
    file.save(zip_path)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                # VULNERABLE: The member name is used directly to construct
                # the output path. A ZIP entry named "../../etc/passwd"
                # will resolve to /etc/passwd and overwrite system files.
                target_path = os.path.join(EXTRACT_DIR, member)

                # No check: does target_path start with EXTRACT_DIR?
                if member.endswith("/"):
                    os.makedirs(target_path, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with zf.open(member) as source, open(target_path, "wb") as dest:
                        shutil.copyfileobj(source, dest)

        return jsonify({"status": "extracted", "path": EXTRACT_DIR})
    finally:
        os.remove(zip_path)


# ============================================================================
# VULN 10: Unrestricted File Upload with Extension Bypass
# The check only looks at the LAST extension, so "shell.php.jpg" passes.
# But many web servers (Apache with mod_php) will execute the .php part.
# Also vulnerable to null byte injection on older systems: "shell.php%00.jpg"
# ============================================================================
def allowed_file(filename):
    # VULNERABLE: Only checks the final extension after the last dot.
    # "malware.php.jpg" passes because "jpg" is in ALLOWED_EXTENSIONS.
    # On Apache with AddHandler, the .php extension is still processed.
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/api/upload/avatar", methods=["POST"])
def upload_avatar():
    file = request.files.get("avatar")
    if not file:
        return jsonify({"error": "No file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    # VULNERABLE: Does not check file content (magic bytes), only the name.
    # A PHP webshell renamed to "shell.php.jpg" will be saved and potentially
    # executed by Apache. The filename is also not sanitized against path traversal.
    filename = file.filename  # BUG: should use secure_filename()
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)

    return jsonify({"status": "uploaded", "path": save_path})


# ============================================================================
# VULN 11: Race Condition in File Operations (TOCTOU - Time of Check to Time of Use)
# The endpoint checks if a file exists, then reads it. Between the check and
# the read, an attacker can swap the file with a symlink to /etc/shadow.
# ============================================================================
@app.route("/api/files/<filename>")
def serve_file(filename):
    filepath = os.path.join(UPLOAD_DIR, filename)

    # TIME OF CHECK: Verify the file exists and is a regular file
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404

    if not os.path.isfile(filepath):
        return jsonify({"error": "Not a regular file"}), 400

    # VULNERABLE WINDOW: Between the check above and the read below,
    # an attacker with local access can:
    #   1. Delete the legitimate file
    #   2. Create a symlink: ln -s /etc/shadow /var/uploads/legitimate.txt
    # The next line will then read /etc/shadow instead of the intended file.

    file_size = os.path.getsize(filepath)
    if file_size > 10 * 1024 * 1024:  # 10MB limit
        return jsonify({"error": "File too large"}), 400

    # TIME OF USE: Read the file (which may now be a symlink to a sensitive file)
    return send_file(filepath)


# ============================================================================
# VULN 12: ReDoS with Catastrophic Backtracking Regex
# The email validation regex has nested quantifiers that cause exponential
# backtracking on carefully crafted inputs, freezing the server.
# ============================================================================
# VULNERABLE REGEX: The (.[a-zA-Z0-9_]+)* group causes catastrophic backtracking.
# Input like "aaaaaaaaaaaaaaaaaaaaaaaa!" forces the regex engine to try
# 2^24 possible ways to match before failing.
EMAIL_REGEX = re.compile(
    r"^([a-zA-Z0-9_]+\.)*[a-zA-Z0-9_]+@([a-zA-Z0-9_]+\.)*[a-zA-Z0-9_]+$"
)

# Even worse: nested repetition for URL validation
URL_REGEX = re.compile(
    r"^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w\.\-]*)*\/?$"
)


@app.route("/api/validate/email", methods=["POST"])
def validate_email():
    data = request.get_json()
    email = data.get("email", "")

    # VULNERABLE: If attacker sends email = "a" * 50 + "!"
    # the regex engine enters catastrophic backtracking and the server hangs
    # for minutes or hours, causing a Denial of Service.
    if EMAIL_REGEX.match(email):
        return jsonify({"valid": True})
    return jsonify({"valid": False})


@app.route("/api/validate/url", methods=["POST"])
def validate_url():
    data = request.get_json()
    url = data.get("url", "")

    # VULNERABLE: Same catastrophic backtracking issue with the URL regex.
    if URL_REGEX.match(url):
        return jsonify({"valid": True})
    return jsonify({"valid": False})
