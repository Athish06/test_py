"""
Network & Request Handling Vulnerabilities
Contains: SSRF URL Parsing Bypass, SSRF IP Obfuscation, HTTP Response Splitting, XXE
"""
import requests
import re
from urllib.parse import urlparse
from lxml import etree
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

INTERNAL_NETWORKS = ["10.", "172.16.", "192.168.", "127."]
BLOCKED_HOSTS = ["metadata.google.internal", "169.254.169.254"]


# ============================================================================
# VULN 13: SSRF via URL Parsing Bypass
# The validation checks the hostname, but can be bypassed using:
#   - URL encoding: http://169.254.169.254 -> http://%31%36%39.%32%35%34...
#   - Alternate IP formats: http://0x7f000001 (hex), http://2130706433 (decimal)
#   - DNS rebinding: Register evil.com to resolve to 169.254.169.254
#   - URL fragments: http://safe.com@169.254.169.254
# ============================================================================
def is_safe_url(url):
    """Naive URL validation that can be easily bypassed."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Check against blocklist (only catches exact string matches)
        if hostname in BLOCKED_HOSTS:
            return False

        # Check against internal networks (only catches dotted-decimal format)
        for prefix in INTERNAL_NETWORKS:
            if hostname.startswith(prefix):
                return False

        return True
    except Exception:
        return False


@app.route("/api/fetch", methods=["POST"])
def fetch_url():
    data = request.get_json()
    url = data.get("url", "")

    if not is_safe_url(url):
        return jsonify({"error": "URL blocked"}), 403

    # VULNERABLE: The validation above is trivially bypassed.
    # Attacker sends: http://0x7f000001 (resolves to 127.0.0.1)
    # or: http://169.254.169.254.evil.com (DNS rebinding)
    # or: http://safe.com@169.254.169.254 (userinfo bypass)
    try:
        resp = requests.get(url, timeout=5)
        return jsonify({"status": resp.status_code, "body": resp.text[:1000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# VULN 14: Server-Side Request Forgery with IP Obfuscation Bypass
# Even with a more "sophisticated" check, the attacker can use alternate
# IP representations that resolve to internal addresses.
# ============================================================================
def is_internal_ip(ip_str):
    """Checks if an IP is internal — but only handles dotted-decimal format."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False  # BUG: Returns False for hex/octal/decimal IPs
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False  # BUG: Returns False for 0x7f.0.0.1 (hex octets)

    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False


@app.route("/api/proxy", methods=["POST"])
def proxy_request():
    data = request.get_json()
    target_url = data.get("url", "")

    try:
        parsed = urlparse(target_url)
        import socket
        resolved_ip = socket.gethostbyname(parsed.hostname)

        if is_internal_ip(resolved_ip):
            return jsonify({"error": "Internal IP blocked"}), 403
    except Exception:
        pass

    # VULNERABLE: Attacker uses IPv6-mapped IPv4: http://[::ffff:169.254.169.254]/
    # Or decimal IP: http://2852039166/ (which is 169.254.169.254 in decimal)
    # Or octal: http://0251.0376.0251.0376/
    # None of these formats are caught by is_internal_ip()
    resp = requests.get(target_url, timeout=5, allow_redirects=False)
    return jsonify({"body": resp.text[:2000]})


# ============================================================================
# VULN 15: HTTP Response Splitting via Header Injection
# User input is placed directly into a response header without sanitizing
# \r\n characters. An attacker can inject additional headers or even
# an entirely new HTTP response body.
# ============================================================================
@app.route("/api/redirect")
def redirect_handler():
    target = request.args.get("url", "/")

    # VULNERABLE: The target URL is placed directly into the Location header.
    # If the attacker sends: url=http://evil.com%0d%0aSet-Cookie:%20admin=true
    # The response becomes:
    #   Location: http://evil.com
    #   Set-Cookie: admin=true
    # This injects an arbitrary cookie into the victim's browser.
    response = make_response("", 302)
    response.headers["Location"] = target  # BUG: no CRLF sanitization
    return response


@app.route("/api/set-language")
def set_language():
    lang = request.args.get("lang", "en")

    # VULNERABLE: Same injection vector via a custom header.
    # Attacker sends: lang=en%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
    response = make_response(jsonify({"language": lang}))
    response.headers["X-Content-Language"] = lang  # BUG: unsanitized user input in header
    return response


# ============================================================================
# VULN 16: XML External Entity (XXE) Injection
# The XML parser is configured to resolve external entities, allowing
# an attacker to read local files, perform SSRF, or cause DoS via
# the "Billion Laughs" attack.
# ============================================================================
@app.route("/api/import/xml", methods=["POST"])
def import_xml():
    xml_data = request.get_data(as_text=True)

    try:
        # VULNERABLE: resolve_entities=True allows the parser to follow
        # external entity declarations. An attacker can send:
        #
        # <?xml version="1.0"?>
        # <!DOCTYPE foo [
        #   <!ENTITY xxe SYSTEM "file:///etc/passwd">
        # ]>
        # <data>&xxe;</data>
        #
        # The parser will read /etc/passwd and include its contents in the output.
        parser = etree.XMLParser(
            resolve_entities=True,  # BUG: enables XXE
            no_network=False,       # BUG: allows network requests from entities
        )
        doc = etree.fromstring(xml_data.encode(), parser)
        result = etree.tostring(doc, pretty_print=True).decode()
        return jsonify({"parsed": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/parse/svg", methods=["POST"])
def parse_svg():
    """SVG files are XML — same XXE vector but less suspicious."""
    svg_data = request.get_data(as_text=True)

    # VULNERABLE: SVG is XML. An attacker embeds XXE in an SVG "image":
    # <?xml version="1.0"?>
    # <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
    # <svg><text>&xxe;</text></svg>
    parser = etree.XMLParser(resolve_entities=True)
    doc = etree.fromstring(svg_data.encode(), parser)
    texts = [el.text for el in doc.iter() if el.text]
    return jsonify({"extracted_text": texts})
