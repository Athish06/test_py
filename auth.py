"""
Authentication & Authorization Vulnerabilities
Contains: JWT Algorithm Confusion, Timing Attack, IDOR with Encoded IDs, Mass Assignment
"""
import jwt
import hmac
import hashlib
import base64
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

PUBLIC_KEY = open("public.pem", "r").read()
PRIVATE_KEY = open("private.pem", "r").read()
SECRET_KEY = "supersecretkey123"
USERS_DB = {}


# ============================================================================
# VULN 1: JWT Algorithm Confusion Attack
# The server uses RS256 (asymmetric) but doesn't restrict accepted algorithms.
# An attacker can forge a token using HS256 with the PUBLIC key as the secret.
# ============================================================================
def create_token(user_id, role):
    payload = {"user_id": user_id, "role": role, "exp": time.time() + 3600}
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")


def verify_token(token):
    # VULNERABLE: algorithms parameter accepts BOTH RS256 and HS256.
    # An attacker can re-sign a token with HS256 using the PUBLIC key
    # (which is publicly available) and the server will accept it.
    try:
        decoded = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256", "HS256"],  # BUG: should ONLY allow RS256
        )
        return decoded
    except jwt.InvalidTokenError:
        return None


@app.route("/admin/dashboard")
def admin_dashboard():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    claims = verify_token(token)
    if not claims or claims.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"secret_data": "all_user_emails_and_passwords"})


# ============================================================================
# VULN 2: Timing Attack in HMAC Comparison
# Uses string equality (==) instead of hmac.compare_digest().
# An attacker can brute-force the signature byte-by-byte by measuring
# response times, because == returns early on first mismatch.
# ============================================================================
def generate_api_signature(payload, secret):
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


@app.route("/api/webhook", methods=["POST"])
def receive_webhook():
    payload = request.get_data(as_text=True)
    received_sig = request.headers.get("X-Signature", "")
    expected_sig = generate_api_signature(payload, SECRET_KEY)

    # VULNERABLE: string comparison leaks timing information.
    # Each correct byte adds a few nanoseconds to the comparison.
    # An attacker can determine the correct signature one byte at a time.
    if received_sig == expected_sig:  # BUG: should use hmac.compare_digest()
        process_webhook(payload)
        return jsonify({"status": "ok"})
    return jsonify({"error": "invalid signature"}), 401


def process_webhook(data):
    pass


# ============================================================================
# VULN 3: Insecure Direct Object Reference with Encoded IDs
# The developer "obfuscates" user IDs with base64, thinking it's secure.
# An attacker can trivially decode, modify, and re-encode the ID.
# ============================================================================
@app.route("/api/profile/<encoded_id>")
def get_profile(encoded_id):
    # VULNERABLE: base64 is encoding, NOT encryption.
    # Attacker can decode "MTIz" to "123", change to "124", re-encode to "MTI0"
    # and access another user's profile. No ownership check is performed.
    try:
        user_id = base64.b64decode(encoded_id).decode("utf-8")
    except Exception:
        return jsonify({"error": "Invalid ID"}), 400

    user = USERS_DB.get(user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    # No check: does the CURRENT authenticated user own this profile?
    return jsonify(user)


@app.route("/api/profile/<encoded_id>", methods=["DELETE"])
def delete_profile(encoded_id):
    user_id = base64.b64decode(encoded_id).decode("utf-8")
    # VULNERABLE: Any authenticated user can delete ANY other user's profile.
    if user_id in USERS_DB:
        del USERS_DB[user_id]
    return jsonify({"status": "deleted"})


# ============================================================================
# VULN 4: Mass Assignment via **kwargs Without Field Filtering
# The update endpoint blindly applies all user-supplied fields to the object,
# allowing an attacker to escalate privileges by setting "role": "admin".
# ============================================================================
class User:
    def __init__(self, username, email, role="user"):
        self.username = username
        self.email = email
        self.role = role
        self.is_verified = False

    def update(self, **kwargs):
        # VULNERABLE: No allowlist filtering. An attacker can send:
        # {"email": "new@email.com", "role": "admin", "is_verified": true}
        # and all three fields will be applied, including the role escalation.
        for key, value in kwargs.items():
            setattr(self, key, value)


@app.route("/api/user/update", methods=["PUT"])
def update_user():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    claims = verify_token(token)
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    user = USERS_DB.get(claims["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    # VULNERABLE: Passes raw request JSON directly into the update method.
    user.update(**request.get_json())
    return jsonify({"status": "updated"})
