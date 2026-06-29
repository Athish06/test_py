"""
Database & Data Manipulation Vulnerabilities
Contains: Second-Order SQLi, NoSQL Injection (PyMongo), Business Logic Flaw, Prototype Pollution
"""
import sqlite3
import re
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
mongo = MongoClient("mongodb://localhost:27017")
db_mongo = mongo["vulnerable_app"]
db_sql = sqlite3.connect(":memory:", check_same_thread=False)
cursor = db_sql.cursor()

cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, bio TEXT)")
cursor.execute("CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY, query TEXT)")
cursor.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL, quantity INTEGER)")


# ============================================================================
# VULN 5: Second-Order SQL Injection
# Data is stored safely via parameterized query, but retrieved and used
# unsafely in a different context later. The injection payload lies dormant
# in the database until the admin triggers the audit report.
# ============================================================================
@app.route("/api/register", methods=["POST"])
def register_user():
    data = request.get_json()
    username = data.get("username", "")
    bio = data.get("bio", "")

    # SAFE: This insert uses parameterized queries. No injection here.
    cursor.execute("INSERT INTO users (username, bio) VALUES (?, ?)", (username, bio))
    db_sql.commit()
    return jsonify({"status": "registered"})


@app.route("/api/admin/user_report")
def generate_user_report():
    # Step 1: Safely retrieve all usernames from the database
    cursor.execute("SELECT username FROM users")
    usernames = [row[0] for row in cursor.fetchall()]

    results = []
    for username in usernames:
        # VULNERABLE: The username was stored safely, but is now interpolated
        # directly into a raw SQL query. If a user registered with the name:
        #   admin' UNION SELECT password FROM credentials --
        # this query will execute the attacker's injected SQL.
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        results.extend(cursor.fetchall())

        # Log the query for audit (also stores the injected payload)
        cursor.execute("INSERT INTO audit_log (query) VALUES (?)", (query,))

    db_sql.commit()
    return jsonify({"report": results})


# ============================================================================
# VULN 6: NoSQL Injection via PyMongo Operator Injection
# The login endpoint passes raw JSON from the request directly into a
# MongoDB query. An attacker can inject query operators like $gt, $ne, $regex.
# ============================================================================
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # VULNERABLE: If the attacker sends:
    #   {"username": "admin", "password": {"$ne": ""}}
    # MongoDB interprets {"$ne": ""} as "password not equal to empty string",
    # which matches ANY non-empty password, bypassing authentication entirely.
    user = db_mongo.users.find_one({
        "username": username,
        "password": password  # BUG: raw dict from request, not a string
    })

    if user:
        return jsonify({"status": "logged_in", "user": str(user["_id"])})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/search", methods=["GET"])
def search_users():
    query_param = request.args.get("q", "")

    # VULNERABLE: Attacker can send q={"$regex": ".*"} as a JSON-encoded string.
    # If the app parses it as JSON and passes it to MongoDB, it bypasses
    # the intended text search and dumps all matching documents.
    import json
    try:
        search_filter = json.loads(query_param)
    except (json.JSONDecodeError, TypeError):
        search_filter = query_param

    results = list(db_mongo.users.find({"username": search_filter}))
    return jsonify({"results": [str(r) for r in results]})


# ============================================================================
# VULN 7: Business Logic Flaw - Negative Quantity/Price Exploitation
# The checkout endpoint doesn't validate that quantity and price are positive.
# An attacker can submit a negative quantity to receive a credit/refund.
# ============================================================================
@app.route("/api/checkout", methods=["POST"])
def checkout():
    data = request.get_json()
    items = data.get("items", [])

    total = 0
    for item in items:
        product_id = item.get("product_id")
        quantity = item.get("quantity", 1)  # Attacker sends -5

        # Fetch product from DB
        cursor.execute("SELECT price FROM products WHERE id = ?", (product_id,))
        row = cursor.fetchone()
        if not row:
            continue

        price = row[0]

        # VULNERABLE: No validation that quantity > 0.
        # If attacker sends quantity = -10 and price = 50.00,
        # the total becomes -500.00, meaning the company PAYS the attacker.
        line_total = price * quantity
        total += line_total

        # Reduce stock (negative quantity INCREASES stock)
        cursor.execute(
            "UPDATE products SET quantity = quantity - ? WHERE id = ?",
            (quantity, product_id)
        )

    # Process payment — negative total means a refund to the attacker's card
    charge_customer(total)
    db_sql.commit()
    return jsonify({"total_charged": total})


def charge_customer(amount):
    # Integrates with payment gateway. Negative amount = refund.
    pass


# ============================================================================
# VULN 8: Prototype Pollution Equivalent in Python
# via __class__.__bases__ / __subclasses__ manipulation.
# The merge_config function recursively merges untrusted dicts into objects,
# allowing an attacker to overwrite internal Python class attributes.
# ============================================================================
class AppConfig:
    debug = False
    secret_key = "default_secret"
    admin_enabled = False


def deep_merge(target, source):
    """
    VULNERABLE: Recursively merges source dict into target object.
    An attacker can send:
    {"__class__": {"__bases__": {"__subclasses__": "..."}}}
    or more practically:
    {"debug": true, "admin_enabled": true, "secret_key": "attacker_key"}

    Because there's no allowlist, ANY attribute can be overwritten,
    including internal Python dunder attributes if the target supports them.
    """
    for key, value in source.items():
        if isinstance(value, dict) and hasattr(target, key):
            deep_merge(getattr(target, key), value)
        else:
            setattr(target, key, value)  # BUG: no filtering of dangerous keys


config = AppConfig()


@app.route("/api/admin/config", methods=["PATCH"])
def update_config():
    data = request.get_json()
    # VULNERABLE: Merges raw user input into the global config object.
    # Attacker can set debug=True, admin_enabled=True, or overwrite secret_key.
    deep_merge(config, data)
    return jsonify({"status": "config updated", "debug": config.debug})
