import os
import re
from datetime import datetime, timezone, timedelta

import jwt
from dotenv import load_dotenv
from flask import Blueprint, request, jsonify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from pymongo.errors import DuplicateKeyError

from database import users_collection

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")

if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET is missing. Add it to the backend .env file."
    )

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")
password_hasher = PasswordHasher()


def valid_email(email):
    return bool(
        re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            email
        )
    )


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    name = data.get("name", "")
    email = data.get("email", "")
    password = data.get("password", "")

    if not all(isinstance(value, str) for value in (name, email, password)):
        return jsonify({
            "error": "Name, email, and password must be text."
        }), 400

    name = name.strip()
    email = email.strip().lower()

    if not name or not email or not password:
        return jsonify({
            "error": "Name, email, and password are required."
        }), 400

    if len(name) > 100 or not valid_email(email):
        return jsonify({
            "error": "Please provide a valid name and email address."
        }), 400

    if len(password) < 12:
        return jsonify({
            "error": "Password must contain at least 12 characters."
        }), 400

    if len(password.encode("utf-8")) > 1024:
        return jsonify({
            "error": "Password is too long."
        }), 400

    user = {
        "name": name,
        "email": email,
        "password_hash": password_hasher.hash(password),
        "role": "user",
        "created_at": datetime.now(timezone.utc)
    }

    try:
        result = users_collection.insert_one(user)

        return jsonify({
            "message": "Registration successful.",
            "user_id": str(result.inserted_id)
        }), 201

    except DuplicateKeyError:
        return jsonify({
            "error": "An account with this email already exists."
        }), 409


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "")
    password = data.get("password", "")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({
            "error": "Email and password must be text."
        }), 400

    email = email.strip().lower()

    if not email or not password:
        return jsonify({
            "error": "Email and password are required."
        }), 400

    user = users_collection.find_one({"email": email})

    if not user:
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    try:
        password_hasher.verify(user["password_hash"], password)

    except (VerifyMismatchError, VerificationError):
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    if password_hasher.check_needs_rehash(user["password_hash"]):
        users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password_hash": password_hasher.hash(password)
                }
            }
        )

    token = jwt.encode(
        {
            "sub": str(user["_id"]),
            "exp": datetime.now(timezone.utc) + timedelta(hours=2)
        },
        JWT_SECRET,
        algorithm="HS256"
    )

    return jsonify({
        "message": "Login successful.",
        "token": token,
        "user": {
            "id": str(user["_id"]),
            "name": user["name"],
            "email": user["email"],
            "role": user.get("role", "user")
        }
    }), 200