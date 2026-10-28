from functools import wraps

import jwt
from flask import request, jsonify, g
from bson import ObjectId
from bson.errors import InvalidId

from auth import JWT_SECRET
from database import users_collection


def token_required(function):
    @wraps(function)
    def decorated(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")

        if not authorization.startswith("Bearer "):
            return jsonify({
                "error": "Authentication token is required."
            }), 401

        token = authorization.split(" ", 1)[1].strip()

        if not token:
            return jsonify({
                "error": "Authentication token is required."
            }), 401

        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=["HS256"]
            )

            user_id = payload.get("sub")

            if not user_id:
                return jsonify({
                    "error": "Invalid authentication token."
                }), 401

            try:
                object_id = ObjectId(user_id)
            except (InvalidId, TypeError):
                return jsonify({
                    "error": "Invalid authentication token."
                }), 401

            user = users_collection.find_one({"_id": object_id})

            if not user:
                return jsonify({
                    "error": "User account not found."
                }), 401

            g.current_user = {
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "role": user.get("role", "user")
            }

        except jwt.ExpiredSignatureError:
            return jsonify({
                "error": "Authentication token has expired. Please log in again."
            }), 401

        except jwt.InvalidTokenError:
            return jsonify({
                "error": "Invalid authentication token."
            }), 401

        return function(*args, **kwargs)

    return decorated