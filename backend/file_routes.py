import os
import hashlib
from datetime import datetime, timezone
from io import BytesIO

from flask import Blueprint, request, jsonify, g, send_file
from bson import ObjectId
from bson.errors import InvalidId
from werkzeug.utils import secure_filename

from auth_middleware import token_required
from database import files_collection, security_logs_collection
from database import users_collection
from crypto_service import encrypt_file_data, decrypt_file_data


file_bp = Blueprint("files", __name__, url_prefix="/api/files")

UPLOAD_FOLDER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "uploads"
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024


def write_security_log(user_id, event, file_id, details):
    security_logs_collection.insert_one({
        "user_id": user_id,
        "event": event,
        "file_id": str(file_id),
        "timestamp": datetime.now(timezone.utc),
        "details": details
    })


@file_bp.route("/share", methods=["POST"])
@token_required
def share_file():
    data = request.get_json(silent=True) or {}

    file_id = data.get("file_id")
    recipient_email = data.get("email", "").strip().lower()

    if not file_id or not recipient_email:
        return jsonify({
            "error": "File ID and recipient email are required."
        }), 400

    try:
        object_id = ObjectId(file_id)
    except (InvalidId, TypeError):
        return jsonify({"error": "Invalid file ID."}), 400

    # Only the file owner can share the file.
    file_record = files_collection.find_one({
        "_id": object_id,
        "owner_id": g.current_user["id"]
    })

    if not file_record:
        write_security_log(
            g.current_user["id"],
            "FILE_SHARE_DENIED",
            file_id,
            "Sharing denied because the file was not owned by the requester."
        )

        return jsonify({
            "error": "File not found or you are not its owner."
        }), 404

    # Find the recipient's registered account.
    recipient = users_collection.find_one({
        "email": recipient_email
    })

    if not recipient:
        return jsonify({
            "error": "No registered user found with that email."
        }), 404

    recipient_id = str(recipient["_id"])

    if recipient_id == g.current_user["id"]:
        return jsonify({
            "error": "You cannot share a file with yourself."
        }), 400

    # Add the recipient without creating duplicate entries.
    files_collection.update_one(
        {"_id": object_id},
        {"$addToSet": {"shared_with": recipient_id}}
    )

    write_security_log(
        g.current_user["id"],
        "FILE_SHARED",
        file_id,
        f"File shared with registered user {recipient_email}."
    )

    return jsonify({
        "message": "File shared successfully.",
        "file_id": file_id,
        "shared_with": recipient_email
    }), 200


@file_bp.route("/upload", methods=["POST"])
@token_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file was provided."}), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({"error": "Please select a file."}), 400

    filename = secure_filename(uploaded_file.filename)

    if not filename:
        return jsonify({"error": "Invalid filename."}), 400

    file_data = uploaded_file.read(MAX_FILE_SIZE + 1)

    if not file_data:
        return jsonify({"error": "The file is empty."}), 400

    if len(file_data) > MAX_FILE_SIZE:
        return jsonify({"error": "Maximum file size is 10 MB."}), 413

    encrypted = encrypt_file_data(file_data)

    file_id = ObjectId()
    encrypted_filename = f"{file_id}.enc"
    encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)

    try:
        with open(encrypted_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted["ciphertext"])

        file_record = {
            "_id": file_id,
            "owner_id": g.current_user["id"],
            "original_filename": filename,
            "encrypted_filename": encrypted_filename,
            "encrypted_aes_key": encrypted["encrypted_aes_key"].hex(),
            "nonce": encrypted["nonce"].hex(),
            "sha256": hashlib.sha256(file_data).hexdigest(),
            "size_bytes": len(file_data),
            "uploaded_at": datetime.now(timezone.utc),
            "status": "encrypted"
        }

        files_collection.insert_one(file_record)

        write_security_log(
            g.current_user["id"],
            "FILE_UPLOADED",
            file_id,
            "File encrypted and uploaded successfully."
        )

        return jsonify({
            "message": "File encrypted and uploaded successfully.",
            "file": {
                "id": str(file_id),
                "filename": filename,
                "size_bytes": len(file_data),
                "encryption": "AES-256-GCM",
                "key_protection": "RSA-OAEP",
                "status": "encrypted"
            }
        }), 201

    except Exception:
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

        return jsonify({
            "error": "File upload failed."
        }), 500


@file_bp.route("/my", methods=["GET"])
@token_required
def list_my_files():
    current_user_id = g.current_user["id"]

    records = files_collection.find({
        "owner_id": current_user_id
    }).sort("uploaded_at", -1)

    files = []

    for record in records:
        files.append({
            "id": str(record["_id"]),
            "filename": record.get("original_filename", "Unknown file"),
            "size_bytes": record.get("size_bytes", 0),
            "uploaded_at": (
                record["uploaded_at"].isoformat()
                if record.get("uploaded_at")
                else None
            ),
            "status": record.get("status", "unknown")
        })

    return jsonify({"files": files}), 200


@file_bp.route("/shared-with-me", methods=["GET"])
@token_required
def list_shared_files():
    current_user_id = g.current_user["id"]

    records = files_collection.find({
        "shared_with": current_user_id
    }).sort("uploaded_at", -1)

    files = []

    for record in records:
        files.append({
            "id": str(record["_id"]),
            "filename": record.get("original_filename", "Unknown file"),
            "size_bytes": record.get("size_bytes", 0),
            "uploaded_at": (
                record["uploaded_at"].isoformat()
                if record.get("uploaded_at")
                else None
            ),
            "status": record.get("status", "unknown")
        })

    return jsonify({
        "message": "Shared files retrieved successfully.",
        "count": len(files),
        "files": files
    }), 200


@file_bp.route("/download/<file_id>", methods=["GET"])
@token_required
def download_file(file_id):
    try:
        object_id = ObjectId(file_id)
    except (InvalidId, TypeError):
        return jsonify({"error": "Invalid file ID."}), 400

    # Allow only the owner or an explicitly authorized recipient.
    record = files_collection.find_one({
        "_id": object_id,
        "$or": [
            {"owner_id": g.current_user["id"]},
            {"shared_with": g.current_user["id"]}
        ]
    })

    if not record:
        write_security_log(
            g.current_user["id"],
            "FILE_ACCESS_DENIED",
            file_id,
            "File does not exist or does not belong to this user."
        )

        return jsonify({
            "error": "File not found or access denied."
        }), 404

    encrypted_path = os.path.join(
        UPLOAD_FOLDER,
        record["encrypted_filename"]
    )

    if not os.path.isfile(encrypted_path):
        return jsonify({
            "error": "Encrypted file is missing."
        }), 404

    try:
        with open(encrypted_path, "rb") as encrypted_file:
            ciphertext = encrypted_file.read()

        plaintext = decrypt_file_data(
            ciphertext,
            bytes.fromhex(record["nonce"]),
            bytes.fromhex(record["encrypted_aes_key"])
        )

        actual_hash = hashlib.sha256(plaintext).hexdigest()

        if actual_hash != record["sha256"]:
            write_security_log(
                g.current_user["id"],
                "FILE_INTEGRITY_FAILURE",
                file_id,
                "Downloaded file failed the SHA-256 integrity check."
            )

            return jsonify({
                "error": "File integrity verification failed."
            }), 500

        write_security_log(
            g.current_user["id"],
            "FILE_DOWNLOADED",
            file_id,
            "File decrypted and downloaded successfully."
        )

        return send_file(
            BytesIO(plaintext),
            as_attachment=True,
            download_name=record["original_filename"],
            mimetype="application/octet-stream"
        )

    except Exception:
        return jsonify({
            "error": "Unable to decrypt the file."
        }), 500