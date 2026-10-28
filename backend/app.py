from flask import Flask, jsonify, g

from auth import auth_bp
from auth_middleware import token_required
from file_routes import file_bp
from security_routes import security_bp
from flask_cors import CORS
app = Flask(__name__)
CORS(app)

# Register application routes
app.register_blueprint(auth_bp)
app.register_blueprint(file_bp)
app.register_blueprint(security_bp)


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "CipherVault",
        "message": "A Secure File Sharing and Threat Detection System",
        "status": "Backend is running"
    })


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "backend": "Flask",
        "database": "MongoDB",
        "encryption": "AES-256-GCM",
        "key_protection": "RSA-OAEP"
    })


@app.route("/api/auth/me", methods=["GET"])
@token_required
def current_user():
    return jsonify({
        "message": "Authentication successful.",
        "user": g.current_user
    }), 200


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )