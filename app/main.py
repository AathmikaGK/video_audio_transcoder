# app/main.py
from flask import Flask, request, redirect, url_for, jsonify, send_from_directory
from app.Cognito import signup_user, confirm_user, login_user, email_mfa
import os
import uuid

# --- Flask app ---
app = Flask(__name__)

# --------- Public endpoints ----------
@app.route("/")
def index():
    return redirect(url_for("static", filename="login.html"))

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    resp = signup_user(data["username"], data["password"], data["email"])
    if "error" in resp:
        return {"error": resp["error"]}, 400
    return {"message": "User registered", "user_sub": resp.get("UserSub")}

@app.route("/confirm", methods=["POST"])
def confirm_signup():
    data = request.json
    resp = confirm_user(data["username"], data["code"])
    if "error" in resp:
        return {"error": resp["error"]}, 400
    return {"message": "User confirmed"}

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    result = login_user(data["username"], data["password"])

    if "AuthenticationResult" in result:
        tokens = result["AuthenticationResult"]
        return {
            "id_token": tokens.get("IdToken"),
            "access_token": tokens.get("AccessToken"),
            "refresh_token": tokens.get("RefreshToken")
        }

    if result.get("ChallengeName") == "EMAIL_OTP":
        # Frontend should show OTP field and then POST to /verify-mfa
        return {
            "challenge": "EMAIL_OTP",
            "session": result.get("Session"),
            "destination": result.get("ChallengeParameters", {}).get("CODE_DELIVERY_DESTINATION")
        }, 200

    if "error" in result:
        print("❌ Cognito error:", result["error"])
        return {"error": result["error"]}, 401

    return {"error": "Unexpected Cognito response", "data": result}, 400

@app.route("/verify-mfa", methods=["POST"])
def verify_mfa():
    data = request.json
    mfa_result = email_mfa(data["username"], data["session"], data["mfa_code"])
    if not mfa_result["success"]:
        return {"error": mfa_result.get("error") or f"Challenge: {mfa_result.get('challenge')}"}, 401

    return jsonify({
        "id_token": mfa_result["IdToken"],
        "access_token": mfa_result["AccessToken"],
        "refresh_token": mfa_result["RefreshToken"]
    })

# --------- Static protected page ----------
@app.route("/index2.html")
def jobs_page():
    return send_from_directory('static', 'index2.html')


# ========= Persistence wiring (S3 + DynamoDB) =========
from app.aws_services import upload_to_s3, save_video_metadata

@app.route("/upload", methods=["POST"])
def upload_video():
    """
    Accept a file upload, store raw object in S3 and a metadata row in DynamoDB.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file field"}), 400

    f = request.files["file"]
    if not f or f.filename.strip() == "":
        return jsonify({"error": "No file uploaded"}), 400

    username = request.form.get("username", "anonymous")
    video_id = str(uuid.uuid4())

    # store with a stable key: user/uuid/original-name
    safe_name = f.filename.replace("/", "_")
    s3_key = f"{username}/{video_id}/{safe_name}"

    stored_key = upload_to_s3(f, s3_key, content_type=f.mimetype or "application/octet-stream")
    if not stored_key:
        return jsonify({"error": "Upload failed"}), 500

    meta = save_video_metadata(
        video_id=video_id,
        owner=username,
        filename=safe_name,
        s3_key=stored_key,
        status="uploaded",
    )
    if not meta:
        # If metadata save failed, you still stored the object; report partial success clearly
        return jsonify({"error": "Saved to S3 but metadata failed"}), 500

    return jsonify({"message": "Upload successful", "video_id": video_id, "s3_key": stored_key})
