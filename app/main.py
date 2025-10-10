# ~/app/app/main.py

import os
import uuid
import traceback
from werkzeug.utils import secure_filename

from flask import (
    Flask, request, redirect, url_for, jsonify, send_from_directory
)

from dotenv import load_dotenv
load_dotenv()

# ==== CONFIG FROM ENV ====
AWS_REGION = os.getenv("COGNITO_REGION", "ap-southeast-2")
S3_BUCKET  = os.getenv("S3_BUCKET_NAME")
DDB_TABLE  = os.getenv("DYNAMODB_TABLE")

# ---- Cognito helpers (unchanged) ----
from app.Cognito import (
    signup_user, confirm_user, login_user, email_mfa
)

# ---- Optional aws_services helpers (we'll gracefully fallback if missing) ----
_upload_to_s3 = None
_save_video_metadata = None
try:
    from app.aws_services import upload_to_s3 as _upload_to_s3
    from app.aws_services import save_video_metadata as _save_video_metadata
except Exception:
    # We'll log and use direct boto3 fallback below
    pass

# ---- Boto3 fallback clients (also used for listing from DynamoDB) ----
import boto3
s3_client = boto3.client("s3", region_name=AWS_REGION)
ddb       = boto3.resource("dynamodb", region_name=AWS_REGION)
ddb_table = ddb.Table(DDB_TABLE)

# ---- Flask app ----
app = Flask(__name__)


# -------------------------------------------------
# Public / Auth endpoints (unchanged from your flow)
# -------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("static", filename="login.html"))


@app.route("/signup", methods=["POST"])
def signup():
    data = request.json or {}
    resp = signup_user(data["username"], data["password"], data["email"])
    if "error" in resp:
        return {"error": resp["error"]}, 400
    return {"message": "User registered", "user_sub": resp["UserSub"]}


@app.route("/confirm", methods=["POST"])
def confirm_signup():
    data = request.json or {}
    resp = confirm_user(data["username"], data["code"])
    if "error" in resp:
        return {"error": resp["error"]}, 400
    return {"message": "User confirmed"}


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    result = login_user(data["username"], data["password"])

    if "AuthenticationResult" in result:
        tokens = result["AuthenticationResult"]
        return {
            "id_token": tokens.get("IdToken"),
            "access_token": tokens.get("AccessToken"),
            "refresh_token": tokens.get("RefreshToken"),
        }

    if result.get("ChallengeName") == "EMAIL_OTP":
        return jsonify({
            "challenge": "EMAIL_OTP",
            "session": result.get("Session"),
            "destination": result.get("ChallengeParameters", {}).get(
                "CODE_DELIVERY_DESTINATION", "email"
            ),
        }), 200

    if "error" in result:
        return {"error": result["error"]}, 401

    return {"error": "Unexpected Cognito response", "data": result}, 400


@app.route("/verify-mfa", methods=["POST"])
def verify_mfa():
    data = request.json or {}
    mfa_result = email_mfa(data["username"], data["session"], data["mfa_code"])
    if not mfa_result.get("success"):
        return {
            "error": mfa_result.get("error")
                     or f"Challenge: {mfa_result.get('challenge')}"
        }, 401
    return jsonify({
        "id_token": mfa_result["IdToken"],
        "access_token": mfa_result["AccessToken"],
        "refresh_token": mfa_result["RefreshToken"],
    })


# -------------------------
# Protected UI entry point
# -------------------------
@app.route("/index2.html")
def jobs_page():
    return send_from_directory('static', 'index2.html')


# -------------------------
# S3 upload + DynamoDB save
# -------------------------
def _s3_fallback_upload(fileobj_or_path: str | bytes, key: str) -> str:
    """
    If app.aws_services.upload_to_s3 isn't working, use a robust direct upload.
    Accepts either a filepath (str path) or a file-like object (stream).
    """
    # Prefer streaming upload when we can
    if hasattr(fileobj_or_path, "read"):
        s3_client.upload_fileobj(fileobj_or_path, S3_BUCKET, key)
    elif isinstance(fileobj_or_path, (bytes, bytearray)):
        s3_client.put_object(Bucket=S3_BUCKET, Key=key, Body=fileobj_or_path)
    else:
        # path string
        s3_client.upload_file(fileobj_or_path, S3_BUCKET, key)

    return f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{key}"


@app.route("/upload", methods=["POST"])
def upload_video():
    """
    Multipart form:
      - file: video file
      - username (optional, for metadata only)
    """
    try:
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "No file uploaded"}), 400

        username = request.form.get("username", "anonymous")
        original = f.filename or "upload.bin"
        key = f"{uuid.uuid4()}_{secure_filename(original)}"

        # Try module helper first; if not present, fallback to direct boto3
        if _upload_to_s3:
            s3_url = _upload_to_s3(f.stream, key)  # let helper handle stream/key
        else:
            s3_url = _s3_fallback_upload(f.stream, key)

        # Save minimal metadata in DynamoDB
        item_video_id = str(uuid.uuid4())
        if _save_video_metadata:
            _save_video_metadata(item_video_id, key, "uploaded", s3_url)
        else:
            ddb_table.put_item(Item={
                "video_id": item_video_id,
                "filename": key,
                "status": "uploaded",
                "s3_url": s3_url,
                "uploader": username,
            })

        return jsonify({
            "message": "Upload successful",
            "video_id": item_video_id,
            "filename": key,
            "url": s3_url
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "error": "Upload failed",
            "detail": str(e)
        }), 500


# -------------------------
# List files from DynamoDB
# -------------------------
@app.route("/files", methods=["GET"])
def list_files():
    """
    Return a simple list of uploaded items from DynamoDB.
    Your table has only a HASH key on 'video_id', so we use a Scan
    (fine for demo; for production add a GSI or change schema).
    """
    try:
        resp = ddb_table.scan()
        items = resp.get("Items", [])
        # Normalize/limit fields for the UI
        out = [{
            "video_id": it.get("video_id"),
            "filename": it.get("filename"),
            "status": it.get("status"),
            "s3_url": it.get("s3_url")
        } for it in items]
        return jsonify(out)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# -------------------------
# Jobs stub (so UI stops erroring)
# -------------------------
@app.route("/jobs", methods=["GET"])
def list_jobs():
    """
    Stub for now. Return an empty list so the dashboard renders without errors.
    Later you can add real transcoding jobs and persist their status in DynamoDB or RDS.
    """
    return jsonify([])


# -------------------------
# Health
# -------------------------
@app.route("/health")
def health():
    return {"status": "ok"}
