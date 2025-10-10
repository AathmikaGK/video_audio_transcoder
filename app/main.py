# app/main.py
import os
import uuid
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

from flask import (
    Flask, request, redirect, url_for, jsonify, send_from_directory
)

# --- AWS (S3 + DynamoDB) ---
import boto3
AWS_REGION = os.getenv("COGNITO_REGION", "ap-southeast-2")
S3_BUCKET = os.getenv("S3_BUCKET_NAME", "a2-group75")
DDB_TABLE = os.getenv("DYNAMODB_TABLE", "a2-group75-videos")

s3 = boto3.client("s3", region_name=AWS_REGION)
ddb = boto3.resource("dynamodb", region_name=AWS_REGION).Table(DDB_TABLE)

# --- Cognito helpers (your existing module) ---
from app.Cognito import (
    signup_user, confirm_user, login_user, email_mfa
)

# ------------------------------------------------------------------------------
# Flask app
# ------------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", static_url_path="/static")


# ------------------------------------------------------------------------------
# Basic pages
# ------------------------------------------------------------------------------
@app.route("/")
def root():
    # serve the login page from /static/login.html
    return redirect(url_for("static", filename="login.html"))


@app.route("/index2.html")
def dashboard():
    # serve your dashboard page
    return send_from_directory("static", "index2.html")


@app.get("/health")
def health():
    return {"status": "ok"}


# ------------------------------------------------------------------------------
# Auth endpoints (Cognito)
# ------------------------------------------------------------------------------
@app.post("/signup")
def http_signup():
    data = request.get_json(force=True)
    resp = signup_user(data["username"], data["password"], data["email"])
    if isinstance(resp, dict) and "error" in resp:
        return {"error": resp["error"]}, 400
    return {"message": "User registered", "user_sub": resp.get("UserSub")}


@app.post("/confirm")
def http_confirm():
    data = request.get_json(force=True)
    resp = confirm_user(data["username"], data["code"])
    if isinstance(resp, dict) and "error" in resp:
        return {"error": resp["error"]}, 400
    return {"message": "User confirmed"}


@app.route("/login", methods=["POST"])
def http_login():
    data = request.get_json(force=True)
    result = login_user(data["username"], data["password"])

    # If Cognito returned an error dict
    if isinstance(result, dict) and "error" in result:
        return {"error": result["error"]}, 401

    # MFA challenge
    if isinstance(result, dict) and result.get("ChallengeName") == "EMAIL_OTP":
        return {
            "mfa_required": True,
            "challenge": "EMAIL_OTP",
            "session": result.get("Session"),
            "destination": result.get("ChallengeParameters", {}).get("CODE_DELIVERY_DESTINATION")
        }, 200

    # Normal sign in
    if "AuthenticationResult" in result:
        tokens = result["AuthenticationResult"]
        return {
            "id_token": tokens.get("IdToken"),
            "access_token": tokens.get("AccessToken"),
            "refresh_token": tokens.get("RefreshToken")
        }, 200

    return {"error": "Unexpected Cognito response", "data": result}, 400


@app.post("/verify-mfa")
def http_verify_mfa():
    data = request.get_json(force=True)
    r = email_mfa(data["username"], data["session"], data["mfa_code"])
    if not r.get("success"):
        return {"error": r.get("error") or f"Challenge: {r.get('challenge')}"}, 401
    return {
        "id_token": r["IdToken"],
        "access_token": r["AccessToken"],
        "refresh_token": r["RefreshToken"]
    }


# ------------------------------------------------------------------------------
# Persistence: S3 upload + DynamoDB metadata
# ------------------------------------------------------------------------------
def save_video_metadata(video_id: str, username: str, s3_url: str):
    ddb.put_item(
        Item={
            "video_id": video_id,                   # PK
            "username": username,
            "s3_url": s3_url,
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
    )


def list_user_videos(username: str):
    # simplest approach: Scan + filter (ok for assignment scale)
    resp = ddb.scan()
    items = resp.get("Items", [])
    return [it for it in items if it.get("username") == username]


@app.post("/upload")
def upload_video():
    # multipart/form-data: file + username
    file = request.files.get("file")
    username = request.form.get("username", "anonymous")

    if not file or file.filename == "":
        return {"error": "No file uploaded"}, 400

    # build a unique key inside the bucket
    key = f"uploads/{uuid.uuid4()}_{file.filename}"

    try:
        # upload to S3
        s3.upload_fileobj(
            Fileobj=file,
            Bucket=S3_BUCKET,
            Key=key,
            ExtraArgs={"ContentType": file.mimetype or "application/octet-stream"}
        )
        s3_url = f"s3://{S3_BUCKET}/{key}"

        # write metadata to DynamoDB
        video_id = str(uuid.uuid4())
        save_video_metadata(video_id, username, s3_url)

        return {"message": "Upload successful", "url": s3_url, "video_id": video_id}
    except Exception as e:
        # log to server logs; return safe error to client
        print("Upload error:", repr(e))
        return {"error": "Upload failed"}, 500


@app.get("/files")
def files_me():
    # Very simple auth model: username query param from the client
    # (Good enough for demo/assignment; tokens can be validated later)
    username = request.args.get("username", "anonymous")
    try:
        items = list_user_videos(username)
        # Shape to something your UI can use
        return jsonify(items)
    except Exception as e:
        print("List files error:", repr(e))
        return {"error": "Failed to load files"}, 500


@app.get("/jobs")
def jobs_me():
    # Stub: if your UI calls /jobs, return an empty list instead of error
    # You can later implement real processing + job records in DDB or RDS.
    return jsonify([])


# ------------------------------------------------------------------------------
# OPTIONAL: Pre-signed upload (for +2 marks)
# ------------------------------------------------------------------------------
@app.post("/presign-upload")
def presign_upload():
    data = request.get_json(force=True)
    filename = data.get("filename")
    if not filename:
        return {"error": "filename required"}, 400

    key = f"uploads/{uuid.uuid4()}_{filename}"
    try:
        url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": S3_BUCKET, "Key": key, "ContentType": "application/octet-stream"},
            ExpiresIn=900,  # 15 minutes
            HttpMethod="PUT",
        )
        return {"url": url, "bucket": S3_BUCKET, "key": key}
    except Exception as e:
        print("Presign error:", repr(e))
        return {"error": "Failed to create presigned URL"}, 500


# ------------------------------------------------------------------------------
# Run local (not used in prod with gunicorn)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
