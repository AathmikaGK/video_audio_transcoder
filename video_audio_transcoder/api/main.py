import os
import uuid
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, request, redirect, jsonify, send_from_directory
from flask_cors import CORS

# Import our modules
from aws_services import (
    upload_to_s3, save_video_metadata, get_video_metadata,
    update_video_status, list_user_videos, send_job_to_queue,
    get_s3_presigned_url
)
from Cognito import (
    signup_user, confirm_user, login_user, email_mfa, verify_jwt
)

# Flask app
app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)

# ============== BASIC ROUTES ==============
@app.route("/")
def root():
    return redirect("/static/login.html")

@app.route("/index2.html")
def dashboard():
    return send_from_directory("static", "index2.html")

@app.get("/health")
def health():
    return {"status": "ok", "service": "api"}

# ============== AUTH ENDPOINTS ==============
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
    
    if isinstance(result, dict) and "error" in result:
        return {"error": result["error"]}, 401
    
    if isinstance(result, dict) and result.get("ChallengeName") == "EMAIL_OTP":
        return {
            "mfa_required": True,
            "challenge": "EMAIL_OTP",
            "session": result.get("Session"),
            "destination": result.get("ChallengeParameters", {}).get("CODE_DELIVERY_DESTINATION")
        }, 200
    
    if "AuthenticationResult" in result:
        tokens = result["AuthenticationResult"]
        return {
            "id_token": tokens.get("IdToken"),
            "access_token": tokens.get("AccessToken"),
            "refresh_token": tokens.get("RefreshToken")
        }, 200
    
    return {"error": "Unexpected Cognito response"}, 400

@app.post("/verify-mfa")
def http_verify_mfa():
    data = request.get_json(force=True)
    r = email_mfa(data["username"], data["session"], data["mfa_code"])
    if not r.get("success"):
        return {"error": r.get("error")}, 401
    return {
        "id_token": r["IdToken"],
        "access_token": r["AccessToken"],
        "refresh_token": r["RefreshToken"]
    }

# Helper to verify token from request
def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None, "Missing Authorization header"
    try:
        token = auth_header.split(" ")[1]
        user_data = verify_jwt(token)
        username = user_data.get("cognito:username") or user_data.get("username")
        return username, None
    except Exception as e:
        return None, str(e)

# ============== UPLOAD ENDPOINT ==============
@app.post("/upload/video")
def upload_video():
    username, error = get_current_user()
    if error:
        return {"error": error}, 401
    
    file = request.files.get("f")
    if not file or file.filename == "":
        return {"error": "No file uploaded"}, 400
    
    # Generate unique filename
    video_id = str(uuid.uuid4())
    original_filename = file.filename
    unique_filename = f"{video_id}_{original_filename}"
    
    # Upload to S3
    s3_url, s3_key, error = upload_to_s3(file, unique_filename)
    if error:
        return {"error": f"S3 upload failed: {error}"}, 500
    
    # Save metadata to DynamoDB
    success, error = save_video_metadata(video_id, username, s3_url, s3_key, original_filename)
    if not success:
        return {"error": f"Failed to save metadata: {error}"}, 500
    
    return {
        "id": video_id,
        "original_filename": original_filename,
        "s3_url": s3_url,
        "message": "Upload successful"
    }, 201

# ============== FILES ENDPOINT ==============
@app.get("/files")
def files_list():
    username, error = get_current_user()
    if error:
        return {"error": error}, 401
    
    videos, error = list_user_videos(username)
    if error:
        return {"error": f"Failed to list files: {error}"}, 500
    
    # Format response
    result = []
    for video in videos:
        result.append({
            "id": video.get("video_id"),
            "original_filename": video.get("original_filename"),
            "created_at": video.get("created_at"),
            "status": video.get("status", "uploaded")
        })
    
    return jsonify(result)

# ============== PROCESS ENDPOINT (NEW - SENDS TO SQS) ==============
@app.post("/process/<video_id>")
def process_video(video_id):
    username, error = get_current_user()
    if error:
        return {"error": error}, 401
    
    # Get video metadata
    video, error = get_video_metadata(video_id)
    if error or not video:
        return {"error": "Video not found"}, 404
    
    # Verify ownership
    if video.get("username") != username:
        return {"error": "Unauthorized"}, 403
    
    # Check if already processing
    status = video.get("status")
    if status in ["queued", "processing"]:
        return {"error": "Job already in progress", "status": status}, 400
    
    # Send to SQS
    job_id, error = send_job_to_queue(video_id, video["s3_key"], username)
    if error:
        return {"error": f"Failed to queue job: {error}"}, 500
    
    # Update status in DynamoDB
    update_video_status(video_id, "queued", job_id=job_id)
    
    return {
        "id": job_id,
        "video_id": video_id,
        "status": "queued",
        "message": "Job queued successfully"
    }, 201

# ============== JOBS ENDPOINT ==============
@app.get("/jobs")
def jobs_list():
    username, error = get_current_user()
    if error:
        return {"error": error}, 401
    
    videos, error = list_user_videos(username)
    if error:
        return {"error": f"Failed to list jobs: {error}"}, 500
    
    # Filter only videos with jobs (status != uploaded)
    jobs = []
    for video in videos:
        if video.get("status") != "uploaded":
            jobs.append({
                "id": video.get("job_id", video.get("video_id")),
                "video_id": video.get("video_id"),
                "status": video.get("status"),
                "created_at": video.get("created_at"),
                "updated_at": video.get("updated_at"),
                "error_message": video.get("error_message")
            })
    
    return jsonify(jobs)

# ============== DOWNLOAD ENDPOINTS ==============
@app.get("/download/audio/<video_id>")
def download_audio(video_id):
    # Check for token in query param (for <a> tag downloads)
    token = request.args.get("access_token")
    if token:
        try:
            user_data = verify_jwt(token)
            username = user_data.get("cognito:username") or user_data.get("username")
        except:
            return {"error": "Invalid token"}, 401
    else:
        username, error = get_current_user()
        if error:
            return {"error": error}, 401
    
    video, error = get_video_metadata(video_id)
    if error or not video:
        return {"error": "Video not found"}, 404
    
    if video.get("username") != username:
        return {"error": "Unauthorized"}, 403
    
    audio_key = video.get("audio_s3_key")
    if not audio_key:
        return {"error": "Audio not ready"}, 404
    
    url, error = get_s3_presigned_url(audio_key)
    if error:
        return {"error": "Failed to generate download URL"}, 500
    
    return redirect(url)

@app.get("/download/transcript/<video_id>")
def download_transcript(video_id):
    # Check for token in query param
    token = request.args.get("access_token")
    if token:
        try:
            user_data = verify_jwt(token)
            username = user_data.get("cognito:username") or user_data.get("username")
        except:
            return {"error": "Invalid token"}, 401
    else:
        username, error = get_current_user()
        if error:
            return {"error": error}, 401
    
    video, error = get_video_metadata(video_id)
    if error or not video:
        return {"error": "Video not found"}, 404
    
    if video.get("username") != username:
        return {"error": "Unauthorized"}, 403
    
    transcript_key = video.get("transcript_s3_key")
    if not transcript_key:
        return {"error": "Transcript not ready"}, 404
    
    url, error = get_s3_presigned_url(transcript_key)
    if error:
        return {"error": "Failed to generate download URL"}, 500
    
    return redirect(url)

# ============== RUN ==============
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)