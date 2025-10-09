from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory
from app.Cognito import signup_user, confirm_user, login_user, token_required, email_mfa
from dotenv import load_dotenv
import os
from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI, UploadFile, File
from app.aws_services import upload_to_s3, save_video_metadata
import uuid

app = Flask(__name__)

# --- Public Endpoints --- #
@app.route("/")
def index():
    return redirect(url_for("static", filename="login.html"))

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    resp = signup_user(data["username"], data["password"], data["email"])
    # If Cognito returned an error dict
    if "error" in resp:
        return {"error": resp["error"]}, 400
    return {"message": "User registered", "user_sub": resp["UserSub"]}

@app.route("/confirm", methods=["POST"])
def confirm_signup():
    data = request.json
    resp = confirm_user(data["username"], data["code"])
    if "error" in resp:
        return {"error": resp["error"]}, 400
    return {"message": "User confirmed"}

@app.route("/login", methods=["POST", "GET"])
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

    if "error" in result:
        print("❌ Cognito error:", result["error"])
        return {"error": result["error"]}, 401

    return {"error": "Unexpected Cognito response", "data": result}, 400

@app.route("/verify-mfa", methods=["POST"])
def verify_mfa():
    data = request.json
    session_id = data["session"]

    # Get OTP from frontend, prompt it only when needed
    mfa_result = email_mfa(data["username"], session_id, data["mfa_code"])
    if not mfa_result["success"]:
        return {"error": mfa_result.get("error") or f"Challenge: {mfa_result.get('challenge')}"}, 401

    id_token = mfa_result["IdToken"]
    access_token = mfa_result["AccessToken"]
    refresh_token = mfa_result["RefreshToken"]
    return jsonify({
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token
    })

# --- Protected Page --- #
@app.route("/index2.html")
def jobs_page():
    """Serve the dashboard page"""
    return send_from_directory('static', 'index2.html')

if __name__ == "__main__":
    app.run(debug=True)
