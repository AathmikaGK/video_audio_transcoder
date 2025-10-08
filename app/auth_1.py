# auth.py
import os, time, hmac, hashlib, base64
from typing import Optional, Dict, Any, List
import requests
import boto3
from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from fastapi.security import OAuth2PasswordBearer
from jose import jwk, jwt as jose_jwt
from jose.utils import base64url_decode
from flask import Flask
from dotenv import load_dotenv
import os

load_dotenv()  
app = Flask(__name__)
# ====== Config via environment ======
app.secret_key = os.getenv("FLASK_SECRET_KEY")
COGNITO_REGION = os.getenv("COGNITO_REGION", "ap-southeast-2")
USERPOOL_ID = os.getenv("COGNITO_USERPOOL_ID")               # e.g. ap-southeast-2_ABC123
CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")           # app client id (no secret for Hosted UI)
APP_CLIENT_SECRET = os.getenv("COGNITO_APP_CLIENT_SECRET")   # optional; only if your client has a secret

cognito = boto3.client("cognito-idp", region_name=REGION)

#ISSUER = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USERPOOL_ID}"
#JWKS_URL = f"{ISSUER}/.well-known/jwks.json"

# Keep OAuth2PasswordBearer so your existing Depends(...) calls still work
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

# FastAPI router for /auth endpoints (sign up, confirm, programmatic login)
router = APIRouter(prefix="/auth", tags=["auth"])

# ====== JWKS cache handling ======
_JWKS_CACHE: List[Dict[str, Any]] = []
def _load_jwks(refresh: bool = False) -> List[Dict[str, Any]]:
    global _JWKS_CACHE
    if refresh or not _JWKS_CACHE:
        try:
            r = requests.get(JWKS_URL, timeout=5)
            r.raise_for_status()
            _JWKS_CACHE = r.json().get("keys", [])
        except Exception:
            _JWKS_CACHE = []
    return _JWKS_CACHE

def _find_key(kid: str) -> Optional[Dict[str, Any]]:
    keys = _load_jwks(refresh=False)
    for k in keys:
        if k.get("kid") == kid:
            return k
    keys = _load_jwks(refresh=True)  # try once more after refresh
    for k in keys:
        if k.get("kid") == kid:
            return k
    return None

# ====== Token verification ======
def _decode_and_validate_cognito_jwt(token: str) -> Dict[str, Any]:
    """
    Validates a Cognito JWT (id_token or access_token):
      - verifies signature using JWKS
      - verifies issuer
      - verifies exp
      - for id_token: verifies aud == APP_CLIENT_ID
      - for access_token: verifies client_id == APP_CLIENT_ID
    Returns claims dict, else raises HTTPException(401).
    """
    if not USERPOOL_ID or not APP_CLIENT_ID:
        raise HTTPException(500, "Cognito not configured: set COGNITO_USERPOOL_ID and COGNITO_APP_CLIENT_ID")

    try:
        headers = jose_jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            raise ValueError("Missing kid")

        key = _find_key(kid)
        if not key:
            raise ValueError("Signing key not found")

        # Verify signature manually
        public_key = jwk.construct(key)
        message, encoded_sig = token.rsplit(".", 1)
        decoded_sig = base64url_decode(encoded_sig.encode())
        if not public_key.verify(message.encode(), decoded_sig):
            raise ValueError("Invalid signature")

        # Now safely read claims and check standard fields
        claims = jose_jwt.get_unverified_claims(token)

        # issuer
        if claims.get("iss") != ISSUER:
            raise ValueError("Issuer mismatch")

        # expiry
        if "exp" not in claims or time.time() > float(claims["exp"]):
            raise ValueError("Token expired")

        # token_use: "id" or "access"
        tuse = claims.get("token_use")
        if tuse == "id":
            if claims.get("aud") != APP_CLIENT_ID:
                raise ValueError("audience mismatch")
        elif tuse == "access":
            # access_token has client_id instead of aud
            if claims.get("client_id") != APP_CLIENT_ID:
                raise ValueError("client_id mismatch")
        else:
            raise ValueError("Unsupported token_use")

        return claims

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate Cognito credentials: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
) -> Dict[str, Any]:
    """
    Accept JWT from Authorization: Bearer <token>
    OR from query (?access_token= / ?token=) for simple <a> downloads.
    Returns: {"username", "email", "groups", "token"}
    """
    if not token:
        token = request.query_params.get("access_token") or request.query_params.get("token")
    if not token:
        raise HTTPException(401, "Missing token", headers={"WWW-Authenticate": "Bearer"})

    claims = _decode_and_validate_cognito_jwt(token)
    username = claims.get("cognito:username") or claims.get("username") or claims.get("sub")
    groups = claims.get("cognito:groups", [])
    if not isinstance(groups, list):
        groups = []
    return {"username": username, "email": claims.get("email"), "groups": groups, "token": token}

def require_admin(user=Depends(get_current_user)):
    if "admin" not in (user.get("groups") or []):
        raise HTTPException(403, "Admin privileges required")
    return user

# ====== Helpers for server-side signup/confirm/login ======
def _cognito_client():
    return boto3.client("cognito-idp", region_name=COGNITO_REGION)

def _secret_hash(username: str) -> Optional[str]:
    """
    Cognito 'SECRET_HASH' is required only if the app client has a secret.
    Matches your sample scripts (signUp.py/authenticate.py):contentReference[oaicite:6]{index=6}:contentReference[oaicite:7]{index=7}.
    """
    if not APP_CLIENT_SECRET:
        return None
    msg = bytes(username + APP_CLIENT_ID, "utf-8")
    key = bytes(APP_CLIENT_SECRET, "utf-8")
    return base64.b64encode(hmac.new(key, msg, hashlib.sha256).digest()).decode()

# ====== Endpoints mirroring your scripts (optional for Hosted UI, useful for testing) ======

@router.post("/signup")
def signup(username: str = Body(...), password: str = Body(...), email: str = Body(...)):
    """
    Server-side sign-up: creates a user and sends confirmation email.
    Mirrors signUp.py:contentReference[oaicite:8]{index=8}.
    """
    if not APP_CLIENT_ID:
        raise HTTPException(500, "COGNITO_APP_CLIENT_ID not set")
    params = {
        "ClientId": APP_CLIENT_ID,
        "Username": username,
        "Password": password,
        "UserAttributes": [{"Name": "email", "Value": email}],
    }
    sh = _secret_hash(username)
    if sh:
        params["SecretHash"] = sh
    try:
        resp = _cognito_client().sign_up(**params)
        return {"status": "ok", "user_sub": resp.get("UserSub"), "message": "Confirmation code sent"}
    except Exception as e:
        raise HTTPException(400, f"Sign-up failed: {e}")

@router.post("/confirm")
def confirm(username: str = Body(...), code: str = Body(...)):
    """
    Confirm sign-up with emailed code.
    Mirrors confirm.py:contentReference[oaicite:9]{index=9}.
    """
    if not APP_CLIENT_ID:
        raise HTTPException(500, "COGNITO_APP_CLIENT_ID not set")
    params = {"ClientId": APP_CLIENT_ID, "Username": username, "ConfirmationCode": code}
    sh = _secret_hash(username)
    if sh:
        params["SecretHash"] = sh
    try:
        _cognito_client().confirm_sign_up(**params)
        return {"status": "ok", "message": "Email confirmed"}
    except Exception as e:
        raise HTTPException(400, f"Confirmation failed: {e}")

@router.post("/login")
def login(username: str = Body(...), password: str = Body(...), mfa_code: Optional[str] = Body(None)):
    """
    Programmatic login. Hosted UI is recommended for browser login (MFA auto-handled),
    but this endpoint is handy for scripts and mirrors authenticate.py:contentReference[oaicite:10]{index=10}.
    If MFA is required, pass mfa_code to complete the challenge.
    Returns id_token/access_token on success.
    """
    if not APP_CLIENT_ID:
        raise HTTPException(500, "COGNITO_APP_CLIENT_ID not set")

    client = _cognito_client()
    auth_params = {"USERNAME": username, "PASSWORD": password}
    sh = _secret_hash(username)
    if sh:
        auth_params["SECRET_HASH"] = sh

    try:
        resp = client.initiate_auth(
            ClientId=APP_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters=auth_params,
        )

        # Success: tokens returned
        if "AuthenticationResult" in resp:
            return {"status": "ok", **resp["AuthenticationResult"]}

        # Challenge (e.g., SMS_MFA, SOFTWARE_TOKEN_MFA, NEW_PASSWORD_REQUIRED)
        chal = resp.get("ChallengeName")
        if chal in ("SMS_MFA", "SOFTWARE_TOKEN_MFA"):
            if not mfa_code:
                raise HTTPException(401, f"MFA_REQUIRED: {chal}")
            resp2 = client.respond_to_auth_challenge(
                ClientId=APP_CLIENT_ID,
                ChallengeName=chal,
                Session=resp["Session"],
                ChallengeResponses={
                    "USERNAME": username,
                    "SMS_MFA_CODE" if chal == "SMS_MFA" else "SOFTWARE_TOKEN_MFA_CODE": mfa_code,
                    **({"SECRET_HASH": sh} if sh else {}),
                },
            )
            if "AuthenticationResult" in resp2:
                return {"status": "ok", **resp2["AuthenticationResult"]}
            raise HTTPException(401, "MFA challenge did not return tokens")
        elif chal == "NEW_PASSWORD_REQUIRED":
            raise HTTPException(401, "NEW_PASSWORD_REQUIRED")  # keep simple; handle if you need
        else:
            raise HTTPException(401, f"Unsupported challenge: {chal}")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(401, f"Authentication failed: {e}")
