import os, boto3, jwt, requests
from dotenv import load_dotenv
from flask import request
from functools import wraps
import hmac, hashlib, base64 
import traceback
#from .config import settings 

load_dotenv()
"""
CLIENT_ID = settings.COGNITO_CLIENT_ID
USERPOOL_ID = settings.COGNITO_USERPOOL_ID
REGION = settings.COGNITO_REGION"""

COGNITO_DOMAIN="https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_lOInK99x5"
USERPOOL_ID="ap-southeast-2_lOInK99x5"
CLIENT_ID="1ingln7v6suqin0roc0i53ehl1"
CLIENT_SECRET="aoel06ss40eghu8damv28ggqi7bjvohde2evn13o5ra5l18colo"
REGION="ap-southeast-2"
#server meta url
JWKS_URL = f"https://cognito-idp.{REGION}.amazonaws.com/{USERPOOL_ID}/.well-known/jwks.json"
jwks = requests.get(JWKS_URL).json()["keys"]

cognito = boto3.client("cognito-idp", region_name=REGION)
# ---------------- Cognito API Calls ---------------- #

def signup_user(username, password, email):
    try:
        response = cognito.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secretHash(CLIENT_ID, CLIENT_SECRET, username),
            Username=username,
            Password=password,
            UserAttributes=[{"Name": "email", "Value": email}]
        )
        return response
    except cognito.exceptions.UsernameExistsException:
        return {"error": "User already exists"}
    except cognito.exceptions.InvalidPasswordException:
        return {"error": "Password does not meet policy requirements"}
    except Exception as e:
        return {"error": str(e)}
    
def secretHash(clientId, clientSecret, username):
    message = bytes(username + clientId,'utf-8') 
    key = bytes(clientSecret,'utf-8') 
    return base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode() 

def confirm_user(username, code):
    try:
        response =  cognito.confirm_sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secretHash(CLIENT_ID, CLIENT_SECRET, username),
            Username=username,
            ConfirmationCode=code
    )
        return response
    except cognito.exceptions.UserNotFoundException:
        return {"error": "User not found"}
    except cognito.exceptions.CodeMismatchException:
        return {"error": "Invalid confirmation code"}
    except cognito.exceptions.ExpiredCodeException:
        return {"error": "Confirmation code expired"}
    except Exception as e:
        print(f"Error during confirmation: {e}")
        return None

def login_user(username, password):
    try:
        print("attempting login")
        response = cognito.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username,
                            "PASSWORD": password,
                            "SECRET_HASH": secretHash(CLIENT_ID, CLIENT_SECRET, username)
                            },
            ClientId=CLIENT_ID
        )
        print(response)
        
        # Case 1: Successful login
        if "AuthenticationResult" in response:
            return {"success": True, "tokens": response["AuthenticationResult"]}

        # Case 2: Challenge (MFA, new password, etc.)
        if response["ChallengeName"] == "EMAIL_OTP":
            print("OTP sent to:", response["ChallengeParameters"]["CODE_DELIVERY_DESTINATION"])
            session = response["Session"]
            return response

    except cognito.exceptions.NotAuthorizedException:
        return {"success": False, "error": "Invalid username or password"}
    except cognito.exceptions.UserNotConfirmedException:
        return {"success": False, "error": "User not confirmed. Please check your email."}
    except cognito.exceptions.LimitExceededException:
        return {"success": False, "error": "Limit exceeded"}
    except Exception as e:
        print("exception during login",e)
        #traceback.print_exec()
        return {"success": False, "error": f"Error during authentication: {e}"}

def email_mfa(username, session_id, code):
    try:
        response = cognito.respond_to_auth_challenge(
                ClientId=CLIENT_ID,
                ChallengeName='EMAIL_OTP', 
                ChallengeResponses={"USERNAME": username,
                                    "EMAIL_OTP_CODE": code,
                                    "SECRET_HASH": secretHash(CLIENT_ID, CLIENT_SECRET, username)
                                    },
                Session=session_id
        )
        if "AuthenticationResult" in response:
                tokens = response["AuthenticationResult"]
                return {
                    "success": True,
                    "IdToken": tokens.get("IdToken"),
                    "AccessToken": tokens.get("AccessToken"),
                    "RefreshToken": tokens.get("RefreshToken")
                }
        else:
            return {"success": False, "error": "No tokens returned", "challenge": response.get("ChallengeName")}
    except Exception as e:
        import traceback; traceback.print_exc()
        return {"success": False, "error": str(e)}

# implement federated identities with aws
def signupWithGoogle():
    pass
# ---------------- JWT Verification ---------------- #

def verify_jwt(token):
    """Verify JWT token and return user claims"""
    try:
        # Get token header
        header = jwt.get_unverified_header(token)
        
        # Find the matching key
        key = next((k for k in jwks if k["kid"] == header["kid"]), None)
        if not key:
            raise Exception("Invalid JWT: key not found")
        
        # Convert JWK to public key
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        
        # First, decode without verification to check token type
        unverified = jwt.decode(token, options={"verify_signature": False})
        
        # Check if this is an access_token or id_token
        token_use = unverified.get("token_use")
        
        print(f"Token type: {token_use}")
        print(f"Token claims: {list(unverified.keys())}")
        
        # Decode and verify based on token type
        if token_use == "id":
            # ID Token - has 'aud' claim
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=CLIENT_ID,  # ID tokens use 'aud'
                issuer=f"https://cognito-idp.{REGION}.amazonaws.com/{USERPOOL_ID}"
            )
        elif token_use == "access":
            # Access Token - has 'client_id' instead of 'aud'
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},  # Don't verify 'aud' for access tokens
                issuer=f"https://cognito-idp.{REGION}.amazonaws.com/{USERPOOL_ID}"
            )
            # Manually verify client_id for access tokens
            if decoded.get("client_id") != CLIENT_ID:
                raise Exception("Invalid client_id in access token")
        else:
            raise Exception(f"Unknown token_use: {token_use}")
        
        # Log successful verification
        username = decoded.get("cognito:username") or decoded.get("username")
        print(f"Token verified successfully for user: {username}")
        
        return decoded
        
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError as e:
        raise Exception(f"Invalid token: {str(e)}")
    except Exception as e:
        print(f"Token verification error: {e}")
        raise Exception(f"Token verification failed: {str(e)}")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return {"error": "Missing Authorization header"}, 401
        try:
            token = auth_header.split(" ")[1]  # "Bearer <token>"
            user = verify_jwt(token)
            return f(user, *args, **kwargs)
        except Exception as e:
            return {"error": str(e)}, 401
    return decorated
