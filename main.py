import os
import shutil
import uuid
from typing import List, Optional
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, status, BackgroundTasks, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import desc
from dotenv import load_dotenv
from pydantic import BaseModel


from app.config import settings
from app.database import Base, engine, SessionLocal
from app.models import File as FileModel, Job, JobStatus
from app.schemas import FileOut, JobOut
from app.tasks import process_job

# Import Cognito functions (we'll create a FastAPI version)
from app.Cognito import (
    signup_user as cognito_signup,
    confirm_user as cognito_confirm,
    login_user as cognito_login,
    email_mfa as cognito_email_mfa,
    verify_jwt
)

load_dotenv()

# ===== FastAPI App Setup =====
app = FastAPI(
    title=settings.PROJECT_NAME,
    docs_url="/docs",  # Enable API docs at /docs
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__),"static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ===== Database Dependency =====
def get_db():
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ===== Authentication Dependency =====
def get_username_from_token(user: dict) -> str:
    """
    Extract username from token claims
    Handles both ID tokens and Access tokens
    """
    # Try ID token format first (cognito:username)
    username = user.get("cognito:username")
    
    # If not found, try access token format (username)
    if not username:
        username = user.get("username")
    
    # If still not found, raise error
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username not found in token"
        )
    
    return username
async def get_current_user(request: Request):
    """
    Dependency to get current authenticated user from JWT token
    Extract token from Authorization header
    """
    auth_header = request.headers.get("Authorization")
    print(f"Authorization header: {auth_header[:50] if auth_header else 'MISSING'}")
    
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header"
        )
    
    try:
       # Expected format: "Bearer <token>"
        parts = auth_header.split(" ")
        if len(parts) != 2:
            print(f"Invalid header format, parts: {len(parts)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format"
            )
        
        token_type, token = parts
        if token_type.lower() != "bearer":
            print(f"Invalid token type: {token_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        # Verify JWT token
        print(f"Verifying token: {token[:20]}...")
        user = verify_jwt(token)
        print(f"User verified: {user.get('cognito:username')}")
        return user
    except HTTPException:
        raise
    except Exception as e:
        print(f"Authentication error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )

# ===== SERVE HTML PAGES =====

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the login/signup page"""
    file_path = os.path.join(os.path.dirname(__file__), "static", "login.html")
    print(f"========== SERVING LOGIN PAGE ==========")
    print(f"Looking for: {file_path}")
    print(f"File exists: {os.path.exists(file_path)}")
    print(f"========================================")
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
    
    return FileResponse(file_path)


@app.get("/index2.html", response_class=HTMLResponse)
async def jobs_page():
    """Serve the jobs dashboard page"""
    file_path = os.path.join(os.path.dirname(__file__), "static", "index2.html")
    return FileResponse(file_path)

# ===== AUTHENTICATION ENDPOINTS =====

class SignupRequest(BaseModel):
    username: str
    password: str
    email: str

class ConfirmRequest(BaseModel):
    username: str
    code: str

class LoginRequest(BaseModel):
    username: str
    password: str

class MFARequest(BaseModel):
    username: str
    session: str
    mfa_code: str

from pydantic import BaseModel

@app.post("/signup")
async def signup(request: SignupRequest):
    """User signup endpoint"""
    resp = cognito_signup(request.username, request.password, request.email)
    
    if "error" in resp:
        raise HTTPException(status_code=400, detail=resp["error"])
    
    return {
        "message": "User registered successfully",
        "user_sub": resp.get("UserSub")
    }

@app.post("/confirm")
async def confirm_signup(request: ConfirmRequest):
    """Confirm user signup with verification code"""
    resp = cognito_confirm(request.username, request.code)
    
    if "error" in resp:
        raise HTTPException(status_code=400, detail=resp["error"])
    
    return {"message": "User confirmed successfully"}

@app.post("/login")
async def login(request: LoginRequest):
    """User login endpoint"""
    result = cognito_login(request.username, request.password)
    
    print("Login result:", result)
    
    # Check if MFA challenge is required
    if result.get("ChallengeName"):
        print("Challenge: EMAIL_OTP")
        return {
            "message": "MFA required",
            "session": result["Session"]
        }
    
    # Check if authentication was successful
    if "AuthenticationResult" in result:
        tokens = result["AuthenticationResult"]
        return {
            "message": "Login successful",
            "id_token": tokens.get("IdToken"),
            "access_token": tokens.get("AccessToken"),
            "refresh_token": tokens.get("RefreshToken")
        }
    
    # Check for error
    if "error" in result:
        print("❌ Cognito error:", result["error"])
        raise HTTPException(status_code=401, detail=result["error"])
    
    raise HTTPException(status_code=400, detail="Unexpected Cognito response")

@app.post("/verify-mfa")
async def verify_mfa(request: MFARequest):
    """Verify MFA code and complete authentication"""
    mfa_result = cognito_email_mfa(
        request.username,
        request.session,
        request.mfa_code
    )
    
    if not mfa_result.get("success"):
        error_msg = mfa_result.get("error", "MFA verification failed")
        raise HTTPException(status_code=401, detail=error_msg)
    
    return {
        "id_token": mfa_result["IdToken"],
        "access_token": mfa_result["AccessToken"],
        "refresh_token": mfa_result["RefreshToken"]
    }

# ===== PROTECTED ENDPOINTS - USER INFO =====

@app.get("/me")
async def me(user: dict = Depends(get_current_user)):
    """Get current user information"""
    username = get_username_from_token(user)
    return {
        "username": username,
        "email": user.get("email"),
        "sub": user.get("sub"),
        "groups": user.get("cognito:groups", [])
    }

@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    print("=" * 50)
    print("🚀 Starting application...")
    print("=" * 50)
    
    # Import models to ensure they're registered
    from app.models import File, Job, JobStatus
    
    print("📊 Creating database tables...")
    try:
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully")
        
        # Verify tables exist
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        print(f"📋 Tables in database: {tables}")
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        raise
    
    print("📁 Creating storage directories...")
    os.makedirs(settings.VIDEO_DIR, exist_ok=True)
    os.makedirs(settings.AUDIO_DIR, exist_ok=True)
    os.makedirs(settings.TEXT_DIR, exist_ok=True)
    print("✅ Storage directories ready")
    
    print("=" * 50)
    print("✅ Application startup complete")
    print(f"📍 Server running at http://localhost:8000")
    print(f"📚 API Documentation at http://localhost:8000/docs")
    print("=" * 50)
# ===== PROTECTED ENDPOINTS - FILE MANAGEMENT =====

@app.post("/upload/video", response_model=FileOut)
async def upload_video(
    f: UploadFile = File(...),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload a video file"""
    # Create video directory if needed
    os.makedirs(settings.VIDEO_DIR, exist_ok=True)
    
    # Generate unique filename
    ext = os.path.splitext(f.filename)[1]
    safe_name = f"{uuid.uuid4().hex}{ext}"
    stored_path = os.path.join(settings.VIDEO_DIR, safe_name)
    
    # Save file
    with open(stored_path, "wb") as buffer:
        shutil.copyfileobj(f.file, buffer)
    
    # Create database entry
    username = get_username_from_token(user)  
    fm = FileModel(
        owner_id=username,  # Now this will be the actual username
        original_filename=f.filename,
        stored_path=stored_path
    )
    db.add(fm)
    db.commit()
    db.refresh(fm)
    
    return fm

@app.get("/files", response_model=List[FileOut])
async def list_files(
    skip: int = 0,
    limit: int = 20,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all files for authenticated user"""
    username = get_username_from_token(user)  
    files = db.query(FileModel).filter(
        FileModel.owner_id == username
    ).order_by(desc(FileModel.created_at)).offset(skip).limit(limit).all()
    
    return files

@app.delete("/files/{file_id}")
async def delete_file(
    file_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a file and associated jobs"""
    username = get_username_from_token(user) 
    fm = db.query(FileModel).filter(FileModel.id == file_id).first()
    
    if not fm:
        raise HTTPException(status_code=404, detail="File not found")
    
    if fm.owner_id != username and "admin" not in user.get("cognito:groups", []):
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Remove physical file
    try:
        if os.path.exists(fm.stored_path):
            os.remove(fm.stored_path)
    except Exception as e:
        print(f"Error deleting file: {e}")
    
    # Delete jobs and outputs
    jobs = db.query(Job).filter(Job.file_id == fm.id).all()
    for job in jobs:
        if job.audio_path and os.path.exists(job.audio_path):
            try:
                os.remove(job.audio_path)
            except Exception:
                pass
        if job.transcript_path and os.path.exists(job.transcript_path):
            try:
                os.remove(job.transcript_path)
            except Exception:
                pass
        db.delete(job)
    
    db.delete(fm)
    db.commit()
    
    return {"ok": True}

# ===== PROTECTED ENDPOINTS - JOB MANAGEMENT =====

@app.post("/process/{file_id}", response_model=JobOut)
async def create_job(
    file_id: int,
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a processing job for a file"""
    username = get_username_from_token(user)  
    fm = db.query(FileModel).filter(FileModel.id == file_id).first()
    
    if not fm or (fm.owner_id != username and "admin" not in user.get("cognito:groups", [])):
        raise HTTPException(status_code=404, detail="File not found")
    
    # Create job
    job = Job(
        owner_id=username,
        file_id=fm.id,
        status=JobStatus.queued
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Add background task
    background_tasks.add_task(run_job_task, job.id)
    
    return job

def run_job_task(job_id: int):
    """Background task to process job"""
    db = SessionLocal()
    try:
        print(f"Processing job {job_id}...")
        process_job(db, job_id)
        print(f"Job {job_id} completed")
    except Exception as e:
        print(f"Error processing job {job_id}: {e}")
    finally:
        db.close()

@app.get("/jobs", response_model=List[JobOut])
async def list_jobs(
    status_filter: Optional[JobStatus] = Query(None, alias="status"),
    sort: Optional[str] = Query("-created_at"),
    page: int = 1,
    page_size: int = 20,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all jobs for authenticated user"""
    username = get_username_from_token(user)  
    query = db.query(Job).filter(Job.owner_id == username)
    # Apply status filter
    if status_filter:
        query = query.filter(Job.status == status_filter)
    
    # Apply sorting
    if sort:
        desc_order = sort.startswith("-")
        field = sort[1:] if desc_order else sort
        col = getattr(Job, field, None)
        if col is not None:
            query = query.order_by(desc(col) if desc_order else col.asc())
    
    # Pagination
    offset = (page - 1) * page_size
    jobs = query.offset(offset).limit(page_size).all()
    
    return jobs

@app.get("/jobs/{job_id}", response_model=JobOut)
async def get_job(
    job_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get details of a specific job"""
    username = get_username_from_token(user)
    job = db.query(Job).filter(Job.id == job_id).first()
    
    if not job or (job.owner_id != username and "admin" not in user.get("cognito:groups", [])):
        raise HTTPException(status_code=404, detail="Job not found")
    
    return job

# ===== PROTECTED ENDPOINTS - DOWNLOAD =====

@app.get("/download/audio/{job_id}", response_class=FileResponse)
async def download_audio(
    job_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download audio file from completed job"""
    username = get_username_from_token(user)
    job = db.query(Job).filter(Job.id == job_id).first()
    
    if not job or (job.owner_id != username and "admin" not in user.get("cognito:groups", [])):
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status != JobStatus.done or not job.audio_path:
        raise HTTPException(status_code=400, detail="Audio not available")
    
    if not os.path.exists(job.audio_path):
        raise HTTPException(status_code=404, detail="Audio file not found")
    
    return FileResponse(
        job.audio_path,
        media_type="audio/mpeg",
        filename=os.path.basename(job.audio_path)
    )

@app.get("/download/transcript/{job_id}", response_class=FileResponse)
async def download_transcript(
    job_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download transcript file from completed job"""
    username = get_username_from_token(user)
    job = db.query(Job).filter(Job.id == job_id).first()
    
    if not job or (job.owner_id != username and "admin" not in user.get("cognito:groups", [])):
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status != JobStatus.done or not job.transcript_path:
        raise HTTPException(status_code=400, detail="Transcript not available")
    
    if not os.path.exists(job.transcript_path):
        raise HTTPException(status_code=404, detail="Transcript file not found")
    
    return FileResponse(
        job.transcript_path,
        media_type="text/plain",
        filename=os.path.basename(job.transcript_path)
    )

# ===== HEALTH CHECK =====

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok"}

# ===== APPLICATION STARTUP =====

@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    
    print("Creating storage directories...")
    os.makedirs(settings.VIDEO_DIR, exist_ok=True)
    os.makedirs(settings.AUDIO_DIR, exist_ok=True)
    os.makedirs(settings.TEXT_DIR, exist_ok=True)
    
    print("✅ Application startup complete")
    print(f"📍 Server running at http://localhost:8000")
    print(f"📚 API Documentation at http://localhost:8000/docs")

@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown"""
    print("Application shutting down...")

# ===== MAIN =====

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Auto-reload on code changes (development only)
        log_level="info"
    )