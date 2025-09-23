import os, shutil, uuid
from datetime import timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, status, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import desc

from .config import settings
from .database import Base, engine, SessionLocal
from .models import User, File as FileModel, Job, JobStatus, Role
from .schemas import Token, UserOut, FileOut, JobOut
from .auth import get_db, get_password_hash, verify_password, create_access_token, get_current_user, require_admin
from .tasks import process_job

# app = FastAPI(title=settings.PROJECT_NAME)
app = FastAPI(
    title=settings.PROJECT_NAME,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
from fastapi.responses import RedirectResponse

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/app/")
# Mount static web client
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/app", StaticFiles(directory=static_dir, html=True), name="static")

# Create DB tables
Base.metadata.create_all(bind=engine)

# Seed users if empty (two users, different roles)
def seed_users():
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            u1 = User(username="admin", password_hash=get_password_hash("admin123"), role=Role.admin)
            u2 = User(username="alice", password_hash=get_password_hash("password"), role=Role.user)
            db.add_all([u1, u2])
            db.commit()
    finally:
        db.close()
seed_users()

@app.get("/", response_class=HTMLResponse)
def root():
    return '<h2>Vid2AudioText API</h2><p>Open <a href="/docs">/docs</a> for API docs or <a href="/app">/app</a> for the web UI.</p>'

# ---------- AUTH ----------
@app.post("/auth/login", response_model=Token, tags=["auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username, "role": user.role.value})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me", response_model=UserOut, tags=["auth"])
def me(user: User = Depends(get_current_user)):
    return user

# ---------- UPLOAD & FILES ----------
@app.post("/upload/video", response_model=FileOut, tags=["files"])
def upload_video(f: UploadFile = File(...), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    os.makedirs(settings.VIDEO_DIR, exist_ok=True)
    ext = os.path.splitext(f.filename)[1]
    safe_name = f"{uuid.uuid4().hex}{ext}"
    stored_path = os.path.join(settings.VIDEO_DIR, safe_name)

    with open(stored_path, "wb") as out:
        shutil.copyfileobj(f.file, out)

    fm = FileModel(owner_id=user.id, original_filename=f.filename, stored_path=stored_path)
    db.add(fm); db.commit(); db.refresh(fm)
    return fm

@app.get("/files", response_model=List[FileOut], tags=["files"])
def list_files(skip: int = 0, limit: int = 20, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(FileModel).filter(FileModel.owner_id == user.id).order_by(desc(FileModel.created_at))
    return q.offset(skip).limit(limit).all()

# Admin can delete any file; user can delete own
@app.delete("/files/{file_id}", tags=["files"])
def delete_file(file_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    fm = db.get(FileModel, file_id)
    if not fm:
        raise HTTPException(404, "File not found")
    if user.role != Role.admin and fm.owner_id != user.id:
        raise HTTPException(403, "Not allowed")
    # Remove physical file
    try:
        if os.path.exists(fm.stored_path): os.remove(fm.stored_path)
    except Exception:
        pass
    # Cascade delete jobs handled by FK ON DELETE? Not set, remove manually
    jobs = db.query(Job).filter(Job.file_id == fm.id).all()
    for j in jobs:
        if j.audio_path and os.path.exists(j.audio_path):
            try: os.remove(j.audio_path)
            except Exception: pass
        if j.transcript_path and os.path.exists(j.transcript_path):
            try: os.remove(j.transcript_path)
            except Exception: pass
        db.delete(j)
    db.delete(fm); db.commit()
    return {"ok": True}

# ---------- JOBS / PROCESS ----------
@app.post("/process/{file_id}", response_model=JobOut, tags=["jobs"])
def create_job(file_id: int, background: BackgroundTasks, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    fm = db.get(FileModel, file_id)
    if not fm or (user.role != Role.admin and fm.owner_id != user.id):
        raise HTTPException(404, "File not found")
    job = Job(owner_id=user.id, file_id=fm.id, status=JobStatus.queued)
    db.add(job); db.commit(); db.refresh(job)

    # Launch background job
    background.add_task(run_job_task, job.id)
    return job

def run_job_task(job_id: int):
    db = SessionLocal()
    try:
        process_job(db, job_id)
    finally:
        db.close()

@app.get("/jobs", response_model=List[JobOut], tags=["jobs"])
def list_jobs(
    status: Optional[JobStatus] = Query(None, description="Filter by status"),
    sort: Optional[str] = Query("-created_at", description="Sort by field, prefix '-' for desc"),
    page: int = 1,
    page_size: int = 20,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Job).filter(Job.owner_id == user.id)
    if status:
        q = q.filter(Job.status == status)
    # Sorting
    if sort:
        desc_order = sort.startswith("-")
        field = sort[1:] if desc_order else sort
        col = getattr(Job, field, None)
        if col is not None:
            q = q.order_by(desc(col) if desc_order else col.asc())
    offset = (page - 1) * page_size
    return q.offset(offset).limit(page_size).all()

@app.get("/jobs/{job_id}", response_model=JobOut, tags=["jobs"])
def get_job(job_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if not job or (user.role != Role.admin and job.owner_id != user.id):
        raise HTTPException(404, "Job not found")
    return job

@app.get("/download/audio/{job_id}", response_class=FileResponse, tags=["download"])
def download_audio(job_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if not job or (user.role != Role.admin and job.owner_id != user.id):
        raise HTTPException(404, "Not found")
    if job.status != JobStatus.done or not job.audio_path or not os.path.exists(job.audio_path):
        raise HTTPException(400, "Audio not available")
    return FileResponse(job.audio_path, media_type="audio/mpeg", filename=os.path.basename(job.audio_path))

@app.get("/download/transcript/{job_id}", response_class=FileResponse, tags=["download"])
def download_transcript(job_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if not job or (user.role != Role.admin and job.owner_id != user.id):
        raise HTTPException(404, "Not found")
    if job.status != JobStatus.done or not job.transcript_path or not os.path.exists(job.transcript_path):
        raise HTTPException(400, "Transcript not available")
    return FileResponse(job.transcript_path, media_type="text/plain", filename=os.path.basename(job.transcript_path))

# ---------- HEALTH ----------
@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}
