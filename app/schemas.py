from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from .models import JobStatus, Role

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[Role] = None

class UserBase(BaseModel):
    username: str
    role: Role

class UserOut(UserBase):
    id: str
    class Config:
        from_attributes = True

class FileOut(BaseModel):
    id: str
    original_filename: str
    stored_path: str
    created_at: datetime
    owner_id: str
    class Config:
        from_attributes = True

class JobOut(BaseModel):
    id: str
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    error_message: Optional[str] = None
    audio_path: Optional[str] = None
    transcript_path: Optional[str] = None
    file_id: int
    owner_id: str
    class Config:
        from_attributes = True
