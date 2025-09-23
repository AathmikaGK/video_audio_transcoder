from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base
import enum

class Role(str, enum.Enum):
    admin = "admin"
    user = "user"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(Role), default=Role.user, nullable=False)

    jobs = relationship("Job", back_populates="owner")

class JobStatus(str, enum.Enum):
    queued = "queued"
    processing = "processing"
    done = "done"
    failed = "failed"

class File(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    original_filename = Column(String, nullable=False)
    stored_path = Column(String, nullable=False)  # path to video file
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User")
    jobs = relationship("Job", back_populates="file")

class Job(Base):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    file_id = Column(Integer, ForeignKey("files.id"))
    status = Column(Enum(JobStatus), default=JobStatus.queued, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    error_message = Column(Text, nullable=True)
    audio_path = Column(String, nullable=True)     # output wav or mp3
    transcript_path = Column(String, nullable=True)# output txt

    owner = relationship("User", back_populates="jobs")
    file = relationship("File", back_populates="jobs")


# use of ai to optimise code