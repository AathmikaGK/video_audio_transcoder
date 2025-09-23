
import os, json, subprocess, wave
from datetime import datetime
from sqlalchemy.orm import Session
from vosk import Model, KaldiRecognizer

from .config import settings
from .models import Job, JobStatus

# ---------- VOSK ----------
_vosk_model = None
def get_vosk_model():
    global _vosk_model
    if _vosk_model is None:
        if not os.path.isdir(settings.VOSK_MODEL_PATH):
            raise RuntimeError(f"Vosk model not found at {settings.VOSK_MODEL_PATH}.")
        _vosk_model = Model(settings.VOSK_MODEL_PATH)
    return _vosk_model

# ---------- FFMPEG HELPERS ----------
def _run_ffmpeg(cmd: list[str]):
    # Let ffmpeg pick threads automatically; you can set -threads 0 explicitly if you want
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def run_ffmpeg_extract_wav(input_video_path: str, output_wav_path: str):
    """
    Extract mono 16k PCM WAV for ASR. In HEAVY mode:
      - afftdn: FFT-based denoise (CPU-heavy)
      - loudnorm: EBU R128 loudness normalization (CPU-heavy)
      - aresample: high-quality soxr resampler with high precision
    """
    base = [
        settings.FFMPEG_BIN, "-y",
        "-i", input_video_path,
        "-vn",                     # ignore video
        "-map", "a:0",            # first audio stream
        "-ac", "1",               # mono
        "-sample_fmt", "s16",     # 16-bit PCM
    ]
    if settings.HEAVY_AUDIO:
        af = "afftdn=nf=-25,loudnorm=I=-16:TP=-1.5:LRA=11,aresample=resampler=soxr:precision=33"
        cmd = base + ["-af", af, "-ar", "16000", "-f", "wav", output_wav_path]
    else:
        # fast path (what you had)
        cmd = base + ["-ar", "16000", "-f", "wav", output_wav_path]
    _run_ffmpeg(cmd)

def wav_to_mp3(wav_path: str, mp3_path: str):
    """
    MP3 encode. In HEAVY mode use highest VBR quality (q=0), which is more CPU than fixed bitrate.
    """
    if settings.HEAVY_AUDIO:
        cmd = [settings.FFMPEG_BIN, "-y", "-i", wav_path, "-codec:a", "libmp3lame", "-q:a", "0", mp3_path]
    else:
        cmd = [settings.FFMPEG_BIN, "-y", "-i", wav_path, "-codec:a", "libmp3lame", "-b:a", "192k", mp3_path]
    _run_ffmpeg(cmd)

def wav_to_flac(wav_path: str, flac_path: str):
    # Highest compression is CPU-heavy
    cmd = [settings.FFMPEG_BIN, "-y", "-i", wav_path, "-c:a", "flac", "-compression_level", "12", flac_path]
    _run_ffmpeg(cmd)

def wav_to_opus(wav_path: str, opus_path: str):
    cmd = [settings.FFMPEG_BIN, "-y", "-i", wav_path, "-c:a", "libopus", "-b:a", "96k", "-vbr", "on", opus_path]
    _run_ffmpeg(cmd)

def wav_to_aac(wav_path: str, aac_path: str):
    # Built-in AAC with VBR quality ~highest
    cmd = [settings.FFMPEG_BIN, "-y", "-i", wav_path, "-c:a", "aac", "-q:a", "0.9", aac_path]
    _run_ffmpeg(cmd)

# ---------- ASR (Vosk) ----------
def transcribe_wav_vosk(wav_path: str, txt_out_path: str):
    model = get_vosk_model()
    rec = KaldiRecognizer(model, 16000)
    rec.SetWords(True)

    wf = wave.open(wav_path, "rb")
    if wf.getnchannels() != 1 or wf.getsampwidth() != 2 or wf.getframerate() != 16000:
        wf.close()
        raise RuntimeError("Unexpected WAV format for ASR; expected mono/16k PCM.")
    results = []
    while True:
        data = wf.readframes(4000)
        if not data:
            break
        if rec.AcceptWaveform(data):
            results.append(json.loads(rec.Result()))
    results.append(json.loads(rec.FinalResult()))
    wf.close()

    # Collect words into a plain transcript
    transcript = " ".join([r.get("text", "") for r in results]).strip()
    with open(txt_out_path, "w", encoding="utf-8") as f:
        f.write(transcript + "\n")

# ---------- MAIN PIPELINE ----------
def process_job(db: Session, job_id: int):
    job = db.get(Job, job_id)
    if not job:
        return
    try:
        job.status = JobStatus.processing
        job.updated_at = datetime.utcnow()
        db.commit()

        video_path = job.file.stored_path
        base_name = os.path.splitext(os.path.basename(video_path))[0]
        os.makedirs(settings.AUDIO_DIR, exist_ok=True)
        os.makedirs(settings.TEXT_DIR, exist_ok=True)

        wav_out = os.path.join(settings.AUDIO_DIR, f"{base_name}_{job.id}.wav")
        mp3_out = os.path.join(settings.AUDIO_DIR, f"{base_name}_{job.id}.mp3")
        txt_out = os.path.join(settings.TEXT_DIR, f"{base_name}_{job.id}.txt")

        # 1) HQ WAV for ASR (heavier path if enabled)
        run_ffmpeg_extract_wav(video_path, wav_out)

        # 2) MP3 (heavier settings if enabled)
        wav_to_mp3(wav_out, mp3_out)

        # 3) Optional extra encodings to pump CPU (no schema changes needed)
        extras = [e.strip().lower() for e in settings.EXTRA_ENCODINGS.split(",") if e.strip()]
        for codec in extras:
            try:
                if codec == "flac":
                    wav_to_flac(wav_out, os.path.join(settings.AUDIO_DIR, f"{base_name}_{job.id}.flac"))
                elif codec == "opus":
                    wav_to_opus(wav_out, os.path.join(settings.AUDIO_DIR, f"{base_name}_{job.id}.opus"))
                elif codec == "aac":
                    wav_to_aac(wav_out, os.path.join(settings.AUDIO_DIR, f"{base_name}_{job.id}.m4a"))
            except Exception:
                # Don't fail the main job if an extra format trips
                pass

        # 4) Transcribe (Vosk)
        transcribe_wav_vosk(wav_out, txt_out)

        job.audio_path = mp3_out
        job.transcript_path = txt_out
        job.status = JobStatus.done
        job.updated_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        job.status = JobStatus.failed
        job.error_message = str(e)
        job.updated_at = datetime.utcnow()
        db.commit()
        raise



# use of ai to optimise code