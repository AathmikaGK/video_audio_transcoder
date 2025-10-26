import os
import json
import subprocess
import wave
import boto3
from vosk import Model, KaldiRecognizer

# Configuration
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-2")
S3_BUCKET = os.getenv("S3_BUCKET_NAME", "a2-group75")
VOSK_MODEL_PATH = os.getenv("VOSK_MODEL_PATH", "/opt/vosk/model")
FFMPEG_BIN = os.getenv("FFMPEG_BIN", "ffmpeg")
HEAVY_AUDIO = os.getenv("HEAVY_AUDIO", "0") == "1"

s3 = boto3.client("s3", region_name=AWS_REGION)

# ============== VOSK ==============
_vosk_model = None

def get_vosk_model():
    global _vosk_model
    if _vosk_model is None:
        if not os.path.isdir(VOSK_MODEL_PATH):
            raise RuntimeError(f"Vosk model not found at {VOSK_MODEL_PATH}")
        _vosk_model = Model(VOSK_MODEL_PATH)
    return _vosk_model

# ============== FFMPEG ==============
def _run_ffmpeg(cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def run_ffmpeg_extract_wav(input_video_path, output_wav_path):
    """Extract mono 16k PCM WAV for ASR"""
    base = [
        FFMPEG_BIN, "-y",
        "-i", input_video_path,
        "-vn",
        "-map", "a:0",
        "-ac", "1",
        "-sample_fmt", "s16",
    ]
    if HEAVY_AUDIO:
        af = "afftdn=nf=-25,loudnorm=I=-16:TP=-1.5:LRA=11,aresample=resampler=soxr:precision=33"
        cmd = base + ["-af", af, "-ar", "16000", "-f", "wav", output_wav_path]
    else:
        cmd = base + ["-ar", "16000", "-f", "wav", output_wav_path]
    _run_ffmpeg(cmd)

def wav_to_mp3(wav_path, mp3_path):
    """MP3 encode"""
    if HEAVY_AUDIO:
        cmd = [FFMPEG_BIN, "-y", "-i", wav_path, "-codec:a", "libmp3lame", "-q:a", "0", mp3_path]
    else:
        cmd = [FFMPEG_BIN, "-y", "-i", wav_path, "-codec:a", "libmp3lame", "-b:a", "192k", mp3_path]
    _run_ffmpeg(cmd)

# ============== ASR ==============
def transcribe_wav_vosk(wav_path, txt_out_path):
    model = get_vosk_model()
    rec = KaldiRecognizer(model, 16000)
    rec.SetWords(True)
    
    wf = wave.open(wav_path, "rb")
    if wf.getnchannels() != 1 or wf.getsampwidth() != 2 or wf.getframerate() != 16000:
        wf.close()
        raise RuntimeError("Unexpected WAV format; expected mono/16k PCM")
    
    results = []
    while True:
        data = wf.readframes(4000)
        if not data:
            break
        if rec.AcceptWaveform(data):
            results.append(json.loads(rec.Result()))
    results.append(json.loads(rec.FinalResult()))
    wf.close()
    
    transcript = " ".join([r.get("text", "") for r in results]).strip()
    with open(txt_out_path, "w", encoding="utf-8") as f:
        f.write(transcript + "\n")

# ============== MAIN PIPELINE ==============
def process_job(video_id, s3_key, temp_dir="/tmp"):
    """
    Download video from S3, transcode, upload results
    Returns: (success, audio_s3_key, transcript_s3_key, error_message)
    """
    try:
        # Setup paths
        video_filename = os.path.basename(s3_key)
        base_name = os.path.splitext(video_filename)[0]
        
        video_path = os.path.join(temp_dir, f"{video_id}_input.mp4")
        wav_path = os.path.join(temp_dir, f"{video_id}.wav")
        mp3_path = os.path.join(temp_dir, f"{video_id}.mp3")
        txt_path = os.path.join(temp_dir, f"{video_id}.txt")
        
        # Download video from S3
        print(f"Downloading {s3_key} from S3...")
        s3.download_file(S3_BUCKET, s3_key, video_path)
        
        # Transcode to WAV
        print("Extracting audio to WAV...")
        run_ffmpeg_extract_wav(video_path, wav_path)
        
        # Convert to MP3
        print("Converting to MP3...")
        wav_to_mp3(wav_path, mp3_path)
        
        # Transcribe
        print("Transcribing audio...")
        transcribe_wav_vosk(wav_path, txt_path)
        
        # Upload results to S3
        audio_s3_key = f"audio/{video_id}.mp3"
        transcript_s3_key = f"transcripts/{video_id}.txt"
        
        print(f"Uploading audio to S3: {audio_s3_key}")
        s3.upload_file(mp3_path, S3_BUCKET, audio_s3_key)
        
        print(f"Uploading transcript to S3: {transcript_s3_key}")
        s3.upload_file(txt_path, S3_BUCKET, transcript_s3_key)
        
        # Cleanup temp files
        for path in [video_path, wav_path, mp3_path, txt_path]:
            if os.path.exists(path):
                os.remove(path)
        
        return True, audio_s3_key, transcript_s3_key, None
        
    except Exception as e:
        print(f"Error processing job: {e}")
        import traceback
        traceback.print_exc()
        return False, None, None, str(e)