# Vid2AudioText API

FastAPI service that converts uploaded **videos** into **audio (MP3)** and **text transcripts** using **FFmpeg** and **Vosk**.

## Quick Start (Local)

```bash
# 1) Build
docker build -t vid2audiotext:latest .

# 2) Run
docker run -it --rm -p 8000:8000 -e SECRET_KEY=change-me vid2audiotext:latest

# Open http://localhost:8000/app
# API docs at http://localhost:8000/docs
```

Seeded users:
- `admin / admin123` (role: admin)
- `alice / password` (role: user)

## REST Endpoints (primary interface)

- `POST /auth/login` -> OAuth2 Password flow returns JWT
- `GET /me` -> whoami
- `POST /upload/video` -> upload a video file (JWT required)
- `POST /process/{file_id}` -> queue CPU-intensive job for that file
- `GET /jobs?page=&page_size=&status=&sort=` -> list jobs with pagination/filter/sort
- `GET /jobs/{job_id}` -> job detail
- `GET /download/audio/{job_id}` -> download MP3
- `GET /download/transcript/{job_id}` -> download TXT
- `GET /files` / `DELETE /files/{id}` -> manage your files
- `GET /health` -> service health

## CPU-Intensive Work

1. **FFmpeg** transcodes video → 16kHz mono WAV (PCM) and → MP3.
2. **Vosk** runs on the WAV to produce a transcript.
Both steps are CPU-heavy on longer videos.

### Load Testing

1. Upload a video once and note the returned `file_id`.
2. Get a JWT via `/auth/login`.
3. From a client with good bandwidth, run:

```bash
python load_test.py --base http://YOUR_EC2_PUBLIC_IP:8000 --token YOUR_JWT --file-id 1 --threads 8 --loops 50
```

Monitor EC2 CPU in the AWS console (Instance → Monitoring). Target **>80%** CPU for ~5 minutes.
If uploads are your bottleneck, pre-upload, then hammer `/process/{file_id}`.

## AWS Deployment (ECR + EC2)

### Push to ECR
```bash
AWS_REGION=ap-southeast-2 # example
AWS_ACCOUNT_ID=YOUR_ACCOUNT_ID
REPO=vid2audiotext

aws ecr create-repository --repository-name $REPO || true
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

docker build -t $REPO:latest .
docker tag $REPO:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:latest
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:latest
```

### Run on EC2 (Ubuntu 24.04)
- Install Docker
- Pull and run:
```bash
docker pull $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:latest
docker run -d --name vid2audiotext -p 80:8000 -e SECRET_KEY=change-me $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:latest
```
Open `http://EC2_PUBLIC_IP/`

## Data Types (for later persistence work)

- **Unstructured**: uploaded video files, produced audio (MP3/WAV), transcripts (TXT).
- **Structured**: SQLite tables for Users, Files, Jobs, including ownership, status, metadata.

> Note: user identity is hard-coded for this assessment (JWT from static list).

## Web Client

A simple static front-end is served at `/app`. It exercises **all endpoints**: login, upload, process, list, download.

## Security Notes

- Replace `SECRET_KEY` in production.
- JWT is required for all file/job actions.
- Role-based authorization (admin vs user) affects deletion and access.

## Troubleshooting

- If Vosk model URL changes, update Dockerfile `curl` line or set `VOSK_MODEL_PATH` to a mounted model directory.
- On small instances (t3.micro), long videos may take a while — that’s OK for this assignment.
- If CPU isn’t saturated, increase `--threads`/`--loops` or process longer videos.
