#!/bin/bash
# Worker instance startup script
# This downloads the Vosk model and starts the worker

echo "===== Worker Startup Script ====="

# Update system
sudo apt-get update

# Install required packages
sudo apt-get install -y python3-pip python3-venv ffmpeg

# Create directories
sudo mkdir -p /opt/vosk/model
sudo mkdir -p /home/ubuntu/worker

# Download Vosk model from S3
echo "Downloading Vosk model from S3..."
aws s3 sync s3://n11806427-vosk-models/models/ 
sudo chown -R ubuntu:ubuntu /opt/vosk/model

# Navigate to worker directory
cd /home/ubuntu/worker

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

echo "===== Startup Complete ====="
echo "To start worker: cd ~/worker && source venv/bin/activate && python worker.py"