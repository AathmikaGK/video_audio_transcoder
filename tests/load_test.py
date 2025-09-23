"""
Simple CPU load generator:
1) Upload a single medium-length video once (through the web UI or /upload/video).
2) Note the file_id returned.
3) Run this script with parallel workers to hammer /process/{file_id} and keep CPU >80%.
"""
import argparse, time, threading, requests

def worker(base_url, token, file_id, loops):
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(loops):
        try:
            r = requests.post(f"{base_url}/process/{file_id}", headers=headers, timeout=10)
            print("Queued job:", r.json())
        except Exception as e:
            print("Err:", e)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000", help="API base URL")
    ap.add_argument("--token", required=True, help="JWT access token from /auth/login")
    ap.add_argument("--file-id", type=int, required=True, help="Existing uploaded file id")
    ap.add_argument("--threads", type=int, default=8, help="Concurrent workers")
    ap.add_argument("--loops", type=int, default=10, help="Jobs per worker")
    args = ap.parse_args()

    threads = [threading.Thread(target=worker, args=(args.base, args.token, args.file_id, args.loops)) for _ in range(args.threads)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    print("Done. Monitor EC2 CPU during this run.")

if __name__ == "__main__":
    main()
