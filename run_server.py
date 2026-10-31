import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
src_path = root / "src"
sys.path.insert(0, str(src_path))

demo_token = "trc_demo_analyst_credential_32chars"
vault_dir = root / "demo_vault"

os.environ["TRACEE_API_TOKEN"] = demo_token
os.environ["TRACEE_UPLOAD_TOKEN"] = demo_token
os.environ["TRACEE_API_VAULT_DIR"] = str(vault_dir)

from tracee.api import create_app
import uvicorn

app = create_app(vault_dir)

if __name__ == "__main__":
    print("=" * 80)
    print("TRACEE LIVE DEMONSTRATION SERVER")
    print("=" * 80)
    print("Primary Workspace:  http://127.0.0.1:8000/")
    print(f"Session API Key:    {demo_token}")
    print("=" * 80)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
