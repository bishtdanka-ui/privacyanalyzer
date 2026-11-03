import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    frontend_app = Path(__file__).resolve().parent / "frontend" / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(frontend_app), "--server.port", "8501"]
    print(f"Starting Streamlit Frontend on http://localhost:8501...")
    subprocess.run(cmd)

