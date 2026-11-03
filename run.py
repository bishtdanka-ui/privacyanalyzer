import subprocess
import sys
import time
import signal
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def main():
    print("=" * 70)
    print("🛡️  Explainable Application Privacy and Permission Analyzer (PS02)")
    print("=" * 70)
    print("Launching FastAPI Backend (port 8000) and Streamlit Frontend (port 8501)...")
    
    backend_proc = subprocess.Popen([
        sys.executable, "-m", "uvicorn", "backend.main:app",
        "--host", "127.0.0.1", "--port", "8000"
    ])
    
    # Wait 2 seconds for backend to initialize database tables
    time.sleep(2)
    
    frontend_app = BASE_DIR / "frontend" / "app.py"
    frontend_proc = subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", str(frontend_app),
        "--server.port", "8501"
    ])
    
    print("\n✓ Services successfully launched:")
    print("  • Backend API Docs: http://127.0.0.1:8000/docs")
    print("  • Frontend Dashboard: http://localhost:8501")
    print("  • Default Admin: admin@privacyanalyzer.local | AdminSecurePassword123!")
    print("\nPress Ctrl+C to terminate both servers.")
    
    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\nTerminating services...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("Shutdown complete.")

if __name__ == "__main__":
    main()
