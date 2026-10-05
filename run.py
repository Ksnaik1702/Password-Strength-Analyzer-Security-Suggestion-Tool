"""
Run Script for Password Strength Analyzer & Security Tool
Launches the FastAPI backend and serves the interactive cybersecurity interface.
"""

import sys
import webbrowser
import uvicorn

if __name__ == "__main__":
    port = 8000
    host = "127.0.0.1"
    url = f"http://{host}:{port}"
    print("=" * 70)
    print("🛡️  PASSWORD STRENGTH ANALYZER & SECURITY SUGGESTION TOOL")
    print("    Defensive Cybersecurity Course Project")
    print(f"    Serving Application at: {url}")
    print("    Swagger API Docs at:   http://127.0.0.1:8000/docs")
    print("    Privacy Notice: Zero Plaintext Password Logging or Storage")
    print("=" * 70)

    # Launch browser automatically
    try:
        webbrowser.open(url)
    except Exception:
        pass

    uvicorn.run("backend.app:app", host=host, port=port, reload=True)
