import signal
import sys
from pathlib import Path

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit to prevent hangs


def setup_kill_switch():
    """Catch Ctrl+C (SIGINT) and exit cleanly without a traceback."""
    def _handler(sig, frame):
        print("\n[!] Kill switch triggered (Ctrl+C). Analysis stopped safely.")
        sys.exit(0)
    signal.signal(signal.SIGINT, _handler)


def require_legal_authorization():
    """Show Computer Crimes Act 1997 disclaimer and require explicit YES."""
    banner = """
====================================================================
  MALSCOPE - STATIC MALWARE ANALYZER (AUTHORIZED USE ONLY)
====================================================================
  LEGAL DISCLAIMER (COMPUTER CRIMES ACT 1997 / ACT 563):
  This tool is strictly for static file analysis in an authorized
  environment. Accessing or analyzing files or systems without
  explicit permission is an offense under Malaysia's Computer
  Crimes Act 1997. All outputs are saved locally (no network).
====================================================================
"""
    print(banner)
    choice = input("Do you have authorization to analyze this file? (type YES to continue): ").strip()
    if choice != "YES":
        print("[!] Authorization not confirmed. Exiting.")
        sys.exit(1)


def validate_scope(target_path: str, allowed_dirs: list[str]) -> Path:
    """Verify the file exists, is within safe size limits, and is inside allowed directories."""
    target = Path(target_path).resolve()

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"File not found: {target}")

    if target.stat().st_size == 0:
        raise ValueError("Empty file (0 bytes) - cannot perform static PE analysis.")

    if target.stat().st_size > MAX_FILE_SIZE_BYTES:
        raise ValueError("File size exceeds the safe 50 MB limit.")

    allowed_resolved = [Path(d).resolve() for d in allowed_dirs]
    in_scope = any(target.parent == allowed or allowed in target.parents for allowed in allowed_resolved)

    if not in_scope:
        raise PermissionError(
            f"Access denied (Out of Scope): '{target}' is outside allowed directories {[str(p) for p in allowed_resolved]}."
        )

    return target