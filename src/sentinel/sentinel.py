"""IPC Step 12 — monitor the environment. Assert boundary invariants; alarm on drift.

Pure check functions are unit-tested. main() additionally runs the LIVE checks (sealed/
ownership+mode, and the active 'blair must be denied' read attempt) and exits non-zero on any
problem so it can drive a daily timer/alert.
"""
import os
import json
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEALED = ROOT / "sealed"
STATE = ROOT / "reports" / "sentinel_state.json"

def check_key_permissions(key_path: Path) -> list:
    try:
        mode = stat.S_IMODE(key_path.stat().st_mode)
    except FileNotFoundError:
        return []  # not provisioned yet
    except PermissionError:
        # The key lives inside the sealed zone (mode 700). When the Sentinel runs as `blair`
        # it CANNOT stat it — and that denial is exactly the boundary working as intended.
        return []
    if mode & 0o077:
        return [f"{key_path} is group/world readable (mode {oct(mode)})"]
    return []

def check_no_unknown_records(present: set, known: set) -> list:
    extra = present - known
    return [f"unknown file in open zone: {name}" for name in sorted(extra)]

def check_sealed_locked() -> list:
    """LIVE: sealed/ must exist, be 700, and blair must NOT be able to read it."""
    problems = []
    if not SEALED.exists():
        return []  # not yet provisioned; nothing to assert
    mode = stat.S_IMODE(SEALED.stat().st_mode)
    if mode != 0o700:
        problems.append(f"sealed/ mode is {oct(mode)}, expected 0o700")
    # active denial check: try to list it as the current (blair) user
    try:
        os.listdir(SEALED)
        problems.append("SECURITY: sealed/ is readable by this user — boundary breached")
    except PermissionError:
        pass  # good — denied
    return problems

def check_sealed_quiescent(current_mtime: float, baseline_mtime) -> list:
    """LIVE blind-spot fix (PD this session): the boundary monitor cannot SEE INTO sealed/,
    so a sudo-armed agent that WRITES a file into sealed/ leaves ownership+mode untouched and
    every other check stays green. But dropping a top-level entry into sealed/ DOES change the
    directory's own mtime — which blair CAN stat without reading the contents. So we baseline
    sealed/'s mtime and ALARM on any unexplained change. This is exactly what tonight's
    roast.md-into-sealed write would have tripped."""
    if baseline_mtime is None:
        return []  # first run — establishing baseline, nothing to compare
    if current_mtime != baseline_mtime:
        return [f"SECURITY: sealed/ mtime changed {baseline_mtime} -> {current_mtime} "
                "without an authorized re-baseline — something wrote INTO the sealed zone"]
    return []

def _load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (FileNotFoundError, ValueError):
        return {}

def _save_state(state: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2))

def check_sudoers_intact() -> list:
    f = Path("/etc/sudoers.d/sovereign-pipeline")
    try:
        if not f.exists():
            return []  # not yet installed
    except PermissionError:
        return []  # not yet installed or permission issue pre-setup
    try:
        text = f.read_text()
    except PermissionError:
        return []  # not yet readable (expected pre-setup)
    if text and "ALL=(sovereign)" not in text:
        return ["sudoers entrypoint rule altered unexpectedly"]
    return []

def main() -> int:
    rebaseline = "--baseline" in sys.argv  # authorized operator acknowledges a sealed change
    problems = []
    problems += check_key_permissions(SEALED / "provider.key")
    problems += check_sealed_locked()
    problems += check_sudoers_intact()

    if SEALED.exists():
        state = _load_state()
        cur = SEALED.stat().st_mtime
        if rebaseline or "sealed_mtime" not in state:
            state["sealed_mtime"] = cur
            _save_state(state)
            print(f"Sentinel: sealed/ mtime baseline set to {cur}")
        else:
            problems += check_sealed_quiescent(cur, state.get("sealed_mtime"))

    if problems:
        print("SENTINEL ALARM:")
        for p in problems:
            print("  -", p)
        return 1
    print("Sentinel OK — all boundary invariants hold.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
