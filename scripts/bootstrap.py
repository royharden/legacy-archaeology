"""Install a locked lane-local environment without changing the caller's cwd."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

PYTHON = "3.12.13"
UV = "0.11.19"
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all-extras", action="store_true",
                        help="Include evaluator and PostgreSQL dependencies for development")
    parser.add_argument("--build", action="store_true", help="Include pinned wheel-building tools")
    args = parser.parse_args()
    uv = shutil.which("uv")
    if not uv:
        parser.error(f"uv {UV} must already be available on PATH")
    version = subprocess.check_output([uv, "--version"], text=True).split()
    if version[:2] != ["uv", UV]:
        parser.error(f"expected uv {UV}; got {' '.join(version)}")
    env = os.environ.copy()
    env["UV_PROJECT_ENVIRONMENT"] = str(ROOT / ".venv" / "runtime")
    env["UV_PYTHON_INSTALL_DIR"] = str(ROOT / ".venv" / "toolchain")
    # Explicit version, no global binary/registry writes and no environment removal.
    subprocess.run([uv, "python", "install", PYTHON, "--no-bin", "--no-registry"],
                   env=env, check=True)
    command = [uv, "sync", "--project", str(ROOT), "--python", PYTHON,
               "--managed-python", "--locked", "--inexact"]
    if args.all_extras:
        command.append("--all-extras")
    if args.build:
        command.extend(["--group", "build"])
    subprocess.run(command, env=env, check=True)
    executable = ROOT / ".venv" / "runtime" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([str(executable), "-c",
                    "import sys; assert sys.version_info[:3] == (3, 12, 13); print(sys.executable); print(sys.version)"],
                   env=env, check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
