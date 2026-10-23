import shutil
import subprocess
import time
from pathlib import Path


MAX_OUTPUT = 20_000

TOOLS = [
    {
        "id": "file",
        "title": "file command",
        "command": ["file", "-b"],
        "hint": "GNU file is usually bundled with Git for Windows (pacman -S file).",
    },
    {
        "id": "exiftool",
        "title": "exiftool",
        "command": ["exiftool"],
        "hint": "Windows: winget install exiftool. Linux: apt install libimage-exiftool-perl.",
    },
    {
        "id": "binwalk",
        "title": "binwalk",
        "command": ["binwalk"],
        "hint": "pip install binwalk, or apt install binwalk on Linux.",
    },
    {
        "id": "strings",
        "title": "strings",
        "command": ["strings", "-n", "6"],
        "hint": "Part of GNU binutils (MSYS: pacman -S binutils, Linux: apt install binutils).",
    },
    {
        "id": "zsteg",
        "title": "zsteg",
        "command": ["zsteg"],
        "hint": "Ruby gem: gem install zsteg (PNG and BMP only).",
    },
    {
        "id": "steghide",
        "title": "steghide info",
        "command": ["steghide", "info", "-p", ""],
        "hint": "Linux or WSL: apt install steghide.",
    },
    {
        "id": "identify",
        "title": "identify",
        "command": ["identify"],
        "hint": "ImageMagick, then run identify from the same shell.",
    },
]


def run_tool(tool, path):
    executable = shutil.which(tool["command"][0])
    if executable is None:
        return {
            "id": tool["id"],
            "title": tool["title"],
            "status": "unavailable",
            "text": "",
            "hint": tool["hint"],
            "duration_ms": 0,
        }

    argv = [executable, *tool["command"][1:], str(path)]
    timeout = tool.get("timeout", 20)
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            cwd=str(Path(path).parent),
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "id": tool["id"],
            "title": tool["title"],
            "status": "error",
            "text": f"{tool['title']} took longer than {timeout} seconds and was stopped.",
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    except OSError as error:
        return {
            "id": tool["id"],
            "title": tool["title"],
            "status": "error",
            "text": f"Could not run {tool['title']}: {error}",
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }

    raw = (completed.stdout or b"") + (completed.stderr or b"")
    text = raw.decode("utf-8", "replace").strip()
    text = text.replace(str(path), Path(path).name)
    if len(text) > MAX_OUTPUT:
        text = text[:MAX_OUTPUT].rstrip() + f"\n... output truncated ({len(text)} characters total)"

    duration_ms = int((time.perf_counter() - started) * 1000)
    if not text:
        return {
            "id": tool["id"],
            "title": tool["title"],
            "status": "empty",
            "text": "",
            "note": f"{tool['title']} printed nothing.",
            "duration_ms": duration_ms,
        }

    return {
        "id": tool["id"],
        "title": tool["title"],
        "status": "ok" if completed.returncode == 0 else "error",
        "text": text,
        "note": None if completed.returncode == 0 else f"Exit code {completed.returncode}.",
        "duration_ms": duration_ms,
    }
