import hashlib
import io
import math
import re
import time
import zipfile
from collections import Counter

from . import external, images


STRING_PATTERN = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_PATTERN = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
INTERESTING = re.compile(r"flag|ctf|pass|secret|key|token|http|ssh|begin", re.IGNORECASE)

MAX_STRING_LINES = 250
MAX_UTF16_LINES = 25
MAX_EMBEDDED_HITS = 60

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"II*\x00", "TIFF image"),
    (b"MM\x00*", "TIFF image"),
    (b"RIFF", "RIFF container"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "Windows executable"),
    (b"fLaC", "FLAC audio"),
    (b"OggS", "Ogg container"),
    (b"ID3", "MP3 audio"),
    (b"8BPS", "Photoshop document"),
    (b"\x00\x00\x01\x00", "ICO image"),
]

SCAN_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\x7fELF", "ELF binary"),
    (b"fLaC", "FLAC audio"),
    (b"OggS", "Ogg container"),
    (b"ID3", "MP3 audio"),
    (b"8BPS", "Photoshop document"),
]


def detect_type(data):
    for signature, label in MAGIC:
        if data.startswith(signature):
            if signature == b"RIFF" and len(data) >= 12:
                flavour = data[8:12]
                if flavour == b"WEBP":
                    return "WebP image"
                if flavour == b"WAVE":
                    return "WAV audio"
                if flavour == b"AVI ":
                    return "AVI video"
            return label
    return None


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _zip_entries(data, offset):
    try:
        with zipfile.ZipFile(io.BytesIO(data[offset:])) as archive:
            infos = archive.infolist()
    except Exception:
        return None

    shown = ", ".join(f"{info.filename} ({info.file_size} bytes)" for info in infos[:6])
    extra = "" if len(infos) <= 6 else f" and {len(infos) - 6} more"
    return f"ZIP entries: {shown}{extra}"


def _section(section_id, title, lines, note=None, duration_ms=0):
    text = "\n".join(line for line in lines if line is not None).rstrip()
    return {
        "id": section_id,
        "title": title,
        "status": "ok" if text.strip() else "empty",
        "text": text,
        "note": note,
        "duration_ms": duration_ms,
    }


def file_section(path, data, label):
    lines = [f"{'Detected':<9} {label or 'Unknown signature'}"]

    dimensions = images.describe(path)
    if dimensions:
        frames = dimensions["frames"]
        lines.append(
            f"{'Image':<9} {dimensions['width']} x {dimensions['height']}, "
            f"{dimensions['mode']}, {frames} frame{'s' if frames != 1 else ''}"
        )

    lines.extend([
        f"{'Size':<9} {len(data):,} bytes",
        f"{'SHA-256':<9} {hashlib.sha256(data).hexdigest()}",
        f"{'MD5':<9} {hashlib.md5(data).hexdigest()}",
        f"{'Entropy':<9} {entropy(data):.2f} bits per byte",
    ])
    return _section("file", "File overview", lines)


def metadata_section(path):
    lines = images.metadata(path)
    return _section("metadata", "Metadata / EXIF", lines)


def structure_section(data, label):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return _section("structure", "PNG chunks", images.png_chunks(data))
    if data.startswith(b"\xff\xd8\xff"):
        return _section("structure", "JPEG segments", images.jpeg_segments(data))
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        entries = _zip_entries(data, 0)
        return _section("structure", "ZIP contents", [entries] if entries else ["Could not read the ZIP directory."])
    return _section(
        "structure",
        "File structure",
        [f"No structural parser for {label or 'this file type'} yet. Hexdump and signature scan below still apply."],
    )


def strings_section(data):
    ascii_matches = list(STRING_PATTERN.finditer(data))
    utf16_matches = list(UTF16_PATTERN.finditer(data))

    lines = []
    for match in ascii_matches[:MAX_STRING_LINES]:
        value = match.group().decode("latin-1")
        if len(value) > 120:
            value = value[:120] + "..."
        marker = "!" if INTERESTING.search(value) else " "
        lines.append(f"{marker} {value}")

    note_parts = [f"{len(ascii_matches)} printable strings"]
    if len(ascii_matches) > MAX_STRING_LINES:
        note_parts.append(f"showing the first {MAX_STRING_LINES}")

    if utf16_matches:
        lines.append("")
        lines.append("UTF-16LE strings:")
        for match in utf16_matches[:MAX_UTF16_LINES]:
            value = match.group().decode("utf-16-le", "replace")
            lines.append(f"  {value[:120]}")

    return _section(
        "strings",
        "Strings",
        lines,
        note=", ".join(note_parts) + ". Lines starting with ! look interesting (flag, key, http...).",
    )


def embedded_section(data, label):
    hits = []
    for signature, hit_label in SCAN_SIGNATURES:
        start = 0
        while True:
            index = data.find(signature, start)
            if index < 0:
                break
            hits.append((index, hit_label))
            start = index + 1
            if len(hits) > 400:
                break

    hits.sort()
    lines = []
    zip_listed = False
    for offset, hit_label in hits[:MAX_EMBEDDED_HITS]:
        suffix = "  (file header)" if offset == 0 and hit_label == label else ""
        lines.append(f"0x{offset:08x}  {hit_label}{suffix}")
        if hit_label == "ZIP archive" and not zip_listed:
            entries = _zip_entries(data, offset)
            if entries:
                lines.append(f"            {entries}")
                zip_listed = True

    if len(hits) > MAX_EMBEDDED_HITS:
        lines.append(f"\n... and {len(hits) - MAX_EMBEDDED_HITS} more signatures.")

    return _section(
        "embedded",
        "Embedded files",
        lines or ["No additional file signatures found."],
        note=f"{len(hits)} signature(s) found.",
    )


def lsb_section(path):
    lines = images.lsb_report(path)
    return _section("lsb", "LSB / pixel data", lines)


def hexdump_section(data):
    return _section("hexdump", "Hexdump", images.hexdump(data), note=f"First 256 of {len(data):,} bytes.")


def analyze_file(path, data, name):
    started = time.perf_counter()
    label = detect_type(data)
    sections = []

    for builder in (
        lambda: file_section(path, data, label),
        lambda: metadata_section(path),
        lambda: structure_section(data, label),
        lambda: strings_section(data),
        lambda: embedded_section(data, label),
        lambda: lsb_section(path),
        lambda: hexdump_section(data),
    ):
        section_started = time.perf_counter()
        try:
            section = builder()
        except Exception as error:
            section = _section("error", "Analysis error", [f"That check failed: {error}"])
        section["duration_ms"] = int((time.perf_counter() - section_started) * 1000)
        for field in ("text", "note"):
            if section.get(field):
                section[field] = section[field].replace(str(path), name)
        sections.append(section)

    for tool in external.TOOLS:
        sections.append(external.run_tool(tool, path))

    return {
        "name": name,
        "size": len(data),
        "type": label or "Unknown",
        "sha256": hashlib.sha256(data).hexdigest(),
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "sections": sections,
    }
