"""Content-based file identification.

The upload filename is never trusted: types come from magic bytes and, for
images, from Pillow. The extension is reported for the user's benefit only.
"""

import hashlib
from pathlib import Path

from .base import FileInfo

try:
    from PIL import Image
except ImportError:  # Pillow is optional for detection, required for image tools
    Image = None


HEADER_SIZE = 4096

MAGIC_BYTES = [
    # (signature, offset, label, mime, kind)
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", "image/png", "image"),
    (b"\xff\xd8\xff", 0, "JPEG image", "image/jpeg", "image"),
    (b"GIF87a", 0, "GIF image", "image/gif", "image"),
    (b"GIF89a", 0, "GIF image", "image/gif", "image"),
    (b"BM", 0, "BMP image", "image/bmp", "image"),
    (b"II*\x00", 0, "TIFF image", "image/tiff", "image"),
    (b"MM\x00*", 0, "TIFF image", "image/tiff", "image"),
    (b"%PDF", 0, "PDF document", "application/pdf", "document"),
    (b"PK\x03\x04", 0, "ZIP archive", "application/zip", "archive"),
    (b"PK\x05\x06", 0, "Empty ZIP archive", "application/zip", "archive"),
    (b"Rar!\x1a\x07", 0, "RAR archive", "application/vnd.rar", "archive"),
    (b"\x1f\x8b", 0, "gzip archive", "application/gzip", "archive"),
    (b"BZh", 0, "bzip2 archive", "application/x-bzip2", "archive"),
    (b"\xfd7zXZ\x00", 0, "XZ archive", "application/x-xz", "archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", "application/x-7z-compressed", "archive"),
    (b"SQLite format 3\x00", 0, "SQLite database", "application/vnd.sqlite3", "database"),
    (b"\x7fELF", 0, "ELF executable", "application/x-elf", "executable"),
    (b"MZ", 0, "Windows executable", "application/vnd.microsoft.portable-executable", "executable"),
    (b"fLaC", 0, "FLAC audio", "audio/flac", "audio"),
    (b"OggS", 0, "Ogg media", "application/ogg", "audio"),
    (b"ID3", 0, "MP3 audio", "audio/mpeg", "audio"),
    (b"8BPS", 0, "Photoshop document", "image/vnd.adobe.photoshop", "image"),
    (b"\x00\x00\x01\x00", 0, "ICO image", "image/x-icon", "image"),
    (b"ustar", 257, "tar archive", "application/x-tar", "archive"),
    (b"CD001", 32769, "ISO 9660 image", "application/x-iso9660-image", "disk"),
    (b"\x53\xef", 1080, "ext2/3/4 filesystem", "application/x-ext4", "disk"),
]

PCAP_SIGNATURES = {
    b"\xd4\xc3\xb2\xa1": "pcap capture (little endian)",
    b"\xa1\xb2\xc3\xd4": "pcap capture (big endian)",
    b"\x4d\x3c\xb2\xa1": "pcap capture (nanosecond)",
    b"\xa1\xb2\x3c\x4d": "pcap capture (nanosecond, big endian)",
}

PCAPNG_SIGNATURE = b"\x0a\x0d\x0d\x0a"

RIFF_SUBTYPES = {
    b"WEBP": ("WebP image", "image/webp", "image"),
    b"WAVE": ("WAV audio", "audio/wav", "audio"),
    b"AVI ": ("AVI video", "video/x-msvideo", "video"),
}

READABLE_BYTES = set(range(32, 127)) | {9, 10, 13}


def _looks_like_text(sample):
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    printable = sum(1 for byte in sample if byte in READABLE_BYTES)
    return printable / len(sample) >= 0.85


def _looks_like_mbr(sample):
    if len(sample) < 512 or sample[510:512] != b"\x55\xaa":
        return False
    return any(byte != 0 for byte in sample[446:510])


def hash_file(path, algorithm="sha256", chunk_size=1024 * 1024):
    digest = hashlib.new(algorithm)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_from_bytes(data, original_name=""):
    """Return (label, mime, kind) for the given bytes, or a text fallback."""
    if data.startswith(PCAPNG_SIGNATURE):
        return "pcapng capture", "application/x-pcapng", "pcap"
    if data[:4] in PCAP_SIGNATURES:
        return PCAP_SIGNATURES[data[:4]], "application/vnd.tcpdump.pcap", "pcap"

    if data[:4] == b"RIFF" and len(data) >= 12:
        subtype = data[8:12]
        if subtype in RIFF_SUBTYPES:
            return RIFF_SUBTYPES[subtype]

    for signature, offset, label, mime, kind in MAGIC_BYTES:
        end = offset + len(signature)
        if len(data) >= end and data[offset:end] == signature:
            return label, mime, kind

    if _looks_like_mbr(data):
        return "disk image (MBR boot sector)", "application/x-raw-disk-image", "disk"

    if _looks_like_text(data):
        return "text file", "text/plain", "text"

    return "unknown binary", "application/octet-stream", "binary"


def _pillow_details(path):
    if Image is None:
        return None
    try:
        with Image.open(path) as image:
            return {
                "format": image.format,
                "size": image.size,
                "mode": image.mode,
                "frames": getattr(image, "n_frames", 1),
            }
    except Exception:
        return None


def detect_file(path, original_name=""):
    path = Path(path)
    with open(path, "rb") as handle:
        sample = handle.read(HEADER_SIZE)

    label, mime, kind = detect_from_bytes(sample, original_name)
    details = _pillow_details(path)
    if details and kind == "binary":
        # Pillow recognised something the magic table did not.
        label = f"{details['format']} image"
        mime = f"image/{details['format'].lower()}"
        kind = "image"

    extension = Path(original_name or "").suffix.lower().lstrip(".")
    size = path.stat().st_size

    return FileInfo(
        path=path,
        original_name=original_name or path.name,
        size=size,
        sha256=hash_file(path, "sha256"),
        md5=hash_file(path, "md5"),
        extension=extension,
        type_label=label,
        mime=mime,
        is_text=kind == "text",
        is_image=kind == "image",
        is_archive=kind == "archive",
        is_pcap=kind == "pcap",
        is_disk_image=kind == "disk",
        image_format=details["format"] if details else None,
        image_size=details["size"] if details else None,
        image_mode=details["mode"] if details else None,
    )


def _zip_metadata_spans(data):
    """Byte ranges covered by ZIP central directories and end records.

    Signatures match inside those structures by accident (six bytes of a ZIP
    end record look like a tiny ICO header), so hits found there are not
    embedded files and are dropped by the signature scan.
    """
    spans = []
    start = 0
    while True:
        header = data.find(b"PK\x03\x04", start)
        if header < 0:
            break
        start = header + 4

        end_record = data.find(b"PK\x05\x06", header)
        if end_record < 0 or len(data) < end_record + 22:
            continue

        directory_size = int.from_bytes(data[end_record + 12:end_record + 16], "little")
        directory_offset = int.from_bytes(data[end_record + 16:end_record + 20], "little")
        comment_size = int.from_bytes(data[end_record + 20:end_record + 22], "little")
        archive_end = min(len(data), end_record + 22 + comment_size)
        directory_start = header + directory_offset

        if directory_size and header <= directory_start <= end_record:
            spans.append((directory_start, archive_end))
        else:
            spans.append((end_record, archive_end))
    return spans


def scan_signatures(path, limit=64 * 1024 * 1024):
    """Yield (offset, label) for known signatures inside a file.

    A bounded read keeps huge uploads from exhausting memory; the limit is
    reported to the user by the caller.
    """
    data = Path(path).read_bytes()
    scanned = data[:limit]
    hits = []
    for signature, _offset, label, _mime, _kind in MAGIC_BYTES:
        start = 0
        while True:
            index = scanned.find(signature, start)
            if index < 0:
                break
            hits.append((index, label))
            start = index + 1
            if len(hits) > 200:
                break
        if len(hits) > 200:
            break
    if PCAPNG_SIGNATURE in scanned:
        hits.append((scanned.find(PCAPNG_SIGNATURE), "pcapng capture"))
    for signature in PCAP_SIGNATURES:
        index = scanned.find(signature)
        if index >= 0:
            hits.append((index, PCAP_SIGNATURES[signature]))

    spans = _zip_metadata_spans(scanned)
    if spans:
        hits = [
            (offset, label)
            for offset, label in hits
            if not any(start < offset < end for start, end in spans)
        ]

    hits.sort()
    return hits, len(data) > limit
