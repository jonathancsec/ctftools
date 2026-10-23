import re
import zlib

try:
    import numpy as np
except ImportError:  # numpy makes LSB work faster, but it is optional
    np = None

try:
    from PIL import ExifTags, Image, UnidentifiedImageError
except ImportError:  # Pillow is optional: the page degrades to raw byte checks
    ExifTags = None
    Image = None
    UnidentifiedImageError = OSError


PRINTABLE_TEXT = re.compile(rb"[\x20-\x7e]{6,}")
MAX_LISTED_STRINGS = 8


def _preview(value, limit=64):
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    text = str(value)
    text = "".join(character if 32 <= ord(character) < 127 else "?" for character in text)
    return text[:limit] + ("..." if len(text) > limit else "")


def describe(path):
    if Image is None:
        return None
    try:
        with Image.open(path) as image:
            return {
                "format": image.format or "unknown",
                "width": image.width,
                "height": image.height,
                "mode": image.mode,
                "frames": getattr(image, "n_frames", 1),
            }
    except Exception:
        return None


def metadata(path):
    lines = []
    if Image is None:
        return ["Pillow is not installed, so EXIF and embedded metadata cannot be read."]

    try:
        with Image.open(path) as image:
            exif = image.getexif()
            for tag_id, value in exif.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id)) if ExifTags else str(tag_id)
                lines.append(f"{name}: {_preview(value, 120)}")

            try:
                exif_ifd = exif.get_ifd(0x8769)
            except Exception:
                exif_ifd = {}
            for tag_id, value in exif_ifd.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id)) if ExifTags else str(tag_id)
                lines.append(f"Exif.{name}: {_preview(value, 120)}")

            for key, value in image.info.items():
                if key in {"exif", "icc_profile", "xmp"}:
                    size = len(value) if value else 0
                    lines.append(f"{key}: {size} bytes")
                elif isinstance(value, str):
                    lines.append(f"{key}: {_preview(value, 120)}")
                elif isinstance(value, bytes):
                    lines.append(f"{key}: {len(value)} bytes of binary data")
    except UnidentifiedImageError:
        return ["Not an image Pillow can read, so there is no EXIF or embedded metadata to list."]
    except Exception as error:
        lines.append(f"Could not read metadata: {error}")

    return lines


def png_chunks(data):
    lines = []
    offset = 8
    chunk_count = 0
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return ["Not a PNG file."]

    while offset + 8 <= len(data) and chunk_count < 80:
        length = int.from_bytes(data[offset:offset + 4], "big")
        chunk_type = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + length]
        name = chunk_type.decode("latin-1")
        entry = f"{offset:>8}  {name:<4}  {length:>7} bytes"

        if chunk_type in {b"tEXt", b"zTXt", b"iTXt"}:
            entry += f"  {_preview(body, 80)}"
        elif chunk_type == b"IHDR" and len(body) >= 8:
            width = int.from_bytes(body[0:4], "big")
            height = int.from_bytes(body[4:8], "big")
            entry += f"  {width} x {height}"

        expected = int.from_bytes(data[offset + 8 + length:offset + 12 + length], "big")
        actual = zlib.crc32(chunk_type + body) & 0xFFFFFFFF
        if expected != actual:
            entry += "  CRC MISMATCH"

        lines.append(entry)
        chunk_count += 1
        offset += 12 + length

        if chunk_type == b"IEND":
            trailing = len(data) - offset
            if trailing > 0:
                lines.append(f"\n{trailing} bytes after IEND: {data[offset:offset + 32].hex(' ')}")
            break

    if chunk_count >= 80:
        lines.append("\nStopped after 80 chunks.")
    return lines


JPEG_MARKERS = {
    0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2", 0xC3: "SOF3",
    0xC4: "DHT", 0xDB: "DQT", 0xDA: "SOS", 0xD8: "SOI", 0xD9: "EOI",
    0xDD: "DRI", 0xE0: "APP0", 0xE1: "APP1", 0xE2: "APP2", 0xE3: "APP3",
    0xE4: "APP4", 0xE5: "APP5", 0xE6: "APP6", 0xE7: "APP7", 0xE8: "APP8",
    0xE9: "APP9", 0xEA: "APP10", 0xEB: "APP11", 0xEC: "APP12", 0xED: "APP13",
    0xEE: "APP14", 0xEF: "APP15", 0xFE: "COM",
}


def jpeg_segments(data):
    lines = []
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            lines.append(f"Unexpected byte 0x{data[offset]:02x} at offset {offset}.")
            break

        marker = data[offset + 1]
        if marker == 0xD8:
            offset += 2
            continue
        if marker == 0xD9:
            lines.append(f"{offset:>8}  EOI")
            trailing = len(data) - offset - 2
            if trailing > 0:
                lines.append(f"\n{trailing} bytes after EOI: {data[offset + 2:offset + 34].hex(' ')}")
            return lines

        name = JPEG_MARKERS.get(marker)
        if name is None:
            lines.append(f"{offset:>8}  marker FF{marker:02X}")
            break

        length = int.from_bytes(data[offset + 2:offset + 4], "big")
        body = data[offset + 4:offset + 2 + length]
        entry = f"{offset:>8}  {name:<5}  {length:>6} bytes"

        if marker == 0xFE:
            entry += f"  {_preview(body, 90)}"
        elif 0xE0 <= marker <= 0xEF:
            entry += f"  {_preview(body[:16], 24)}"

        lines.append(entry)
        offset += 2 + length

        if marker == 0xDA:
            lines.append("\nImage data starts here.")
            return lines

    return lines


def _plane_bits(plane):
    if np is not None:
        values = np.frombuffer(plane, dtype=np.uint8) & 1
        return np.packbits(values.astype(np.uint8)).tobytes()

    bits = bytearray()
    for value in plane:
        bits.append(value & 1)
    packed = bytearray()
    for index in range(0, len(bits) - 7, 8):
        byte = 0
        for bit in bits[index:index + 8]:
            byte = (byte << 1) | bit
        packed.append(byte)
    return bytes(packed)


def _strings_in(data, limit=MAX_LISTED_STRINGS):
    found = []
    for match in PRINTABLE_TEXT.finditer(data):
        text = match.group().decode("latin-1")
        if text not in found:
            found.append(text[:90])
        if len(found) >= limit:
            break
    return found


def lsb_report(path):
    if Image is None:
        return ["Pillow is not installed, so LSB data cannot be inspected."]

    try:
        with Image.open(path) as image:
            has_alpha = image.mode in {"RGBA", "LA", "PA", "RGBa"}
            image = image.convert("RGBA")
            width, height = image.size
            raw = image.tobytes()
    except UnidentifiedImageError:
        return ["Not an image Pillow can read, so there is no pixel data to check."]
    except Exception as error:
        return [f"Could not read pixel data: {error}"]

    lines = []
    channel_names = ["R", "G", "B"] + (["A"] if has_alpha else [])
    for index, name in enumerate(channel_names):
        plane = raw[index::4]
        extracted = _plane_bits(plane)
        printable = sum(1 for byte in extracted if 32 <= byte < 127)
        ratio = (printable / len(extracted) * 100) if extracted else 0
        strings = _strings_in(extracted)
        summary = f"{name} channel LSB: {ratio:.1f}% printable, {len(strings)} string(s)"
        lines.append(summary)
        for text in strings:
            lines.append(f"    {text}")

    combined = bytearray()
    for index in range(3):
        combined.extend(_plane_bits(raw[index::4]))
    combined_strings = _strings_in(bytes(combined))
    lines.append(f"\nR,G,B LSB order: {len(combined_strings)} string(s)")
    for text in combined_strings:
        lines.append(f"    {text}")

    lines.append(f"\nPixels checked: {width} x {height}")
    return lines


def hexdump(data, length=256):
    lines = []
    chunk = data[:length]
    for offset in range(0, len(chunk), 16):
        block = chunk[offset:offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in block)
        text_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in block)
        lines.append(f"{offset:08x}  {hex_part:<47}  {text_part}")
    if len(data) > length:
        lines.append(f"\nShowing the first {length} of {len(data)} bytes.")
    return lines
