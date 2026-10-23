import re
from pathlib import Path

from .. import runner
from ..base import ToolResult, ToolSpec

try:
    from PIL import Image, __version__ as pillow_version
except ImportError:  # Pillow is part of the image; keep the module importable
    Image = None
    pillow_version = "not installed"

try:
    import numpy as np
except ImportError:
    np = None


SPEC = ToolSpec(
    key="steganography",
    display_name="Steganography checks",
    binary=None,
    timeout=60,
    install_hint="apt install steghide (image pixel checks are built in)",
)

STEGHIDE = ToolSpec(
    key="steghide",
    display_name="steghide",
    binary="steghide",
    version_args=("--version",),
    timeout=45,
    install_hint="apt install steghide",
)

TITLE = "Steganography"

PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")
EMBEDDED_FILE = re.compile(r'embedded file "([^"]+)"')
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
MAX_PIXELS_NUMPY = 25_000_000
MAX_PIXELS_PYTHON = 4_000_000


def applies_to(file_info):
    return file_info.is_image


def _pack_lsb(plane):
    if np is not None:
        bits = (np.frombuffer(plane, dtype=np.uint8) & 1).astype(np.uint8)
        return np.packbits(bits).tobytes()

    bits = bytearray(byte & 1 for byte in plane)
    packed = bytearray()
    for index in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[index:index + 8]:
            value = (value << 1) | bit
        packed.append(value)
    return bytes(packed)


def _printable_strings(data, limit=6):
    found = []
    for match in PRINTABLE.finditer(data):
        text = match.group().decode("latin-1")
        if text not in found:
            found.append(text[:120])
        if len(found) >= limit:
            break
    return found


def _lsb_lines(image):
    pixel_count = image.width * image.height
    budget = MAX_PIXELS_NUMPY if np is not None else MAX_PIXELS_PYTHON
    if pixel_count > budget:
        return [
            f"Skipped LSB inspection: {image.width} x {image.height} is above the "
            f"{budget:,} pixel safety limit."
        ]

    has_alpha = image.mode in {"RGBA", "LA", "PA", "RGBa"}
    rgba = image.convert("RGBA")
    raw = rgba.tobytes()

    names = ["R", "G", "B"] + (["A"] if has_alpha else [])
    lines = []
    for index, name in enumerate(names):
        packed = _pack_lsb(raw[index::4])
        printable = sum(1 for byte in packed if 32 <= byte < 127)
        ratio = (printable / len(packed) * 100) if packed else 0
        strings = _printable_strings(packed)
        lines.append(f"{name} channel LSB: {ratio:.1f}% printable, {len(strings)} string(s)")
        for text in strings:
            lines.append(f"    {text}")

    combined = bytearray()
    for index in range(3):
        combined.extend(_pack_lsb(raw[index::4]))
    combined_strings = _printable_strings(bytes(combined))
    lines.append(f"\nR,G,B interleaved LSB: {len(combined_strings)} string(s)")
    for text in combined_strings:
        lines.append(f"    {text}")

    return lines


def _safe_output_path(directory, name):
    base = Path(name).name if name else "steghide-extracted.bin"
    cleaned = SAFE_NAME.sub("_", base).strip("._")[:100] or "steghide-extracted.bin"
    target = directory / cleaned
    counter = 1
    while target.exists():
        target = directory / f"{Path(cleaned).stem}-{counter}{Path(cleaned).suffix}"
        counter += 1
    return target


def _steghide_lines(context):
    """Run steghide once. With a passphrase (or an empty one) this extracts
    embedded data to the job's artifact directory; it never guesses passwords."""
    if not runner.available(STEGHIDE):
        return (
            ["steghide is not installed, so passphrase-protected embedded data was not checked."],
            "unavailable",
            [],
        )

    passphrase = context.passphrase or ""
    path = context.file_info.path

    try:
        info = runner.run(
            STEGHIDE,
            ["info", "-p", passphrase, str(path)],
            timeout=STEGHIDE.timeout,
            stdin_text="y\n",
        )
    except runner.ToolTimeout as error:
        return [str(error)], "failed", []
    except runner.ToolUnavailable as error:
        return [str(error)], "unavailable", []

    output = info.output.strip()
    lowered = output.lower()
    embedded = EMBEDDED_FILE.search(output)
    lines = ["steghide info:", output or "(no output)"]
    artifacts = []

    if embedded:
        lines.append(f"Embedded file: {embedded.group(1)}")
    if "could not extract any data" in lowered or "no embedded data" in lowered:
        if context.passphrase:
            lines.append("Result: the supplied passphrase did not unlock any embedded data.")
        else:
            lines.append("Result: no embedded data was found with an empty passphrase.")
            lines.append("If the file uses a passphrase, provide it when uploading.")
        return lines, "completed", artifacts
    if "unknown file format" in lowered or "not supported" in lowered:
        lines.append("Result: steghide does not support this file format.")
        return lines, "completed", artifacts
    if info.returncode != 0:
        lines.append(f"Result: steghide could not read the file (exit code {info.returncode}).")
        return lines, "completed", artifacts

    # steghide listed an embedded file: extract exactly once, to a name we choose.
    if embedded or "embedded file" in lowered:
        directory = context.artifact_dir("steganography")
        target = _safe_output_path(directory, embedded.group(1) if embedded else None)
        try:
            extract = runner.run(
                STEGHIDE,
                [
                    "extract", "-sf", str(path),
                    "-p", passphrase,
                    "-xf", str(target),
                    "-f",
                ],
                timeout=STEGHIDE.timeout,
                stdin_text="y\n",
            )
        except runner.ToolTimeout as error:
            return [*lines, f"Extraction failed: {error}"], "failed", artifacts
        except runner.ToolUnavailable as error:
            return [*lines, f"Extraction failed: {error}"], "unavailable", artifacts

        if target.is_file() and target.stat().st_size > 0:
            artifacts.append(target)
            lines.append(
                f"Extracted {target.name} ({target.stat().st_size} bytes) to the artifacts section."
            )
        else:
            lines.append("Extraction produced no file; the embedded data may be damaged.")
            if extract.output.strip():
                lines.append(extract.output.strip())
        return lines, "completed", artifacts

    lines.append("Result: steghide found no embedded file to extract.")
    return lines, "completed", artifacts


def analyze(context):
    lines = []
    errors = []
    properties = None

    if Image is None:
        lines.append("Pillow is not installed, so image properties and LSB checks were skipped.")
    else:
        try:
            with Image.open(context.file_info.path) as image:
                properties = {
                    "format": image.format,
                    "width": image.width,
                    "height": image.height,
                    "mode": image.mode,
                    "frames": getattr(image, "n_frames", 1),
                }
                info_keys = sorted(key for key in image.info if key not in {"exif", "icc_profile"})

                lines.append("Image properties")
                lines.append(f"    Format: {properties['format']}")
                lines.append(f"    Dimensions: {properties['width']} x {properties['height']}")
                lines.append(f"    Mode: {properties['mode']}")
                lines.append(f"    Frames: {properties['frames']}")
                if info_keys:
                    lines.append(f"    Metadata keys: {', '.join(info_keys)}")

                lines.append("\nLeast-significant-bit scan")
                try:
                    for line in _lsb_lines(image):
                        lines.append(line if line.startswith("    ") else f"    {line}")
                except Exception as error:
                    lines.append(f"    LSB inspection failed: {error}")
        except Exception as error:
            lines.append(f"Pillow could not open the image: {error}")

    steghide_lines, steghide_status, artifacts = _steghide_lines(context)
    lines.append("\nsteghide")
    lines.extend(steghide_lines)

    versions = [f"Pillow {pillow_version}"]
    if runner.available(STEGHIDE):
        versions.append(runner.version(STEGHIDE) or "steghide")

    summary_bits = []
    if properties:
        summary_bits.append(
            f"{properties['format']} {properties['width']}x{properties['height']} {properties['mode']}"
        )
    summary_bits.append("steghide " + ("available" if runner.available(STEGHIDE) else "not installed"))
    if artifacts:
        summary_bits.append(f"{len(artifacts)} file(s) extracted")

    status = "completed"
    if steghide_status == "failed":
        status = "failed"
        errors.append("steghide check failed.")
    if properties is None and not runner.available(STEGHIDE):
        status = "unavailable"

    return ToolResult(
        status=status,
        summary=", ".join(summary_bits),
        output="\n".join(lines),
        error=" ".join(errors),
        version=" / ".join(versions),
        artifacts=artifacts,
    )
