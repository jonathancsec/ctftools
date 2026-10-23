import argparse
import base64
import binascii
import html
import urllib.parse


MORSE_LETTERS = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", "-..-.": "/",
    "-....-": "-", "-.--.": "(", "-.--.-": ")", "---...": ":",
    ".--.-.": "@", "-...-": "=", ".-.-.": "+", ".-..-.": '"',
    "-.-.--": "!", ".----.": "'",
}


def to_text(data):
    """Turn raw bytes into readable text, even when they are not valid UTF-8."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def decode_binary(text):
    if not text.strip():
        raise ValueError("Enter some binary first.")

    unexpected = {character for character in text if character not in "01 \t\r\n"}
    if unexpected:
        raise ValueError("Binary input can only contain 0s, 1s, and spaces.")

    bits = "".join(character for character in text if character in "01")
    if len(bits) % 8:
        raise ValueError(f"Binary needs groups of 8 bits (got {len(bits)}).")

    data = bytes(int(bits[index:index + 8], 2) for index in range(0, len(bits), 8))
    return to_text(data)


def decode_hex(text):
    cleaned = "".join(
        character for character in text
        if not character.isspace() and character not in ",:-"
    )
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]

    if not cleaned:
        raise ValueError("Enter some hex first.")

    if any(character not in "0123456789abcdefABCDEF" for character in cleaned):
        raise ValueError("Hex input can only contain 0-9, a-f, and spaces.")

    if len(cleaned) % 2:
        raise ValueError(f"Hex needs an even number of digits (got {len(cleaned)}).")

    return to_text(bytes.fromhex(cleaned))


def decode_base64(text):
    cleaned = "".join(text.split())
    if not cleaned:
        raise ValueError("Enter some Base64 first.")

    cleaned = cleaned.replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)

    try:
        data = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("That does not look like valid Base64.") from None

    return to_text(data)


def decode_base32(text):
    cleaned = "".join(text.split()).upper()
    if not cleaned:
        raise ValueError("Enter some Base32 first.")

    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for character in cleaned):
        raise ValueError("That does not look like valid Base32.")

    cleaned += "=" * (-len(cleaned) % 8)
    try:
        data = base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError):
        raise ValueError("That does not look like valid Base32.") from None

    return to_text(data)


def _printable_ratio(text):
    if not text:
        return 0.0
    printable = sum(1 for character in text if character.isprintable() or character in "\n\r\t")
    return printable / len(text)


def decode_base85(text):
    """Try Ascii85 and RFC 1924 Base85, keeping the most readable result."""
    cleaned = "".join(text.split())
    if not cleaned:
        raise ValueError("Enter some Base85 or Ascii85 first.")

    attempts = []
    if cleaned.startswith("<~") and cleaned.endswith("~>"):
        attempts.append(lambda: base64.a85decode(cleaned, adobe=True))
    else:
        attempts.append(lambda: base64.a85decode(cleaned))
        attempts.append(lambda: base64.b85decode(cleaned))

    decoded = []
    for attempt in attempts:
        try:
            decoded.append(to_text(attempt()))
        except (ValueError, binascii.Error):
            continue

    if not decoded:
        raise ValueError("That does not look like valid Base85 or Ascii85.")
    return max(decoded, key=_printable_ratio)


def decode_url(text):
    if "%" not in text and "+" not in text:
        raise ValueError("No percent-escapes or plus signs found to decode.")

    data = urllib.parse.unquote_to_bytes(text.replace("+", " "))
    return to_text(data)


def decode_html(text):
    if "&" not in text:
        raise ValueError("No HTML entities found to decode.")

    decoded = html.unescape(text)
    if decoded == text:
        raise ValueError("No HTML entities found to decode.")
    return decoded.replace("\xa0", " ")


def decode_morse(text):
    if not text.strip():
        raise ValueError("Enter some Morse code first.")

    normalized = (
        text.replace("·", ".")
        .replace("•", ".")
        .replace("–", "-")
        .replace("—", "-")
        .replace("_", "-")
    )

    unexpected = {character for character in normalized if character not in ".-/ \t\r\n"}
    if unexpected:
        raise ValueError("Morse can only contain dots, dashes, spaces, and / between words.")

    words = [word for word in normalized.split("/") if word.strip()]
    decoded_words = []
    for word in words:
        decoded_words.append("".join(MORSE_LETTERS.get(code, "?") for code in word.split()))
    return " ".join(decoded_words)


DECODERS = {
    "binary": decode_binary,
    "hex": decode_hex,
    "base32": decode_base32,
    "base64": decode_base64,
    "base85": decode_base85,
    "morse": decode_morse,
    "url": decode_url,
    "html": decode_html,
}


def main():
    parser = argparse.ArgumentParser(description="Decode binary, hex, Base32/64/85, URL, HTML, or Morse.")
    parser.add_argument("encoding", choices=sorted(DECODERS), help="The input encoding")
    parser.add_argument("text", help="The encoded text")
    args = parser.parse_args()

    try:
        print(DECODERS[args.encoding](args.text))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
