import argparse
import base64
import binascii
import html
import re
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


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

NATO_ALPHABET = {
    "alpha": "A", "alfa": "A", "bravo": "B", "charlie": "C", "delta": "D",
    "echo": "E", "foxtrot": "F", "golf": "G", "hotel": "H", "india": "I",
    "juliett": "J", "juliet": "J", "kilo": "K", "lima": "L", "mike": "M",
    "november": "N", "oscar": "O", "papa": "P", "quebec": "Q", "romeo": "R",
    "sierra": "S", "tango": "T", "uniform": "U", "victor": "V", "whiskey": "W",
    "xray": "X", "yankee": "Y", "zulu": "Z",
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "niner": "9",
    "nine": "9",
}

# Digits are the common leetspeak substitutions; ambiguous ones (1, 9) follow
# the usual CTF reading, so 1337 becomes IEET rather than LEET.
LEET_TABLE = str.maketrans({
    "0": "o", "1": "i", "2": "z", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s",
})


def decode_base58(text):
    """Decode Bitcoin-style Base58 (the alphabet omits 0, O, I, and l)."""
    cleaned = "".join(text.split())
    if not cleaned:
        raise ValueError("Enter some Base58 first.")

    number = 0
    for character in cleaned:
        index = BASE58_ALPHABET.find(character)
        if index < 0:
            raise ValueError("That does not look like valid Base58.")
        number = number * 58 + index

    decoded = b""
    while number:
        number, remainder = divmod(number, 256)
        decoded = bytes([remainder]) + decoded

    padding = len(cleaned) - len(cleaned.lstrip("1"))
    return to_text(b"\x00" * padding + decoded)


def decode_nato(text):
    """Decode words spelled out with the NATO phonetic alphabet."""
    if not text.strip():
        raise ValueError("Enter some NATO alphabet words first.")

    normalized = text.lower().replace("x-ray", "xray")
    words = [
        word for word in re.split(r"[\s,;/|]+", normalized) if word
    ]
    if not words:
        raise ValueError("Enter some NATO alphabet words first.")

    decoded = []
    for word in words:
        if word not in NATO_ALPHABET:
            raise ValueError(f"{word!r} is not a NATO alphabet word.")
        decoded.append(NATO_ALPHABET[word])
    return "".join(decoded)


def decode_leetspeak(text):
    """Turn leetspeak digits and a few symbols back into letters."""
    if not text.strip():
        raise ValueError("Enter some leetspeak first.")
    if not re.search(r"[0-9@$]", text):
        raise ValueError("No leetspeak characters (digits, @ or $) found to decode.")
    return text.translate(LEET_TABLE)


def decode_decimal(text):
    """Decode space- or comma-separated decimal character codes."""
    stripped = text.strip()
    if not stripped:
        raise ValueError("Enter some decimal character codes first.")
    if re.search(r"[^0-9\s,;./|+\-]", stripped):
        raise ValueError("Decimal decoding accepts numbers 0-255 separated by spaces or commas.")

    tokens = re.findall(r"\d+", stripped)
    if len(tokens) < 2:
        raise ValueError("Enter at least two decimal character codes separated by spaces.")
    if any(int(token) > 255 for token in tokens):
        raise ValueError("Decimal character codes must be between 0 and 255.")
    return to_text(bytes(int(token) for token in tokens))


def decode_octal(text):
    """Decode octal character codes such as 124 150 145 (or \\150 style)."""
    stripped = text.replace("\\", " ").strip()
    if not stripped:
        raise ValueError("Enter some octal character codes first.")
    if re.search(r"[^0-7\s,;./|+\-]", stripped):
        raise ValueError("Octal decoding accepts digits 0-7 separated by spaces or commas.")

    tokens = [token for token in re.split(r"[\s,;./|+\-]+", stripped) if token]
    if len(tokens) < 2:
        raise ValueError("Enter at least two octal character codes separated by spaces.")
    if any(len(token) > 3 for token in tokens):
        raise ValueError("Octal character codes use at most three digits.")

    values = [int(token, 8) for token in tokens]
    if any(value > 255 for value in values):
        raise ValueError("Octal character codes must be between 0 and 377.")
    return to_text(bytes(values))


DECODERS = {
    "binary": decode_binary,
    "hex": decode_hex,
    "octal": decode_octal,
    "decimal": decode_decimal,
    "base32": decode_base32,
    "base58": decode_base58,
    "base64": decode_base64,
    "base85": decode_base85,
    "morse": decode_morse,
    "nato": decode_nato,
    "leetspeak": decode_leetspeak,
    "url": decode_url,
    "html": decode_html,
}


def main():
    parser = argparse.ArgumentParser(
        description="Decode binary, hex, octal, decimal, Base32/58/64/85, NATO, leetspeak, URL, HTML, or Morse."
    )
    parser.add_argument("encoding", choices=sorted(DECODERS), help="The input encoding")
    parser.add_argument("text", help="The encoded text")
    args = parser.parse_args()

    try:
        print(DECODERS[args.encoding](args.text))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
