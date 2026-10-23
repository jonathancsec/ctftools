"""Classical cipher decoders used by the cryptography page and auto-decoder."""

import math
import re

LETTERS = "abcdefghijklmnopqrstuvwxyz"
ATBASH_TABLE = str.maketrans(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA",
)
BACON_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def atbash(text):
    """Swap each letter with its mirror in the alphabet."""
    return text.translate(ATBASH_TABLE)


def rot47(text):
    """Rotate printable ASCII (33-126) by 47 positions."""
    output = []
    for character in text:
        code = ord(character)
        if 33 <= code <= 126:
            output.append(chr(33 + (code - 33 + 47) % 94))
        else:
            output.append(character)
    return "".join(output)


def decode_bacon(text):
    """Decode Bacon's cipher using five A/B (or 0/1) symbols per letter."""
    normalized = text.upper().replace("0", "A").replace("1", "B")
    cleaned = "".join(
        character
        for character in normalized
        if not character.isspace() and character not in ",;:-_/|."
    )
    if not cleaned:
        raise ValueError("Enter some Bacon cipher text first.")
    if any(character not in "AB" for character in cleaned):
        raise ValueError("Bacon decoding accepts groups of A/B (or 0/1) only.")
    if len(cleaned) % 5:
        raise ValueError(f"Bacon's cipher needs groups of five symbols (got {len(cleaned)}).")

    return "".join(
        BACON_ALPHABET[int(cleaned[index:index + 5].replace("A", "0").replace("B", "1"), 2)]
        for index in range(0, len(cleaned), 5)
    )


def decode_a1z26(text):
    """Turn numbers 1-26 into letters, with / or | separating words."""
    stripped = text.strip()
    if not stripped:
        raise ValueError("Enter some numbers first.")
    if re.search(r"[^0-9\s,;./|+\-]", stripped):
        raise ValueError("A1Z26 accepts numbers 1-26 separated by spaces, commas, or dashes.")

    words = []
    for group in re.split(r"\s*[/|]\s*", stripped):
        if not group.strip():
            continue
        numbers = [int(token) for token in re.findall(r"\d+", group)]
        if not numbers:
            continue
        if any(number < 1 or number > 26 for number in numbers):
            raise ValueError("A1Z26 numbers must be between 1 and 26.")
        words.append("".join(chr(64 + number) for number in numbers))

    if not words:
        raise ValueError("Enter some numbers first.")
    return " ".join(words)


def _usable_key(key):
    key_letters = "".join(character for character in key if character.isalpha())
    if not key_letters:
        raise ValueError("Enter an alphabetic key.")
    if len(key_letters) != len(key.strip()):
        raise ValueError("The key can only contain letters and spaces.")
    return key_letters.lower()


def encrypt_vigenere(text, key):
    """Vigenère encryption; kept here so the decoder can be tested in both directions."""
    key_letters = _usable_key(key)
    output = []
    key_index = 0
    for character in text:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            shift = ord(key_letters[key_index % len(key_letters)]) - ord("a")
            output.append(chr((ord(character) - base + shift) % 26 + base))
            key_index += 1
        else:
            output.append(character)
    return "".join(output)


def decrypt_vigenere(text, key):
    """Vigenère decryption, preserving case and non-letter characters."""
    key_letters = _usable_key(key)
    output = []
    key_index = 0
    for character in text:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            shift = ord(key_letters[key_index % len(key_letters)]) - ord("a")
            output.append(chr((ord(character) - base - shift) % 26 + base))
            key_index += 1
        else:
            output.append(character)
    return "".join(output)


def _column_order(key):
    if not key or not key.strip():
        raise ValueError("Enter a keyword for the column order.")
    if not key.isalpha():
        raise ValueError("The columnar key can only contain letters.")
    if len(key) > 64:
        raise ValueError("The columnar key must be 64 characters or fewer.")
    # Stable sorting keeps repeated letters in left-to-right order.
    return sorted(range(len(key)), key=lambda index: key[index].lower())


def decrypt_columnar(text, key):
    """Decrypt a columnar transposition written with an alphabetically ordered key."""
    order = _column_order(key)
    width = len(order)
    rows, remainder = divmod(len(text), width)
    if rows == 0 and remainder == 0:
        return text
    if remainder:
        rows += 1

    lengths = [
        rows if column < remainder else rows - 1
        for column in range(width)
    ] if remainder else [rows] * width

    columns = {}
    offset = 0
    for column in order:
        columns[column] = text[offset:offset + lengths[column]]
        offset += lengths[column]

    output = []
    for row in range(rows):
        for column in range(width):
            if row < lengths[column]:
                output.append(columns[column][row])
    return "".join(output)


def encrypt_columnar(text, key):
    """Columnar encryption, used by tests and the auto-decoder's fixtures."""
    order = _column_order(key)
    width = len(order)
    rows = math.ceil(len(text) / width) if text else 0
    return "".join(
        text[row * width + column]
        for column in order
        for row in range(rows)
        if row * width + column < len(text)
    )


def _mod_inverse(value):
    value %= 26
    for candidate in range(1, 26):
        if value * candidate % 26 == 1:
            return candidate
    raise ValueError("The affine multiplier has no inverse modulo 26.")


def decrypt_affine(text, multiplier, offset):
    """Decrypt E(x) = a*x + b (mod 26)."""
    multiplier %= 26
    offset %= 26
    inverse = _mod_inverse(multiplier)

    output = []
    for character in text:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            value = ord(character) - base
            output.append(chr((inverse * (value - offset)) % 26 + base))
        else:
            output.append(character)
    return "".join(output)


def encrypt_affine(text, multiplier, offset):
    """Affine encryption inverse, used by tests."""
    multiplier %= 26
    offset %= 26
    if math.gcd(multiplier, 26) != 1:
        raise ValueError("The affine multiplier must be coprime with 26.")

    output = []
    for character in text:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            output.append(chr((multiplier * (ord(character) - base) + offset) % 26 + base))
        else:
            output.append(character)
    return "".join(output)
