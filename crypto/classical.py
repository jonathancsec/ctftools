"""Classical cipher decoders used by the cryptography page and auto-decoder."""

import math
import re

LETTERS = "abcdefghijklmnopqrstuvwxyz"
ATBASH_TABLE = str.maketrans(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA",
)
BACON_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
# The 5x5 Polybius square merges I and J, so it has 25 cells.
POLYBIUS_SQUARE = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


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


def _polybius_square(key=""):
    """Build a keyed 5x5 square: unique key letters first, then the rest."""
    cells = []
    for character in key.upper():
        if "A" <= character <= "Z":
            character = "I" if character == "J" else character
            if character not in cells:
                cells.append(character)
    for character in POLYBIUS_SQUARE:
        if character not in cells:
            cells.append(character)
    return "".join(cells)


def _cell_position(square, letter):
    letter = "I" if letter == "J" else letter
    index = square.index(letter)
    return divmod(index, 5)


def decode_polybius(text):
    """Decode Polybius square coordinates: pairs of digits from 1 to 5."""
    stripped = text.strip()
    if not stripped:
        raise ValueError("Enter some Polybius coordinates first.")
    if re.search(r"[^0-9\s,;./|+\-]", stripped):
        raise ValueError("Polybius decoding accepts digits 1-5 separated by spaces, commas, or dashes.")

    words = []
    for group in re.split(r"\s*[/|]\s*", stripped):
        digits = re.findall(r"\d", group)
        if not digits:
            continue
        if len(digits) % 2:
            raise ValueError(f"Polybius coordinates come in pairs (got {len(digits)} digits).")
        if any(digit not in "12345" for digit in digits):
            raise ValueError("Polybius coordinates must be digits from 1 to 5.")
        words.append(
            "".join(
                POLYBIUS_SQUARE[(int(digits[index]) - 1) * 5 + int(digits[index + 1]) - 1]
                for index in range(0, len(digits), 2)
            )
        )

    if not words:
        raise ValueError("Enter some Polybius coordinates first.")
    return " ".join(words)


def decrypt_beaufort(text, key):
    """Beaufort decryption (C = K - P), preserving case and punctuation."""
    key_letters = _usable_key(key)
    output = []
    key_index = 0
    for character in text:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            shift = ord(key_letters[key_index % len(key_letters)]) - ord("a")
            output.append(chr((shift - (ord(character) - base)) % 26 + base))
            key_index += 1
        else:
            output.append(character)
    return "".join(output)


def encrypt_beaufort(text, key):
    """Beaufort is reciprocal, so encryption is decryption."""
    return decrypt_beaufort(text, key)


def _rebuild_with_punctuation(original, letters):
    """Put decoded letters back where the original letters were."""
    decoded = iter(letters)
    return "".join(
        next(decoded) if character.isalpha() else character
        for character in original
    )


def decrypt_bifid(text, key, period=5):
    """Decrypt a Bifid cipher using a keyed 5x5 square and a block period."""
    if isinstance(period, bool) or not isinstance(period, int) or period < 1:
        raise ValueError("The Bifid period must be a positive whole number.")

    square = _polybius_square(_usable_key(key))
    letters = ["I" if character.upper() == "J" else character.upper()
               for character in text if character.isalpha()]

    plain = []
    for start in range(0, len(letters), period):
        block = letters[start:start + period]
        # The ciphertext block is the coordinate stream split back into pairs,
        # so putting the digits in one row lets us read rows then columns.
        digits = []
        for letter in block:
            row, column = _cell_position(square, letter)
            digits.extend((row, column))
        size = len(block)
        plain.extend(
            square[digits[index] * 5 + digits[size + index]]
            for index in range(size)
        )

    return _rebuild_with_punctuation(text, plain)


def encrypt_bifid(text, key, period=5):
    """Bifid encryption, used by tests to check the decoder."""
    if isinstance(period, bool) or not isinstance(period, int) or period < 1:
        raise ValueError("The Bifid period must be a positive whole number.")

    square = _polybius_square(_usable_key(key))
    letters = ["I" if character.upper() == "J" else character.upper()
               for character in text if character.isalpha()]

    cipher = []
    for start in range(0, len(letters), period):
        block = letters[start:start + period]
        rows_columns = [_cell_position(square, letter) for letter in block]
        flat = [row for row, _column in rows_columns] + [column for _row, column in rows_columns]
        cipher.extend(
            square[flat[index] * 5 + flat[index + 1]]
            for index in range(0, len(flat), 2)
        )

    return _rebuild_with_punctuation(text, cipher)


def _playfair_pairs(letters, filler="X"):
    """Split letters into Playfair digraphs, inserting fillers when needed."""
    pairs = []
    index = 0
    while index < len(letters):
        first = letters[index]
        if index + 1 >= len(letters):
            pairs.append((first, filler))
            break
        second = letters[index + 1]
        if first == second:
            pairs.append((first, filler))
            index += 1
        else:
            pairs.append((first, second))
            index += 2
    return pairs


def decrypt_playfair(text, key):
    """Decrypt Playfair digraphs, keeping punctuation in place and X padding."""
    square = _polybius_square(_usable_key(key))
    letters = ["I" if character.upper() == "J" else character.upper()
               for character in text if character.isalpha()]
    if len(letters) % 2:
        raise ValueError(f"Playfair ciphertext needs an even number of letters (got {len(letters)}).")

    plain = []
    for index in range(0, len(letters), 2):
        (row1, column1) = _cell_position(square, letters[index])
        (row2, column2) = _cell_position(square, letters[index + 1])
        if row1 == row2:
            plain.append(square[row1 * 5 + (column1 - 1) % 5])
            plain.append(square[row2 * 5 + (column2 - 1) % 5])
        elif column1 == column2:
            plain.append(square[((row1 - 1) % 5) * 5 + column1])
            plain.append(square[((row2 - 1) % 5) * 5 + column2])
        else:
            plain.append(square[row1 * 5 + column2])
            plain.append(square[row2 * 5 + column1])

    return _rebuild_with_punctuation(text, plain)


def encrypt_playfair(text, key):
    """Playfair encryption, used by tests and sample ciphertext."""
    square = _polybius_square(_usable_key(key))
    letters = ["I" if character.upper() == "J" else character.upper()
               for character in text if character.isalpha()]

    cipher = []
    for first, second in _playfair_pairs(letters):
        (row1, column1) = _cell_position(square, first)
        (row2, column2) = _cell_position(square, second)
        if row1 == row2:
            cipher.append(square[row1 * 5 + (column1 + 1) % 5])
            cipher.append(square[row2 * 5 + (column2 + 1) % 5])
        elif column1 == column2:
            cipher.append(square[((row1 + 1) % 5) * 5 + column1])
            cipher.append(square[((row2 + 1) % 5) * 5 + column2])
        else:
            cipher.append(square[row1 * 5 + column2])
            cipher.append(square[row2 * 5 + column1])

    # Padding adds filler letters, so there is no one-to-one position mapping.
    return "".join(cipher)


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
