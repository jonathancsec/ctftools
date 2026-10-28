"""Rank plausible decodings of an unknown cipher or encoding.

The heuristic is deliberately simple: run every keyless or brute-forceable
decoder, score each result by how much it looks like English, then return the
best candidates. Keyed ciphers still need their key; for Vigenère we try to
recover it from letter frequencies.
"""

import binascii
import re
from collections import Counter

from .caesarshift import decrypt as decrypt_caesar
from .classical import (
    LETTERS,
    atbash,
    decode_a1z26,
    decode_bacon,
    decode_polybius,
    decrypt_affine,
    decrypt_beaufort,
    decrypt_vigenere,
    rot47,
)
from .railfence import decrypt as decrypt_railfence
from .encodings import (
    decode_base32,
    decode_base58,
    decode_base64,
    decode_base85,
    decode_binary,
    decode_decimal,
    decode_hex,
    decode_html,
    decode_leetspeak,
    decode_morse,
    decode_nato,
    decode_octal,
    decode_url,
)

MAX_INPUT = 5_000
MAX_RESULTS = 15
AFFINE_MULTIPLIERS = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)

ENGLISH_FREQ = (
    ("a", 8.167), ("b", 1.492), ("c", 2.782), ("d", 4.253), ("e", 12.702),
    ("f", 2.228), ("g", 2.015), ("h", 6.094), ("i", 6.966), ("j", 0.153),
    ("k", 0.772), ("l", 4.025), ("m", 2.406), ("n", 6.749), ("o", 7.507),
    ("p", 1.929), ("q", 0.095), ("r", 5.987), ("s", 6.327), ("t", 9.056),
    ("u", 2.758), ("v", 0.978), ("w", 2.360), ("x", 0.150), ("y", 1.974),
    ("z", 0.074),
)
FREQ_PERCENT = [percent for _letter, percent in ENGLISH_FREQ]
COMMON_BIGRAMS = (
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti",
    "es", "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to",
    "nt", "ng", "se", "ha", "as", "ou", "io", "le", "ve", "co", "me",
    "de", "hi", "ri", "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch",
    "ll", "be", "ma", "si", "om", "ur", "ca", "el", "ta", "la", "ns",
)
COMMON_KEYS = (
    "lemon", "key", "secret", "cipher", "crypto", "flag", "ctf",
    "password", "attack", "abc", "test",
)
READABLE_PUNCTUATION = set(" \t\r\n.,;:!?'\"()[]{}<>-_/@#$%^&*+=|\\~")
COMMON_WORDS = {
    "about", "after", "again", "all", "also", "and", "any", "are", "attack",
    "back", "because", "been", "before", "brown", "but", "can", "cipher",
    "could", "ctf", "dawn", "day", "did", "do", "dog", "down", "each",
    "even", "find", "first", "flag", "for", "fox", "from", "get", "give",
    "good", "great", "had", "has", "have", "he", "hello", "her", "here",
    "him", "his", "how", "if", "in", "into", "is", "it", "its", "jumps",
    "just", "key", "know", "lazy", "like", "look", "made", "make", "many",
    "me", "more", "most", "my", "new", "no", "not", "now", "of", "on",
    "one", "only", "or", "other", "our", "out", "over", "people", "quick",
    "said", "say", "secret", "see", "she", "should", "so", "some", "take",
    "test", "than", "that", "the", "their", "them", "then", "there", "these",
    "they", "think", "this", "time", "to", "two", "up", "us", "use", "very",
    "want", "was", "way", "we", "well", "were", "what", "when", "which",
    "who", "will", "with", "work", "world", "would", "you", "your",
}
COMMON_WORD_PATTERN = re.compile(
    r"|".join(sorted((word for word in COMMON_WORDS if len(word) >= 4), key=len, reverse=True))
)


def english_score(text):
    """Score text by letter frequency and common English words."""
    if not text:
        return -1_000.0

    lower = text.lower()
    letters = [character for character in lower if "a" <= character <= "z"]
    if not letters:
        return -100.0

    count = len(letters)
    counts = Counter(letters)
    chi_square = 0.0
    for letter, percent in ENGLISH_FREQ:
        expected = count * percent / 100
        chi_square += (counts.get(letter, 0) - expected) ** 2 / expected

    # Short texts have noisy frequency counts, so damp the chi-square penalty.
    score = 40.0 - (chi_square / count) * min(1.0, count / 30.0)
    words = re.findall(r"[a-z]{2,}", lower)
    score += 4.0 * sum(1 for word in words if word in COMMON_WORDS)
    score -= 1.5 * sum(
        1 for word in words if len(word) >= 3 and word not in COMMON_WORDS
    )

    # Unspaced plaintext such as ATTACKATDAWN still contains recognizable
    # vocabulary, while random letter soup from a wrong cipher does not.
    present_words = set(COMMON_WORD_PATTERN.findall(lower))
    score += 1.5 * min(10, len(present_words))

    if count > 1:
        bigram_hits = sum(lower.count(bigram) for bigram in COMMON_BIGRAMS)
        score += 6.0 * bigram_hits / (count - 1)

    if re.search(r"flag\{[^}]*\}", lower):
        score += 25.0
    if "ctf" in lower:
        score += 5.0

    readable = sum(
        1 for character in text
        if character.isalnum() or character.isspace() or character in READABLE_PUNCTUATION
    )
    score += 4.0 * readable / len(text)

    suspicious = sum(
        1 for character in text
        if not (character.isalnum() or character.isspace() or character in READABLE_PUNCTUATION)
    )
    score -= 30.0 * suspicious / len(text)
    return score


def _try_decode(method, function, *args):
    try:
        return function(*args)
    except (ValueError, TypeError, UnicodeError, binascii.Error):
        return None


def _vigenere_shift_chi(column, shift):
    count = len(column)
    counts = Counter((ord(character) - 97 - shift) % 26 for character in column)
    return sum(
        (counts.get(index, 0) - count * percent / 100) ** 2 / (count * percent / 100)
        for index, percent in enumerate(FREQ_PERCENT)
    )


def _beaufort_shift_chi(column, shift):
    # Beaufort is P = K - C, so guessing a key letter maps C to (K - C).
    count = len(column)
    counts = Counter((shift - (ord(character) - 97)) % 26 for character in column)
    return sum(
        (counts.get(index, 0) - count * percent / 100) ** 2 / (count * percent / 100)
        for index, percent in enumerate(FREQ_PERCENT)
    )


def _add_encoding_candidates(add, text):
    cleaned = "".join(text.split())

    if (
        len(cleaned) >= 8
        and re.fullmatch(r"[A-Za-z0-9+/=_-]+", cleaned)
        and (
            any(character in cleaned for character in "+/=-_")
            or (len(cleaned) % 4 == 0 and len(cleaned) >= 16)
        )
    ):
        decoded = _try_decode("Base64", decode_base64, text)
        if decoded is not None:
            add("Base64", decoded)

    if (
        len(cleaned) >= 8
        and re.fullmatch(r"[A-Z2-7=]+", cleaned.upper())
        and (cleaned.endswith("=") or len(cleaned) % 8 == 0 or len(cleaned) >= 16)
    ):
        decoded = _try_decode("Base32", decode_base32, text)
        if decoded is not None:
            add("Base32", decoded)

    if len(cleaned) >= 6 and re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0:
        decoded = _try_decode("Hex", decode_hex, text)
        if decoded is not None:
            add("Hex", decoded)

    if (
        len(cleaned) >= 8
        and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", cleaned)
        and any(character.isdigit() for character in cleaned)
        and any(character.isalpha() for character in cleaned)
    ):
        decoded = _try_decode("Base58", decode_base58, text)
        if decoded is not None:
            add("Base58", decoded)

    if re.fullmatch(r"[01\s]+", text) and len(re.sub(r"\s", "", text)) >= 8:
        decoded = _try_decode("Binary", decode_binary, text)
        if decoded is not None:
            add("Binary", decoded)

    number_tokens = re.findall(r"\d+", text)
    numeric_input = (
        len(number_tokens) >= 2
        and not re.search(r"[^0-9\s,;./|+\-]", text.strip())
    )

    if (
        numeric_input
        and all(len(token) <= 3 and int(token) <= 255 for token in number_tokens)
    ):
        decoded = _try_decode("Decimal ASCII", decode_decimal, text)
        if decoded is not None:
            add("Decimal ASCII", decoded)

    if (
        numeric_input
        and all(len(token) <= 3 and token[0] in "01234567" for token in number_tokens)
        and max(int(token) for token in number_tokens) > 9
    ):
        decoded = _try_decode("Octal ASCII", decode_octal, text.replace("\\", " "))
        if decoded is not None:
            add("Octal ASCII", decoded)

    if re.fullmatch(r"[.\-·•–—_/\s]+", text) and any(character in ".-·•–—" for character in text):
        decoded = _try_decode("Morse", decode_morse, text)
        if decoded is not None:
            add("Morse", decoded)

    if (
        len(cleaned) >= 8
        and (
            cleaned.startswith("<~")
            or re.search(r"[!#$%&()*;<=>?@^_`{|}~]", cleaned)
        )
    ):
        decoded = _try_decode("Base85", decode_base85, text)
        if decoded is not None:
            add("Base85", decoded)

    if re.search(r"%[0-9A-Fa-f]{2}", text):
        decoded = _try_decode("URL encoding", decode_url, text)
        if decoded is not None:
            add("URL encoding", decoded)

    if re.search(r"&(?:#\d+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);", text):
        decoded = _try_decode("HTML entities", decode_html, text)
        if decoded is not None:
            add("HTML entities", decoded)

    if re.fullmatch(r"[0-9\s,;./|+\-]+", text.strip()):
        tokens = re.findall(r"\d+", text)
        if (
            len(tokens) >= 2
            and all(1 <= int(token) <= 26 for token in tokens)
            and re.search(r"\d\s*[\s,;./|+\-]\s*\d", text)
        ):
            decoded = _try_decode("A1Z26", decode_a1z26, text)
            if decoded is not None:
                add("A1Z26", decoded)

    normalized = text.upper().replace("0", "A").replace("1", "B")
    bacon_text = "".join(
        character
        for character in normalized
        if not character.isspace() and character not in ",;:-_/|."
    )
    if (
        len(bacon_text) >= 5
        and len(bacon_text) % 5 == 0
        and set(bacon_text) <= {"A", "B"}
    ):
        decoded = _try_decode("Bacon", decode_bacon, text)
        if decoded is not None:
            add("Bacon", decoded)

    if re.fullmatch(r"[1-5\s,;./|+\-]+", text.strip()):
        digits = re.findall(r"[1-5]", text)
        if len(digits) >= 4 and len(digits) % 2 == 0:
            decoded = _try_decode("Polybius square", decode_polybius, text)
            if decoded is not None:
                add("Polybius square", decoded)

    if re.search(r"[A-Za-z]", text) and re.search(r"[0-9@$]", text):
        decoded = _try_decode("Leetspeak", decode_leetspeak, text)
        if decoded is not None and decoded != text:
            add("Leetspeak", decoded)

    if re.fullmatch(r"[A-Za-z ,;/|\-]+", text.strip()) and len(text.split()) >= 2:
        decoded = _try_decode("NATO alphabet", decode_nato, text)
        if decoded is not None and decoded != text:
            add("NATO alphabet", decoded)


def _add_classical_candidates(add, text):
    for shift in range(1, 26):
        add(f"Caesar (shift {shift})", decrypt_caesar(text, shift))

    add("Atbash", atbash(text))
    add("ROT47", rot47(text))

    for rails in range(2, min(10, len(text) - 1) + 1):
        decoded = _try_decode("Rail fence", decrypt_railfence, text, rails)
        if decoded is not None and decoded != text:
            add(f"Rail fence ({rails} rails)", decoded)

    for multiplier in AFFINE_MULTIPLIERS:
        for offset in range(26):
            if multiplier == 1 and offset == 0:
                continue
            decoded = _try_decode("Affine", decrypt_affine, text, multiplier, offset)
            if decoded is not None:
                add(f"Affine (a={multiplier}, b={offset})", decoded)


def _add_vigenere_crack(add, text):
    letters = [
        character.lower()
        for character in text
        if "a" <= character <= "z" or "A" <= character <= "Z"
    ]
    if len(letters) < 12:
        return

    # Common keys catch short textbook examples where frequency analysis has
    # too little material to recover the key reliably.
    for key in COMMON_KEYS:
        add(
            f"Vigenère (key: {key.upper()})",
            decrypt_vigenere(text, key),
        )

    max_key_length = min(12, len(letters) // 2)
    for key_length in range(1, max_key_length + 1):
        key = []
        for position in range(key_length):
            column = letters[position::key_length]
            best_shift = min(
                range(26),
                key=lambda shift: _vigenere_shift_chi(column, shift),
            )
            key.append(LETTERS[best_shift])

        key_text = "".join(key)
        decoded = decrypt_vigenere(text, key_text)
        if decoded != text:
            add(f"Vigenère crack (key: {key_text.upper()})", decoded)


def _add_beaufort_crack(add, text):
    letters = [
        character.lower()
        for character in text
        if "a" <= character <= "z" or "A" <= character <= "Z"
    ]
    if len(letters) < 12:
        return

    for key in COMMON_KEYS:
        add(f"Beaufort (key: {key.upper()})", decrypt_beaufort(text, key))

    max_key_length = min(12, len(letters) // 2)
    for key_length in range(1, max_key_length + 1):
        key = []
        for position in range(key_length):
            column = letters[position::key_length]
            best_shift = min(
                range(26),
                key=lambda shift: _beaufort_shift_chi(column, shift),
            )
            key.append(LETTERS[best_shift])

        key_text = "".join(key)
        decoded = decrypt_beaufort(text, key_text)
        if decoded != text:
            add(f"Beaufort crack (key: {key_text.upper()})", decoded)


def autodecode(text):
    """Return ranked candidate decodings for an unknown cipher text."""
    if not isinstance(text, str):
        raise ValueError("Text must be a string.")
    if not text.strip():
        raise ValueError("Enter some cipher text or encoded text first.")
    if len(text) > MAX_INPUT:
        raise ValueError(f"Auto-decode accepts at most {MAX_INPUT:,} characters at a time.")

    results = []
    seen = set()

    def add(method, candidate):
        if not isinstance(candidate, str) or not candidate.strip():
            return
        key = candidate.strip()
        if key in seen:
            return
        seen.add(key)
        results.append({
            "method": method,
            "text": candidate,
            "score": round(english_score(candidate[:4_000]), 2),
        })

    add("No change", text)
    _add_encoding_candidates(add, text)
    _add_classical_candidates(add, text)
    _add_vigenere_crack(add, text)
    _add_beaufort_crack(add, text)

    results.sort(key=lambda item: item["score"], reverse=True)
    return results[:MAX_RESULTS]
