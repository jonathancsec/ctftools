import base64

import pytest

from crypto.autodecode import autodecode
from crypto.classical import (
    atbash,
    decode_a1z26,
    decode_bacon,
    decrypt_affine,
    decrypt_columnar,
    decrypt_vigenere,
    encrypt_affine,
    encrypt_columnar,
    encrypt_vigenere,
    rot47,
)
from crypto.encodings import (
    decode_base32,
    decode_base85,
    decode_html,
    decode_url,
)


def bacon_encode(text):
    groups = []
    for character in text.upper():
        if "A" <= character <= "Z":
            bits = format(ord(character) - ord("A"), "05b")
            groups.append(bits.replace("0", "A").replace("1", "B"))
    return " ".join(groups)


def rail_encrypt(text, rails):
    pattern = []
    row = 0
    direction = 1
    for _ in text:
        pattern.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    rows = [""] * rails
    for character, row_index in zip(text, pattern):
        rows[row_index] += character
    return "".join(rows)


def top_text(ciphertext):
    result = autodecode(ciphertext)
    assert result
    return result[0]


def test_atbash_mirrors_letters_and_keeps_punctuation():
    assert atbash("Gsrh rh z gvhg!") == "This is a test!"


def test_rot47_rotates_printable_ascii_only():
    assert rot47("%96 BF:4< 3C@H? 7@I") == "The quick brown fox"


def test_bacon_decodes_five_symbol_groups():
    assert decode_bacon(bacon_encode("HELLO")) == "HELLO"
    assert decode_bacon("AABBA ABBAA ABBAB ABBAA") == "GMNM"


def test_a1z26_decodes_words_and_preserves_word_breaks():
    assert decode_a1z26("20 8 5 / 17 21 9 3 11") == "THE QUICK"
    with pytest.raises(ValueError):
        decode_a1z26("27 1")


def test_vigenere_round_trip_preserves_case_and_punctuation():
    ciphertext = encrypt_vigenere("Attack at dawn!", "LEMON")

    assert ciphertext == "Lxfopv ef rnhr!"
    assert decrypt_vigenere(ciphertext, "lemon") == "Attack at dawn!"
    with pytest.raises(ValueError):
        decrypt_vigenere("abc", "")


@pytest.mark.parametrize("key", ["zebra", "KEY", "ab"])
def test_columnar_round_trip_with_uneven_rows(key):
    plaintext = "The quick brown fox jumps over the lazy dog"

    ciphertext = encrypt_columnar(plaintext, key)

    assert decrypt_columnar(ciphertext, key) == plaintext
    assert ciphertext != plaintext


def test_columnar_round_trip_when_text_is_shorter_than_key():
    plaintext = "abc"
    ciphertext = encrypt_columnar(plaintext, "ZEBRA")

    assert ciphertext == "cba"
    assert decrypt_columnar(ciphertext, "ZEBRA") == plaintext


def test_columnar_rejects_non_alphabetic_key():
    with pytest.raises(ValueError):
        decrypt_columnar("abc", "key 2")


def test_affine_round_trip_and_invalid_multiplier():
    ciphertext = encrypt_affine("Attack at dawn", 5, 8)

    assert ciphertext == "Izzisg iz xiov"
    assert decrypt_affine(ciphertext, 5, 8) == "Attack at dawn"
    with pytest.raises(ValueError):
        decrypt_affine("abc", 2, 3)


def test_base32_and_base85_decoding():
    assert decode_base32(base64.b32encode(b"Hello world").decode()) == "Hello world"
    assert decode_base85(base64.b85encode(b"Hello world").decode()) == "Hello world"
    assert decode_base85(base64.a85encode(b"Hello world").decode()) == "Hello world"
    assert decode_base85("<~" + base64.a85encode(b"Hello world").decode() + "~>") == "Hello world"


def test_url_and_html_entity_decoding():
    assert decode_url("flag%7Bhello%20world%7D") == "flag{hello world}"
    assert decode_html("flag&#123;hello&nbsp;world&#125;") == "flag{hello world}"


CASES = [
    ("Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj", "The quick brown fox jumps over the lazy dog"),
    ("Gsrh rh z gvhg", "This is a test"),
    ("%96 BF:4< 3C@H? 7@I", "The quick brown fox"),
    ("VGhlIHF1aWNrIGJyb3duIGZveA==", "The quick brown fox"),
    (base64.b32encode(b"The quick brown fox").decode(), "The quick brown fox"),
    (base64.b85encode(b"The quick brown fox").decode(), "The quick brown fox"),
    (b"The quick brown fox".hex(), "The quick brown fox"),
    (" ".join(format(byte, "08b") for byte in b"The quick brown fox"), "The quick brown fox"),
    (".... . .-.. .-.. --- / .-- --- .-. .-.. -..", "HELLO WORLD"),
    ("20 8 5 / 17 21 9 3 11", "THE QUICK"),
    (bacon_encode("THE QUICK BROWN FOX"), "THEQUICKBROWNFOX"),
    (rail_encrypt("The quick brown fox jumps over the lazy dog", 4), "The quick brown fox jumps over the lazy dog"),
    ("LXFOPVEFRNHR", "ATTACKATDAWN"),
]


@pytest.mark.parametrize(("ciphertext", "plaintext"), CASES)
def test_auto_decode_ranks_the_correct_answer_first(ciphertext, plaintext):
    result = top_text(ciphertext)

    assert result["text"].strip().upper() == plaintext.upper()
    assert result["method"]
    assert isinstance(result["score"], float)


def test_auto_decode_admits_when_plaintext_is_already_readable():
    result = top_text("The quick brown fox jumps over the lazy dog")

    assert result["method"] == "No change"
    assert result["text"] == "The quick brown fox jumps over the lazy dog"


def test_auto_decode_cracks_longer_vigenere():
    plaintext = (
        "The quick brown fox jumps over the lazy dog and then runs into the "
        "forest where nobody can find him"
    )
    ciphertext = encrypt_vigenere(plaintext, "lemon")

    result = top_text(ciphertext)

    assert result["text"] == plaintext
    assert "LEMON" in result["method"]


def test_auto_decode_rejects_empty_and_oversized_input():
    with pytest.raises(ValueError):
        autodecode("   ")
    with pytest.raises(ValueError):
        autodecode("A" * 5_001)
