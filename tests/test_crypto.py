import base64

import pytest

from crypto.autodecode import autodecode
from crypto.classical import (
    atbash,
    decode_a1z26,
    decode_bacon,
    decode_polybius,
    decrypt_affine,
    decrypt_beaufort,
    decrypt_bifid,
    decrypt_columnar,
    decrypt_playfair,
    decrypt_vigenere,
    encrypt_affine,
    encrypt_beaufort,
    encrypt_bifid,
    encrypt_columnar,
    encrypt_playfair,
    encrypt_vigenere,
    rot47,
)
from crypto.encodings import (
    decode_base32,
    decode_base58,
    decode_base85,
    decode_decimal,
    decode_html,
    decode_leetspeak,
    decode_nato,
    decode_octal,
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


def test_polybius_decodes_coordinate_pairs():
    assert decode_polybius("23 15 31 31 34 / 52 34 42 31 14") == "HELLO WORLD"
    assert decode_polybius("2311") == "HA"
    with pytest.raises(ValueError):
        decode_polybius("16 23")
    with pytest.raises(ValueError):
        decode_polybius("23 15 3")


def test_beaufort_round_trip_preserves_case_and_punctuation():
    ciphertext = encrypt_beaufort("Attack at dawn!", "fortification")

    assert ciphertext == "Fvytgv ij xtmb!"
    assert decrypt_beaufort(ciphertext, "FORTIFICATION") == "Attack at dawn!"


def test_bifid_round_trip_with_period():
    plaintext = "defend the east wall of the castle"

    ciphertext = encrypt_bifid(plaintext, "keyword", 5)

    assert ciphertext == "RFNRDC FEY DBTA TPHY ZZ KFD PCLVKU"
    assert decrypt_bifid(ciphertext, "keyword", 5) == plaintext.upper()
    assert encrypt_bifid(plaintext, "keyword", 20) != ciphertext
    with pytest.raises(ValueError):
        decrypt_bifid("abc", "keyword", 0)


def test_playfair_round_trip_with_filler_padding():
    ciphertext = encrypt_playfair("Hide the gold in the tree stump", "monarchy")

    assert ciphertext == "BFCKPDFIMPBKRQCFZDIUILLZOL"
    assert decrypt_playfair(ciphertext, "MONARCHY") == "HIDETHEGOLDINTHETREXESTUMP"
    with pytest.raises(ValueError):
        decrypt_playfair("abc", "monarchy")


def test_base58_decoding_uses_the_bitcoin_alphabet():
    assert decode_base58("JxF12TrwUP45BMd") == "Hello World"
    assert decode_base58("2NEpo7TZRRrLZSi2U") == "Hello World!"
    with pytest.raises(ValueError):
        decode_base58("0OIl")


def test_nato_leetspeak_decimal_and_octal_decoding():
    assert decode_nato("Tango Hotel Echo / Quebec Uniform India Charlie Kilo") == "THEQUICK"
    assert decode_leetspeak("7h3 qu1ck 8r0wn f0x") == "the quick brown fox"
    assert decode_decimal("84 104 101 32 113 117 105 99 107") == "The quick"
    assert decode_octal("124 150 145 40 161 165 151 143 153") == "The quick"
    with pytest.raises(ValueError):
        decode_nato("Tango Whisky Foxtrot")
    with pytest.raises(ValueError):
        decode_decimal("84 300")


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
    ("23 15 31 31 34 / 52 34 42 31 14", "HELLO WORLD"),
    ("JxF12TrwUP45BMd", "Hello World"),
    ("Tango Hotel Echo / Quebec Uniform India Charlie Kilo", "THEQUICK"),
    ("7h3 qu1ck 8r0wn f0x", "the quick brown fox"),
    (" ".join(str(byte) for byte in b"The quick brown fox"), "The quick brown fox"),
    (" ".join(format(byte, "o") for byte in b"The quick brown fox"), "The quick brown fox"),
    (
        encrypt_beaufort(
            "The quick brown fox jumps over the lazy dog and keeps running",
            "lemon",
        ),
        "The quick brown fox jumps over the lazy dog and keeps running",
    ),
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
