import argparse


def shift_text(text, shift):
    letters = "abcdefghijklmnopqrstuvwxyz"
    output = []
    for character in text:
        if character.isupper() and character.lower() in letters:
            index = letters.index(character.lower())
            output.append(letters[(index + shift) % 26].upper())
        elif character in letters:
            index = letters.index(character)
            output.append(letters[(index + shift) % 26])
        else:
            output.append(character)
    return "".join(output)


def decrypt(ciphertext, shift):
    return shift_text(ciphertext, -shift)


def decrypt_all(ciphertext):
    return [decrypt(ciphertext, shift) for shift in range(26)]


def main():
    parser = argparse.ArgumentParser(description="Shift text through the Caesar alphabet.")
    parser.add_argument("text", help="The text to shift")
    parser.add_argument("shift", type=int, help="The number of positions to shift")
    args = parser.parse_args()
    print(shift_text(args.text, args.shift))


if __name__ == "__main__":
    main()
