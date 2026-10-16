import sys; args = sys.argv[1:]
lst = ['a','b','c','d','e','f','g','h','i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
letters = "abcdefghijklmnopqrstuvwxyz"
enc = str(args[0])
shift = int(args[1])
out = ""
for chr in enc:
    if chr in letters.upper():
        out += letters[((letters.upper().index(chr)+shift)%26)].upper()
    elif chr in letters:
        out += letters[((letters.index(chr)+shift)%26)]
    else:
        out += chr

print(out)
