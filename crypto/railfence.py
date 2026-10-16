import argparse


def decrypt(ciphertext, rails):
	if rails < 1:
		raise ValueError("The number of rails must be at least 1.")

	if rails == 1 or rails >= len(ciphertext):
		return ciphertext

	row_pattern = []
	row = 0
	direction = 1
	for _ in ciphertext:
		row_pattern.append(row)
		if row == 0:
			direction = 1
		elif row == rails - 1:
			direction = -1
		row += direction

	row_lengths = [row_pattern.count(index) for index in range(rails)]
	rail_chars = []
	offset = 0
	for length in row_lengths:
		rail_chars.append(iter(ciphertext[offset:offset + length]))
		offset += length

	return "".join(next(rail_chars[index]) for index in row_pattern)


def main():
	parser = argparse.ArgumentParser(description="Decode a rail-fence cipher.")
	parser.add_argument("ciphertext", help="The encrypted text")
	parser.add_argument("rails", type=int, help="The number of rails used")
	args = parser.parse_args()

	try:
		print(decrypt(args.ciphertext, args.rails))
	except ValueError as error:
		parser.error(str(error))


if __name__ == "__main__":
	main()
