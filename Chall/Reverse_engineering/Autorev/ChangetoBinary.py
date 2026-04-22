with open("secret.txt", "r") as handle:
    data = handle.read().strip()
hex_byte = bytes.fromhex(data)
with open("Chall", "wb+") as chall:
    chall.write(hex_byte)

