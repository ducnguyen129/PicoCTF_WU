data = bytearray()
hash_byte = [0xC3, 0xFF, 0xC8, 0xC2, 0x92, 0x9B, 0x8B, 0xC0, 0x80, 0xC2, 0xC4, 0x8B]
for i in range(len(hash_byte)):
    data.append(hash_byte[i]^0xAA)
index = 5381
hash = ""
for i in range(len(data)):
    index=(33 * index + data[i])&0xFFFFFFFFFFFFFFFF
    hash+=index
print(f"Your hash: {hash}")