import binascii

cipher = bytes.fromhex("235a201d702015483b1d412b265d3313501f0c072d135f0d2002302d06476350224507462e")

for k in range(256):
    decoded = bytes([b ^ k for b in cipher])
    if all(32 <= c < 127 for c in decoded):
        print(k, decoded)
