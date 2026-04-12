def decrypt():
    cipher_hex = "235a201d70201548251358110c552f135409"
    ciphertext = bytes.fromhex(cipher_hex)
    key = b"S3Cr3t"
    
    flag = ""
    for i in range(len(ciphertext)):
        flag += chr(ciphertext[i] ^ key[i % len(key)])
        
    print(f"Decrypted: {flag}")

if __name__ == "__main__":
    decrypt()