from cryptography.fernet import Fernet

# The 32-byte Base64 encoded key found in the extension
key = b"cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="

# The encrypted webhook URL
encrypted_webhook = b"gAAAAABmfRjwFKUB-X3GBBqaN1tZYcPg5oLJVJ5XQHFogEgcRSxSis1e4qwicAKohmjqaD-QG8DIN5ie3uijCVAe3xiYmoEHlxATWUP3DC97R00Cgkw4f3HZKsP5xHewOqVPH8ap9FbE"

# Initialize Fernet suite and decrypt
cipher = Fernet(key)
decrypted_url = cipher.decrypt(encrypted_webhook)

print(f"Decrypted Webhook: {decrypted_url.decode('utf-8')}")