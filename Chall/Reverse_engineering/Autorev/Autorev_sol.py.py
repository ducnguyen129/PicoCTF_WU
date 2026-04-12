from pwn import *
import re

def solve_autorev():
    # Connect to the remote challenge server
    print("[*] Connecting to target...")
    target = remote('mysterious-sea.picoctf.net', 64061)

    # The challenge requires us to beat 20 binaries back-to-back
    for level in range(1, 21):
        print(f"\n--- Solving Level {level}/20 ---")
        
        # Read the console output until the hex dump is printed
        target.recvuntil(b"Here's the next binary in bytes:\n")
        
        # Grab the giant hex string
        hex_data = target.recvline().decode('utf-8').strip()
        
        # Search the hex for the exact assembly instruction:
        # mov DWORD PTR [rbp-0x4], <4-byte secret>
        # Opcode: c7 45 fc <8 hex characters>
        match = re.search(r'c745fc([0-9a-f]{8})', hex_data)
        
        if match:
            raw_hex = match.group(1)
            
            # Convert the extracted little-endian hex into a standard integer
            secret_bytes = bytes.fromhex(raw_hex)
            secret_int = int.from_bytes(secret_bytes, byteorder='little')
            
            print(f"[+] Extracted Hex: {raw_hex} -> Decimal: {secret_int}")
            
            # Wait for the input prompt and fire the answer back immediately
            target.recvuntil(b"What's the secret?:")
            target.sendline(str(secret_int).encode())
            
            # Read the success message
            success_msg = target.recvline().decode('utf-8').strip()
            print(f"[+] Server Response: {success_msg}")
            
        else:
            print("[-] Error: Could not find the assembly signature in this binary!")
            break

    # After looping 20 times, the server should drop the flag
    print("\n[*] Challenge complete! Fetching flag...")
    target.interactive()

if __name__ == "__main__":
    solve_autorev()