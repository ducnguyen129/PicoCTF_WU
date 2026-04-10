# Reverse engineering write up

## gatekeeper

* Input: số lớn hơn 999 bé hơn 9999
* Chuỗi nhập vào có thể là các chữ cái vì nó có hàm `atoi`(ascii to int)
* Enter random input to test and recive
```
}847ftc_oc_ipd936ftc_oc_ipb_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{FTCftc_oc_ipocipftc_oc_ip
```
From this output i can see that the string `ftc_oc_ip` looping so i just delete all the looping character and recieve the pure string

```shell
}847d936b_999_TG_xeh_tigid_3{FTCocip
```

* Reverse all the pure string and get the flag

```shell
}847   -> 748}
d936   -> 639d
b_99   -> 99_b
9_TG   -> GT_9
_xeh   -> hex_
_tig   -> git_
id_3   -> 3_di
{FTC   -> CTF{
ocip   -> pico
```

* Flag: `picoCTF{3_digit_hex_GT_999_b639d748}`

## hiddencipher 1

* When start execute the program, you will recived flag but encoded
![Encoded flag](../../PicoCTF_WU/img/Screenshot%202026-04-10%20123925.png)
* The encode flag is : `235a201d70201548251358110c552f135409`
* But i don't know how the encode flag printing so i use ida to decompiler the file `hidencipher`

* Thử XOR với đoạn text bên trên và được flag: `picoCTF{xor_unpack_4nalys1s_530ca742}`

## hidencipher 2

* First i connect to server and server give me a math problem(very easy to answer)
* Then you just answer the math problem and recieve the encoded flag

```c
int __fastcall encode_flag(__int64 a1, int a2)
{
  int i; // [rsp+1Ch] [rbp-4h]

  puts("Encoded flag values:");
  for ( i = 0; *(_BYTE *)(i + a1); ++i )
  {
    printf("%d", a2 * *(char *)(i + a1));
    if ( *(_BYTE *)(i + 1LL + a1) )
      printf(", ");
  }
  return putchar(10);
}
```
* Encode technique: using the number `a2` multiply with the character of the flag but you can guess it after recieve the encode flag

```python
Encodeflag = [
1680, 1575, 1485, 1665, 1005, 1260, 1050, 1845, 1635, 780, 1740, 1560, 1425, 1470, 765, 1560, 735, 1650, 1500, 1425, 1485, 735, 1680, 1560, 765, 1710, 1425, 780, 1455, 765, 1470, 750, 1485, 1485, 1530, 1875
]
```

* Try to divide the encoded flag to ascii number of every character with the prefix flag `picoCTF{` and its alway return 15

```txt
1680 / p (112) = 15

1575 / i (105) = 15

1485 / c (99) = 15

1665 / o (111) = 15

1005 / C (67) = 15

1260 / T (84) = 15

1050 / F (70) = 15

1845 / { (123) = 15
```
* Combine with the encode technique we discorvered we can see that the `a2` is 15 
* So what i need to do is divide all encoded number to 15 and then convert number to character according to the ascii table and recieve the flag

```python
data = [1680, 1575, 1485, 1665, 1005, 1260, 1050, 1845, 1635, 780, 1740, 1560, 1425, 1470, 765, 1560, 735, 1650, 1500, 1425, 1485, 735, 1680, 1560, 765, 1710, 1425, 780, 1455, 765, 1470, 750, 1485, 1485, 1530, 1875] # Replace your nums list here
text = ""
for num in data:
  char = num // 15 # Divide 15 to get the ascii number
  text += chr(char)
print(f"Flag is : {text}") # Flag
```

* flag : `picoCTF{m4th_b3h1nd_c1ph3r_4a3b2ccf}`

## The Add/On Trap

* First when i dowloaded the file it have suffix `.xpi` file so i change it to the suffix `.zip` file and compress it
* After compress the file, i recieve a folder and wwhen open that folder i see the `main.js`
* In this `main.js` files it have this encode string
```js
console.log(`Information to exfiltrate: ${details.url}`);
    const key="cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
    const webhookUrl='gAAAAABmfRjwFKUB-X3GBBqaN1tZYcPg5oLJVJ5XQHFogEgcRSxSis1e4qwicAKohmjqaD-QG8DIN5ie3uijCVAe3xiYmoEHlxATWUP3DC97R00Cgkw4f3HZKsP5xHewOqVPH8ap9FbE'
    const payload = {
        content: `${details.url}`
        ...
    }
    ...
```

* The key is encoded by `base64` and the `webhookUrl` is `Fernet`
* SO i using python and decode the webbookurl by the Fernet in cryptographic lib, run this file and recieve the flag

```python
from cryptography.fernet import Fernet

# The 32-byte Base64 encoded key found in the extension
key = b"cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="

# The encrypted webhook URL
encrypted_webhook = b"gAAAAABmfRjwFKUB-X3GBBqaN1tZYcPg5oLJVJ5XQHFogEgcRSxSis1e4qwicAKohmjqaD-QG8DIN5ie3uijCVAe3xiYmoEHlxATWUP3DC97R00Cgkw4f3HZKsP5xHewOqVPH8ap9FbE"

# Initialize Fernet suite and decrypt
cipher = Fernet(key)
decrypted_url = cipher.decrypt(encrypted_webhook)

print(f"Decrypted Webhook: {decrypted_url.decode('utf-8')}")
```

flag : `picoCTF{Us3_4dd/0ns_v3ry_c4r3fully1}`

## Auto Rev
