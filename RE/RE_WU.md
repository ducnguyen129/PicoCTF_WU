# Reverse engineering write up

## gatekeeper

* Input: số lớn hơn 999 bé hơn 9999
* Chuỗi nhập vào có thể là các chữ cái vì nó có hàm `atoi`(ascii to string)
* Nhập abc: được chuỗi `}847ftc_oc_ipd936ftc_oc_ipb_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{FTCftc_oc_ipocipftc_oc_ip`
các chuỗi bị lặp lại là : `ftc_oc_ip`
Từ đó ta có thể tìm ra các chuỗi không lặp:

```shell
}847
d936
b_99
9_TG
_xeh
_tig
id_3
{FTC
ocip
```

* Việc bây giờ chỉ cần đảo ngược lại các xâu trong này

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

* Dịch ra thành: `picoCTF{3_digit_hex_GT_999_b639d748}`

## hiddencipher

* Kết nối đến server : 235a201d702015483b1d412b265d3313501f0c072d135f0d2002302d06476350224507462e
* Đây là flag được mã hóa bởi XOR (tính chất: Nếu XOR hai lần với key là chính nó thì vẫn ra chính nó)
* Nếu như XOR thử `picoCTF{` thì nó sẽ ra được cái này: `S3Cr3t`
* Thử XOR với đoạn text bên trên và được flag: `picoCTF{xor_unpack_4nalys1s_530ca742}`

## hidencipher2

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

```shell
1680, 1575, 1485, 1665, 1005, 1260, 1050, 1845, 1635, 780, 1740, 1560, 1425, 1470, 765, 1560, 735, 1650, 1500, 1425, 1485, 735, 1680, 1560, 765, 1710, 1425, 780, 1455, 765, 1470, 750, 1485, 1485, 1530, 1875
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

* The key encoded by `base64` and the `webhookUrl` was `Fernet`
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

## 
