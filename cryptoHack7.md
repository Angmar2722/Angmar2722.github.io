---
layout: page
title: Block Ciphers - ECB / CBC / OFB / CTR / GCM / Other Modes / Other Ciphers
---
<hr/>

The Block Ciphers section consists of 22 challenges. The challenges are subdivided into 9 different stages : AES, Block Cipher Modes, ECB, CBC, OFB, CTR, GCM, Other Modes and Other Ciphers. Below are the writeups for the ones I managed to complete for the ECB, CBC, OFB, CTR, GCM, Other Modes and Other Ciphers sections :

<br/>

# ECB Oracle (ECB)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img76.png)

When you go the <a href="http://aes.cryptohack.org/ecb_oracle/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

Source Code Provided :

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


KEY = ?
FLAG = ?


@chal.route('/ecb_oracle/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}

    return {"ciphertext": encrypted.hex()}

```

So this program is running on a server where based on a given input (plaintext), it returns an encryped ciphertext in hex. The encryption used is AES and the mode of operation is ECB (electronic codebook) which has many, many vulnerabilities.

Before I learnt how to crack this challenge, I needed to learn how to communicate with the server. To do that, I used the `requests` package in Python. Here is a <a href="https://docs.python-requests.org/en/master/user/quickstart/#make-a-request" target="_blank">link</a> to the quickstart documentation for using requests. This <a href="https://www.youtube.com/watch?v=Rk0NIQfEXBA" target="_blank">video</a> from Computerphile explains popular modes of operation really well while this <a href="https://www.youtube.com/watch?v=R3NosHMSi0o" target="_blank">video</a> explains how padding and the cryptographic message syntax (CMS) works.

So to solve this challenge, I have to exploit the fact that ECB takes in a block of bytes (16 bytes in the case of AES) and then outputs the ciphertext after encryption it with the AES key. If the same plaintext (block of bytes) is inputted again, the same ciphertext would be outputted. So it is very easy to establish patterns amongst the ciphertext using ECB.

What I did was that I first tried to find the length of the flag. So when I give the encryption algorithm 1 byte of input ("00" in hex which is 1 byte), it gave me a ciphertext of length 64 in hex (32 bytes). So I created a loop which would have a counter which would be incremented and multiplied with the input "00" each time and then get the length of the resulting ciphertext until the original cipher length and new cipher length differed (so when the ciphertext changed from 32 bytes to 48 bytes). One thing I forgot was that when padding, if the last unoccupied byte (the 16th byte in a block) is occupied, it creates a new block of bytes. So if at the 7th byte (00000000000000 as the input) resulted in the output ciphertext of 48 bytes, it means that the 7th byte is the last byte which occupied the 32nd byte slot. I was overcounting my key length by one byte (so I was assuming that the key length was 26 bytes instead of the actual 25). To get the key length, I subtracted the counter (which was tracking the 00s input) from the original key length of 32 bytes (so 32-7 = 25, but I did 32-6 = 26 in my program).

Getting the key length wasn't the main part of solving the challenge. What I did was that I realized that the key was within 32 bytes (or 2 blocks) so if I used the input injected and prepended before the flag and focused on the 3rd block (bytes 33 - 48), I could get the flag one byte at a time. So say I input 47 bytes of zeroes into the encryption program, what it would do is add the 47 bytes and then add the flag (so the first byte of the flag would occupy the 48th byte slot) and so on, and then encrypt it and give the ciphertext. So if I added 47 zeroes and saw the ciphertext, the equivalent hex (ciphertext) would be 47 zeroes followed by the flag. Since I know that the flag format is "crypto{" ), this would be 47 zeroes followed by a "c" and so on. So if I restricted my outputted ciphertext to the 33rd to 48th bytes (the 3rd block), what I could do was input 47 zeroes and check the hex (ciphertext) and compare that to the ciphertext (hex) resulting from 47 zeroes and a readable/printable ASCII character (from 33 in decimal "!" to 126 in decimal, though in my program, I looped only till 125 as I assumed that the ASCII character 126 (the wavy line) would not be part of the flag). 

Now if I got the first byte of the flag, I could decrease my input to 46 zeroes and compare the resulting hex ciphertext to the ciphertext resulting from 46 zeroes and the first byte of the flag as well as an ASCII character (I used a loop to go from 33 to 126 in ASCII and if the hex ciphertext matched, that would be the byte of the flag). So each time I got an additonal byte of the flag, I could add it to the flag variable and then reduce the number of zeroes input by one, check the ciphertext and compare it with the ciphertext resulting from the equivalent reduced number of zeroes input along with the flag currently known as well as one byte for the ASCII character guess (the new byte of the flag to get). So each time, I am comparing two hex ciphertexts and if they match, the ASCII character which produced that hex is the byte of the flag. I am using the property of ECB where idential plaintexts yield idential ciphertexts with the same key, which highlights how unsafe ECB really is. Even though the AES is implemented correctly, the weakness of ECB allows me to get the flag.

**Flag :** crypto{p3n6u1n5_h473_3cb}