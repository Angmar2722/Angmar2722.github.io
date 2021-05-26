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

It is important to note that I was only focusing on the third block and effectively moving the flag and zeroes input down by one each time. The program took around 31 minutes to run, clearly it could be optimized way, way more and reduce the runtime. And since I was using the wrong flag length (26 instead of 25), the program never stopped as I would only stop it if the flag length was 26 (so after getting the flag I had to exit manually). Next time, it would be better to put the correct flag length (obviously) and maybe even a check for the "}" as the closing brace is the last part of the flag in most challenges in CryptoHack and CTFs. So if I reached the closing brace, I could exit the program. Most of what I learnt came from <a href="https://godiego.tech/posts/AES-128-padding-attack/" target="_blank">this</a> excellent CTF writeup.

This is the code that I wrote :

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests

def getLength(guess):
    payloadURL = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + guess + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    return getCiphertextLengthInBytes( temp['ciphertext'] )

def getCiphertextLengthInBytes(ciphertext):
    return len(ciphertext) // 2

def getHex(guess):
    payloadURL = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + guess + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    temp = temp['ciphertext']
    return temp[64:96]

length = 0

def getFlagLength():
    c = 1
    guess = "00" * c
    originalLength = getLength(guess)
    print(originalLength)
    check = True
    c = 1
    while (check == True):
        guess = "00" * c
        length = getLength(guess)
        if(length == originalLength):
            c = c + 1
        elif (length != originalLength):
            c = c - 1
            check = False
            break
    return (originalLength - c)
        
#flagLength = getFlagLength() 
#print(flagLength)

flag = ""

end = True 

while (end == True):

    payload = "00"*(47-len(flag))
    hex = getHex(payload)

    for i in range(33, 126):
        temp = flag + chr(i)
        payload = "00"*(47-len(flag)) + temp.encode("utf-8").hex()
        if(hex == getHex(payload)):
            flag = flag + chr(i)
            print ("Flag: ", flag)
            if (len(flag) == 26):
                break
        if (len(flag) == 26):
            end = False

```

And after running the program, you slowly get the flag (I had to manually quit as my flag length was wrong, but the code still worked well enough) :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img77.png)

**Flag :** crypto{p3n6u1n5_h473_3cb}

I guess the "penguins hate ECB" flag relates to the iconic <a href="https://blog.filippo.io/the-ecb-penguin/" target="_blank">ECB Penguin</a>.

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img78.png)

<br/>

# ECB Oracle (ECB)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img80.png)

When you go the <a href="http://aes.cryptohack.org/ecbcbcwtf/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img80.png)

Original Code Provided :

```python

from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/ecbcbcwtf/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/ecbcbcwtf/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}

```

So what we have here is a decryption function using CBC (Cipher Block Chaining) and decryption using ECB. The diagram they provided was very useful. What I did was first divide the flag ciphertext into 3 blocks (16 bytes of 32 hex characters each). I passed in the last block into the decryption function and XORed that value with the second block of ciphertext (as that is how the cipher block chaining in CBC works). This would give me the last part of the flag. I then did the same thing, I passed in the second cipher block into the decrypt function and XORed that value with the first block of the flag cipher. By then the entirety of the flag was printed, I didn't even have to get the first block of plaintext!

The code that I wrote :

```python

import requests
import textwrap

def hexToInt(hexString):
    return int(hexString, 16)

def xor(x, y):
    return '{:x}'.format(x ^ y)

def getHex(input):
    payloadURL = "http://aes.cryptohack.org/ecbcbcwtf/decrypt/" + input + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    temp = temp['plaintext']
    return temp

flagCipher = "9c08a7f404a18e41792f3e0ba29c2ee211402550da530e5f877ab7b43be68ac287759e09226c9d8d2556e8d14cc20dfc"

flagCipherList = textwrap.wrap(flagCipher, 32)

halfStep = getHex(flagCipherList[2])
lastPlaintextBlock = xor( hexToInt(halfStep), hexToInt(flagCipherList[1]) )

flag = lastPlaintextBlock

halfStep = getHex(flagCipherList[1])
lastPlaintextBlock = xor( hexToInt(halfStep), hexToInt(flagCipherList[0]) )

flag = lastPlaintextBlock + flag

print(bytes.fromhex(flag).decode('utf-8'))

```
And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img79.png)

**Flag :** crypto{3cb_5uck5_4v01d_17_!!!!!}
