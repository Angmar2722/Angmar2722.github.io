---
layout: page
title: General : Encoding / XOR
---
<hr/>

The geneal section consists of 18 challenges. The challenges are subdivided into 4 different stages : Encoding, XOR, Mathematics and Data Formats. Below are the writeups for the ones I managed to complete for the Encoding and XOR sections :

<br/>

# ASCII (Encoding)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img8.png)

As shown in the image above, all you had to do was convert the numbers to their corresponding ASCII characters in order to obtain the flag. I used a python command `''.join(chr(i) for i in array)` in order to achieve this. I then got the flag as shown below :
 
![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img9.png)

**Flag :** crypto{ASCII_pr1nt4bl3}

<br/>

# Hex (Encoding)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img10.png)

As shown in the image above, all you had to do was convert the hex string to ASCII characters in order to obtain the flag. I used a python command `"63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d".decode("hex")` in order to achieve this. I then got the flag as shown below :
 
![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img11.png)

**Flag :** crypto{You_will_be_working_with_hex_strings_a_lot}

<br/>

# Base64 (Encoding)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img12.png)

As shown in the image above, all you had to do was convert the hex string to ASCII characters and then encode it to a base 64 string in order to obtain the flag. I used a python command `'72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf'.decode('hex').encode('base64')` in order to achieve this. I then got the flag as shown below :
 
![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img13.png)

Note that before submitting, the challenge stated that the flag format was `crypto/FLAG/`.

**Flag :** crypto/Base+64+Encoding+is+Web+Safe/

<br/>

# Bytes and Big Integers (Encoding)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img16.png)

As shown in the image above, I had to convert the integer `11515195063862318899931685488813747395775516287289682636499965282714637259206269` into hex (base 16) by using the command `hex(11515195063862318899931685488813747395775516287289682636499965282714637259206269)`. When I did that, I noticed that I was getting `0x63727970746f7b336e633064316e365f346c6c5f3768335f7734795f6430776e7dL` and at the end of that hex string was the character `L` which is not part of the hexadecimal system (as it ranges from 0 to F). Hence I converted that hex string without the `L` into ASCII by using the command `"63727970746f7b336e633064316e365f346c6c5f3768335f7734795f6430776e7d".decode("hex")` and with that I got the flag as shown below :
 
![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img17.png)

**Flag :** crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}

<br/>

# Encoding Challenge (Encoding)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img18.png)

As shown in the image above, I had to write my first <a href="https://github.com/Gallopsled/pwntools-tutorial/blob/master/tubes.md" target="_blank">Pwntools</a> script in order to solve the challenge. As stated in its Github page - Pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible. I would receive data from the server in an encoded format (for example a string in base 64) and I had to convert that to a string (ASCII or UTF-8) in order to pass a level. There were 100 such levels and 5 different encoding formats - base64, hex, rot13 (a special type of Caesar Cipher which has a right shift of 13), int and utf-8.

Source code for what was running on the server (file `13337.py` as shown in the challenge image above) :

```python

#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener # this is cryptohack's server-side module and not part of python
import base64
import codecs
import random

FLAG = "crypto{????????????????????}"
ENCODINGS = [
    "base64",
    "hex",
    "rot13",
    "bigint",
    "utf-8",
]
with open('/usr/share/dict/words') as f:
    WORDS = [line.strip().replace("'", "") for line in f.readlines()]


class Challenge():
    def __init__(self):
        self.challenge_words = ""
        self.stage = 0

    def create_level(self):
        self.stage += 1
        self.challenge_words = "_".join(random.choices(WORDS, k=3))
        encoding = random.choice(ENCODINGS)

        if encoding == "base64":
            encoded = base64.b64encode(self.challenge_words.encode()).decode() # wow so encode
        elif encoding == "hex":
            encoded = self.challenge_words.encode().hex()
        elif encoding == "rot13":
            encoded = codecs.encode(self.challenge_words, 'rot_13')
        elif encoding == "bigint":
            encoded = hex(bytes_to_long(self.challenge_words.encode()))
        elif encoding == "utf-8":
            encoded = [ord(b) for b in self.challenge_words]

        return {"type": encoding, "encoded": encoded}

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        if self.stage == 0:
            return self.create_level()
        elif self.stage == 100:
            self.exit = True
            return {"flag": FLAG}

        if self.challenge_words == your_input["decoded"]:
            return self.create_level()

        return {"error": "Decoding fail"}


listener.start_server(port=13377)

```
The defualt Pwntools source code template that they provided (file `pwntools_example.py` as shown in the challenge image) is shown below :

```python

from pwn import * # pip install pwntools
import json

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)


received = json_recv()

print("Received type: ")
print(received["type"])
print("Received encoded value: ")
print(received["encoded"])

to_send = {
    "decoded": "changeme"
}
json_send(to_send)

json_recv()

```
<br/>

I found this <a href="https://github.com/Gallopsled/pwntools-tutorial/blob/master/tubes.md" target="_blank">Pwntools tutorial</a> to be very useful. So after a lot of Googling, this is the script that I wrote in order to get the flag :

```python

from pwn import * # pip install pwntools
import json
import base64
import codecs

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
        line = r.recvline()
        return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

for i in range(100):

    received = json_recv()

    #print("Received type: ")
    #print(received["type"])
    #print("Received encoded value: ")
    #print(received["encoded"])

    str1 = ""
    if (received["type"] == "rot13"):
        str0 = received["encoded"]
        str1 = str0.upper()

    arr1 = list(str1)

    sortedArray = list(str1)
            
    str2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    arr2 = list(str2)
    arr3 = list(str2)

    spaceArray = [0] * len(str1)
    for i in range( len(arr1) ):
        if arr1[i] == '_':
            spaceArray[i] = "1"

    def shiftArray(rightShift):
        arrPositionLength = len(arr2) - 1
        for i in range( len(arr2) ):
            if (i + rightShift) <= arrPositionLength:
                arr3[i] = arr2[i + rightShift]
            else:
                positiveGap = arrPositionLength - i
                arr3[i] = arr2[i + positiveGap]
                negativeGap = (rightShift - positiveGap) - 1
                if negativeGap >= 0 :
                    arr3[i] = arr2[negativeGap]
        return arr3

    def getDecryptedTextWithShift(rightShift):
        shiftedArray = shiftArray(rightShift)
        for i in range( len(arr1) ):
            for f in  range( len(shiftedArray) ):
                if (shiftedArray[f] == arr1[i]) :
                    sortedArray[i] = arr2[f]
        decryptedText = ""
        for i in range( len(sortedArray) ):
            if spaceArray[i] != 1:
                decryptedText = decryptedText + sortedArray[i]
            else:
                decryptedText = decryptedText + "_"
        return decryptedText
            

    def decoder(encodedText, encodedType):
        if(encodedType == "base64"):
            base64_string = encodedText
            base64_bytes = base64_string.encode("ascii")
            sample_string_bytes = base64.b64decode(base64_bytes)
            sample_string = sample_string_bytes.decode("ascii")
            return sample_string
        elif (encodedType == "hex"):
            hex_decoder = codecs.getdecoder("hex_codec")
            decodedHex = hex_decoder(encodedText)[0]
            return decodedHex.decode("utf-8")
        elif (encodedType == "bigint"):
            hexText = encodedText.upper()
            temp = list(hexText)
            temp.remove('0')
            temp.remove('X')
            hexText = "".join(temp)
            decodedInt = bytes.fromhex(hexText).decode('utf-8')
            return decodedInt
        elif (encodedType == "utf-8"):
            return ''.join(chr(i) for i in encodedText)
        else:
            decryptedROT13 = getDecryptedTextWithShift(13)
            decryptedROT13 = decryptedROT13.lower()
            return decryptedROT13


    decodedText = decoder(received["encoded"], received["type"])
    #print("The decoded ", received["type"], " is : ", decodedText)

    to_send = {
        "decoded": decodedText
    }
    json_send(to_send)

flag = r.recvline()
print(flag)

```

After running my script as shown in the image below, I got my flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img19.png)

**Flag :** crypto{3nc0d3_d3c0d3_3nc0d3}



