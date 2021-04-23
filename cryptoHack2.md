---
layout: page
title: General - Encoding / XOR
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

As shown in the image above, I had to write my first <a href="https://github.com/Gallopsled/pwntools-tutorial/blob/master/tubes.md" target="_blank">Pwntools</a> script in order to solve the challenge. As stated in its Github page - Pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible. I would receive data from the server in an encoded format (for example a string in base 64) and I had to convert that to a string (ASCII or UTF-8) in order to pass a level. There were 100 such levels and 5 different encoding formats - base64, hex, rot13 (a <a href="https://en.wikipedia.org/wiki/ROT13" target="_blank">special type of Caesar Cipher</a> which has a right shift of 13), int and utf-8.

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

I found this <a href="https://github.com/Gallopsled/pwntools-tutorial/blob/master/tubes.md" target="_blank">Pwntools tutorial</a> to be very useful. I also copied and slightly modified the inefficient Caesar Cipher decryptor that I wrote for the <a href="https://angmar2722.github.io/cryptoHack0/" target="_blank">Logging In</a> section of CryptoHack in order to solve the ROT13 cipher. So after a lot of Googling, this is the script that I wrote in order to get the flag :

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

<br/>

# XOR Starter (XOR)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img20.png)

As shown in the image above, I am supposed to XOR each character from the string `"label"` with the integer `13`. In the script that I used to solve this, I used two ways to get the answer. The first way involved converting each character of the string "label" to ASCII and then XORing that integer with the integer 13.

For the second and much longer way that I used to solve this, I converted both the string and integer to binary and then XORed the binary string of each character in `"label"` with the binary of 13. Then I converted that XORed binary back to ASCII and then outputted the value.

Of note, I found a helpful answer in Stack Overflow that showed how to convert an integer to binary and specify the number of digits as shown in the image below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img21.png)

Source code for my script is shown below (the first way to get the answer ends before the prompt to the user to input a string and the second way starts with the prompt):

```python

#!/usr/bin/env python3

string = "label"
int_ = 13
arr1 = list(string)

for i in range( len(arr1) ):
    arr1[i] = ord(arr1[i])^int_

#print(arr1)

print( ''.join(chr(i) for i in arr1) )

str1 = input("Enter the string that you want to convert to binary : ")
arr = list(str1)

int1 = int(input("Enter the integer that you want to convert to binary : "))
intb = '{0:b}'.format(int1)

for i in range ( len(arr) ):
    arr[i] = ord(arr[i])
    arr[i] = '{0:b}'.format(arr[i])

def xor(x, y):
    return '{0:b}'.format(int(x, 2) ^ int(y, 2))

for i in range (  len(arr) ):
    arr[i] = xor(arr[i], intb)
    n = int(arr[i], 2)
    arr[i] = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()

print("The decoded string is ", "".join(arr))

```

As shown in the image below, I get the answer both ways :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img22.png)

**Flag :** crypto{aloha}

<br/>

# XOR Properties (XOR)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img23.png)

As shown in the image above, I am supposed to apply the associative property of XOR operations in order to get each key. For example, given that I know key 1 and the value of (key2 XOR key1), I can find key2 by performing the operation (key2 XOR key1) XOR key1. In my script I did the opposite but because XOR properties are commutative, that really isn't an issue. This same concept was applied for finding the other keys and eventually the value of the flag in hex. After that I converted the hex to ASCII and then got the flag.

The source code for the script that I wrote to solve this challenge is shown below :

```python

#!/usr/bin/env python3
import codecs

KEY1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
KEY2xorKEY1 = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
KEY2xorKEY3 = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
FLAGxorKEY1xorKEY2xorKEY3 = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

def hexToInt(hexString):
    return int(hexString, 16)

def keyGetter(k1, k2):

    k1 = hexToInt(k1)
    k2 = hexToInt(k2)

    k1b = '{0:b}'.format(k1)
    k2b = '{0:b}'.format(k2)

    def xor(x, y):
        return '{0:b}'.format(int(x, 2) ^ int(y, 2))

    temp = xor(k1b, k2b)

    x = hex(int(temp, 2))
    #print("The key in hex is : ", x)
    return x

KEY2 = keyGetter(KEY1, KEY2xorKEY1)
KEY3 = keyGetter(KEY2xorKEY3, KEY2)
KEY1_XOR_KEY3_XOR_KEY2 = keyGetter(KEY1, KEY2xorKEY3)
FLAG_HEX = keyGetter(KEY1_XOR_KEY3_XOR_KEY2, FLAGxorKEY1xorKEY2xorKEY3)

#print(FLAG_HEX)

def hexToString(hexText):
    hexText = hexText.upper()
    temp = list(hexText)
    temp.remove('0')
    temp.remove('X')
    hexText = "".join(temp)
    decodedHex = bytes.fromhex(hexText).decode('utf-8')
    return decodedHex

flag = hexToString(FLAG_HEX)
print("The flag is : ", flag)

```

And after running my script, I got the flag as shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img24.png)

**Flag :** crypto{x0r_i5_ass0c1at1v3}

<br/>

# Favourite byte (XOR)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img25.png)

As shown in the image above, I am supposed to find a certain single byte which when XORed with each byte in the ciphertext would yield the flag. To do this, I wrote a script that loops through the numbers 0 to 255 (because a byte can represent values in this range and each value is my byte guess) and then XORed that byte guess with each byte from the ciphertext (after converting the hexadecimal to a byte string using `binascii.unhexlify`). I then used the `chr()` to convert the int to ASCII and then used `''.join` to join the array of decoded characters to form a string. After that, I would output the decoded text if it was printable and if the first 7 characters matched `crypto{` as that is the flag format. 

Source code for my script :

```python

#!/usr/bin/env python3
import codecs
import itertools
import binascii

encoded = binascii.unhexlify('73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d')
for xor_key in range(256):
    decoded = ''.join(chr(b ^ xor_key) for b in encoded)
    if (decoded.isprintable() and decoded[0] == "c" and decoded[1] == "r" and decoded[2] == "y" and decoded[3] == "p" and decoded[4] == "t" and decoded[5] == "o" and decoded[6] == "{"):
        print(xor_key, decoded)
        
```

As shown in the image below, after running the script I get the flag (the 16 means that the special byte was `0x10` and this was explicitly stated in the flag) :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img26.png)

**Flag :** crypto{0x10_15_my_f4v0ur173_by7e}

<br/>

# You either know, XOR you don't (XOR)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img31.png)

As shown in the image above, I am supposed to decrypt the hex string `0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104` in order to get the flag. There is a hint which tells us to remember the flag format : `crypto{flag-text-goes-here}`. I spent a lot of time trying to create a program that would brute force this hex string but failed to do so. The size of the key in bytes is also unknown....

Assuming that the decoded text would start off with the 7 characters `crypto{`, I XORed the first 7 bytes of the cipher text (`0e, 0b, 21, 3f, 26, 04, 1e` with `crypto{` respectively) because each byte of the ciphertext XOR each byte of the plaintext (flag format) would yield the key). After doing this, I got `6d 79 58 4f 52 6b 65` respectively which when converted to ASCII gives me `myXORke`. Also assuming that the last byte of the ciphertext would be `}` (the closing brace of the flag which is part of the format), I XORed that brace with the last byte of the ciphertext (04) and this gave me 79 in hex which is "y" in ASCII. So the key was probably 8 bytes as the last byte of the key was probably 79 which means that the key in ASCII was `myXORkey` or `6d79584f526b6579` in hex which is 7888433320024565113 in decimal (int).

Ok so now that we probably know the key, I could use my script which I was writing for brute forcing the key and just modify it to loop only once and pass in 7888433320024565113 (the key in decimal) as the key. Source code for the script :

```python

#!/usr/bin/env python3
import codecs
import itertools
import binascii
import textwrap
from itertools import permutations

def hexToInt(hexString):
    return int(hexString, 16)

def hexToString(hexText):
    hexText = hexText.upper()
    temp = list(hexText)
    hexText = "".join(temp)
    decodedHex = bytes.fromhex(hexText).decode('utf-8')
    return decodedHex

def xor(x, y):
    return '{:x}'.format( int('{0:b}'.format(x ^ y), 2) )

def keyGetter(cipherText, keyGuess, byteKey):

    tempCipherByteList = textwrap.wrap(str(cipherText), 2)
    keyGuessInHexList = textwrap.wrap(str('{:x}'.format(keyGuess)), 2)
   
    for i in range( len(tempCipherByteList) ):
        tempCipherByteList[i] = hexToInt(tempCipherByteList[i])

    keyGuess = int(keyGuess)
    decodedArray = list("0" * len(tempCipherByteList))

    tracker = 0

    for i in range ( len(tempCipherByteList) ):
        if (tracker == len(keyGuessInHexList) ):
            tracker = 0
        #print('{:x}'.format(tempCipherByteList[i]), keyGuessInHexList[tracker])
        decodedArray[i] = str( xor(tempCipherByteList[i], hexToInt(keyGuessInHexList[tracker])) )
        tracker = tracker + 1

    return "".join(decodedArray)

cipherText = '0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104'

inputCipher = input("Enter the ciphertext that you want to decrypt : ")
byteKeyInput = int(input("Enter the size of the key in bytes that you want to brute force : "))
flagFormat = input("Enter the first part of the flag format (Example - `crypto{` ) : ")

flagFormatHex = flagFormat.encode("utf-8").hex()
flagFormatHexList = textwrap.wrap(str(flagFormatHex), 2)

#for xor_key in range( 2**(8*byteKeyInput) ):
for xor_key in range( 7888433320024565113, 7888433320024565114 ):

    flagHex = keyGetter(inputCipher, xor_key, byteKeyInput)
    flagHexList = textwrap.wrap(str(flagHex), 2)

    for i in range (len(flagHexList)):
        if (flagHexList[i] == flagFormatHexList[0]) and (i < ( len(flagHexList) - len(flagFormatHexList) ) ):
            c = 0
            while (flagHexList[i + c] == flagFormatHexList[c]) and (c < len(flagFormatHexList)):
                x = 1
                if (c == len(flagFormatHexList)-1):
                    print(hexToString(flagHex))
                    break
                c = c + 1

```

And after running my very **inefficient** script, I got the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img32.png)

**Flag :** crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}

<br/>

# Lemur XOR (XOR)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img30.png)

As shown in the image above, I am supposed to XOR the images `lemur.png` and `flag.png` in order to get an image which will have the flag. I found a <a href="https://stackoverflow.com/questions/54398627/xor-ing-and-summing-two-black-and-white-images" target="_blank">Stack Overflow answer</a> which showed exactly how to achieve this. So I imported <a href="https://imagemagick.org/script/download.php" target="_blank">imagemagick</a> and then used the command `magick lemur.png flag.png -evaluate-sequence xor result.png` in order to XOR the two images and place the result in the image `result.png` which is showed below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img29.png)

As shown above, the flag is now visible!

**Flag :** crypto{X0Rly_n0t!}
