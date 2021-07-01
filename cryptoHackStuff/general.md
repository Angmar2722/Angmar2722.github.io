---
layout: page
title: General 
---
<hr/>

The general section consists of 19 challenges. The challenges are subdivided into 4 different stages : Encoding, XOR, Mathematics and Data Formats. Below are the writeups for the challenges that I managed to complete for this section :

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


<br/>

# Greatest Common Divisor (Mathematics)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img27.png)

As shown in the image above, I just had to find the GCD of the two numbers `66528` and `52920`. To do that, I wrote this script :

```python

#!/usr/bin/env python3

def getGCD(x, y):
    temp = 0	
    if (x < y):
        temp = x
        x = y
        y = temp
    elif (x % y == 0):
        return y
            
    return getGCD(y, x%y)


print(getGCD(66528, 52920))

```

After running the script, I got the GCD (and this was the flag) :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img28.png)

**Flag :** 1512

<br/>

# Extended GCD (Mathematics)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img33.png)

As shown in the image above, I had to find the integers u and v such that pu + qv = 1 (the GCD of the two prime numbers p and q). This is a case of using <a href="https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity#:~:text=In%20elementary%20number%20theory%2C%20B%C3%A9zout's,exactly%20the%20multiples%20of%20d." target="_blank">Bezout's Identity</a> which this <a href="https://www.youtube.com/watch?v=9KM6bX2rud8" target="_blank">video</a> explains very nicely. To get u and v, I looked at the pseudocode implementation of the <a href="https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm" target="_blank">Extended Euclidean algorithm</a> on Wikipedia and converted that to the Python code shown below :

```python

#!/usr/bin/env python3

p = 26513
q = 32321

def extended_gcd(p, q):
    old_r, r = p, q
    old_s, s = 1, 0
    old_t, t = 0, 1

    while (r != 0):
        quotient = int(old_r / r)
        old_r, r = r, (old_r - quotient * r)
        old_s, s = s, (old_s - quotient * s)
        old_t, t = t, (old_t - quotient * t)

    print("Bezout coefficients : ", old_s, " ", old_t)
    print("GCD : ", old_r)

extended_gcd(p, q)

```

And as shown below, after running the program, I got u and v :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img34.png)

**Flag :** crypto{10245,-8404}

<br/>

# Modular Arithmetic 1 (Mathematics)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img35.png)

As shown in the image above, I had to calculate a and b and the flag is the smaller of the two integers (a and b). If a is congruent to b mod m, then b = a % m (as explained in the image above). So doing that for the two integers I got 5 and 4 respectively. So the flag was 4 (the smaller integer). Shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img36.png)

**Flag :** 4

<br/>

# Modular Arithmetic 2 (Mathematics)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img37.png)

`3^17 mod 17` gives 3, `5^17 mod 17` gives 5, `7^16 mod 17` gives 1. So `273246787654^65536 mod 65537` gives 1.

**Flag :** 1

<br/>

# Modular Inverting (Mathematics)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img38.png)

3*9 mod 13 gives 1 as 27 mod 13 gives 1. Therefore the flag is 9.

**Flag :** 9

<br/>

# Privacy-Enhanced Mail? (Data Formats)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img39.png)

As shown in the image above, I have to convert the given PEM file (a base 64 encoded DER file) into a DER file in order to access the private exponent "d" of the private RSA key, which is the flag.

Image of the contents of the PEM file :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img41.png)

This <a href="https://www.cryptologie.net/article/260/asn1-vs-der-vs-pem-vs-x509-vs-pkcs7-vs/" target="_blank">link</a> they gave explains the different TLS certificate formats (including DER and ASN.1). I found this <a href="https://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file" target="_blank">answer</a> explaining what a PEM file is to be very useful too.

The Python cryptography documentation was also very useful :
* <a href="https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
" target="_blank">Serialization</a>
* <a href="https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
" target="_blank">RSAPrivateKey</a>
* <a href="https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateNumbers
" target="_blank">RSAPrivateNumbers</a>

In order to convert the PEM file to a DER file and then extract the private exponent "d" I wrote the following code :

```python

#!/usr/bin/env python3
 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key
 
with open("privacy_enhanced_mail_1f696c053d76a78c2c531bb013a92d4a.pem", "rb") as keyfile:

    # Load the PEM format key
    pemkey = serialization.load_pem_private_key(
       keyfile.read(),
       None,
       default_backend()
    )

    # Serialize it to DER format
    derkey = pemkey.private_bytes(
       serialization.Encoding.DER,
       serialization.PrivateFormat.TraditionalOpenSSL,
       serialization.NoEncryption()
    )

    key = load_der_private_key(derkey, password=None)
    print(isinstance(key, rsa.RSAPrivateKey))
    pn = key.private_numbers()
    print(pn.d)
  
```

And after running the program I got the flag (the int private exponent "d") :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img40.png)

**Flag :** 15682700288056331364787171045819973654991149949197959929860861228180021707316851924456205543665565810892674190059831330231436970914474774562714945620519144389785158908994181951348846017432506464163564960993784254153395406799101314760033445065193429592512349952020982932218524462341002102063435489318813316464511621736943938440710470694912336237680219746204595128959161800595216366237538296447335375818871952520026993102148328897083547184286493241191505953601668858941129790966909236941127851370202421135897091086763569884760099112291072056970636380417349019579768748054760104838790424708988260443926906673795975104689

<br/>

# CERTainly not (Data Formats)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img42.png)

As shown in the image above, I had to extract the integer modulus of the public key of the DER file given (as a DER certificate does not contain a private key but rather the public key). To do this, I used the <a href="https://www.pyopenssl.org/en/stable/" target="_blank">PyOpenSSL library</a>. Below is the code that I wrote to get the modulus n (the product of the primes p and q) :

```python

#!/usr/bin/env python3

import OpenSSL.crypto
 
with open("2048b-rsa-example-cert_3220bd92e30015fe4fbeb84a755e7ca5.der", "rb") as keyfile:
    der = keyfile.read()
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der)
    pkey = x509.get_pubkey()
    modn = pkey.to_cryptography_key().public_numbers().n
    print(modn)
    
```

And after running the program I got the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img43.png)

**Flag :** 22825373692019530804306212864609512775374171823993708516509897631547513634635856375624003737068034549047677999310941837454378829351398302382629658264078775456838626207507725494030600516872852306191255492926495965536379271875310457319107936020730050476235278671528265817571433919561175665096171189758406136453987966255236963782666066962654678464950075923060327358691356632908606498231755963567382339010985222623205586923466405809217426670333410014429905146941652293366212903733630083016398810887356019977409467374742266276267137547021576874204809506045914964491063393800499167416471949021995447722415959979785959569497

<br/>

# SSH Keys (Data Formats)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img162.png)

The public key given is shown in the image (the file is the same key) above. I first converted that to a `pem` format using the command `ssh-keygen -f bruce_rsa_6e7ecd53b443a97013397b1a1ea30e14.pub -e -m pem` and from there on out, I extracted the modulus.

<p> <b>Flag :</b> 3931406272922523448436194599820093016241472658151801552845094518579507815990600459669259603645261532927611152984942840889898756532060894857045175300145765800633499005451738872081381267004069865557395638550041114206143085403607234109293286336393552756893984605214352988705258638979454736514997314223669075900783806715398880310695945945147755132919037973889075191785977797861557228678159538882153544717797100401096435062359474129755625453831882490603560134477043235433202708948615234536984715872113343812760102812323180391544496030163653046931414723851374554873036582282389904838597668286543337426581680817796038711228401443244655162199302352017964997866677317161014083116730535875521286631858102768961098851209400973899393964931605067856005410998631842673030901078008408649613538143799959803685041566964514489809211962984534322348394428010908984318940411698961150731204316670646676976361958828528229837610795843145048243492909 </p>

<br/>

# Transparency (Data Formats)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img44.png)

Initially I approached this challenge from a completely wrong angle - I thought that I had to decode the public key which would have some attribute that would point to the required subdomain. After a lot of frustrating time spent down this fruitless and pointless rabbit hole, I realised that I could use  <a href="https://transparencyreport.google.com/https/certificates?hl=en" target="_blank">this website made by Google</a> to find the subdomain of cryptohack.org (and this was so obvious from the hint they gave " "since 2018 Certificate Transparency has been enforced by Google Chrome. Every CA must publish all certificates that they issue to a log, which anyone can search." ).

As shown in the image below, I found the subdomain (on the 3rd page of the results) which had the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img45.png)

After entering the subdomain, the flag was there :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img46.png)

**Flag :** crypto{thx_redpwn_for_inspiration}

