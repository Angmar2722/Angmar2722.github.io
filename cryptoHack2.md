---
layout: page
title: General 
---
<hr/>

The geneal section consists of 18 challenges. The challenges are subdivided into 4 different stages : Encoding, XOR, Mathematics and Data Formats. Below are the writeups for the ones I managed to complete :

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


