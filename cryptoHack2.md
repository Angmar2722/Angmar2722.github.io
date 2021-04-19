---
layout: page
title: General - Encoding
---
<hr/>

The geneal section consists of 18 challenges. This page has my writeups for the encoding section (5 challenges) of the general section. 

<br/>

# ASCII 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img8.png)

As shown in the image above, all you had to do was convert the numbers to their corresponding ASCII characters in order to obtain the flag. I used a python command `''.join(chr(i) for i in array)` in order to achieve this. I then got the flag as shown below :
 
![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img9.png)

**Flag :** crypto{ASCII_pr1nt4bl3}

<br/>

# Hex 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img10.png)

As shown in the image above, all you had to do was convert the hex string to ASCII characters in order to obtain the flag. I used a python command `"63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d".decode("hex")` in order to achieve this. I then got the flag as shown below :
 
![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img11.png)

**Flag :** crypto{You_will_be_working_with_hex_strings_a_lot}

<br/>

# Base64 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img12.png)

As shown in the image above, all you had to do was convert the hex string to ASCII characters and then encode it to a base 64 string in order to obtain the flag. I used a python command `'72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf'.decode('hex').encode('base64')` in order to achieve this. I then got the flag as shown below :
 
![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img13.png)

Note that before submitting, the challenge stated that the flag format was `crypto/FLAG/`.

**Flag :** crypto/Base+64+Encoding+is+Web+Safe/

<br/>



