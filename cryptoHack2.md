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

# ASCII 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img10.png)

As shown in the image above, all you had to do was convert the hex string to ASCII characters in order to obtain the flag. I used a python command `"63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d".decode("hex")` in order to achieve this. I then got the flag as shown below :
 
![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img11.png)

**Flag :** crypto{You_will_be_working_with_hex_strings_a_lot}

<br/>


