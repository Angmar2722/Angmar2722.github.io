---
layout: page
title: General - Encoding
---
<hr/>

The geneal section consists of 18 challenges. This page has my writeups for the encoding section (5 challenges) of the general section. 

<br/>

# ASCII 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img7.png)

As shown in the image above, all you had to do was convert the numbers to their corresponding ASCII characters in order to obtain the flag. I used a python command `''.join(chr(i) for i in array)` in order to achieve this. I then got the flag as shown below :
 
![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img8.png)

**Flag :** crypto{ASCII_pr1nt4bl3}

<br/>

