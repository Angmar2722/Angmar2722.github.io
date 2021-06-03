---
layout: page
title: RSA - Starter / Primes Part 1
---
<hr/>

The RSA section consists of 29 challenges. The challenges are subdivided into 7 different stages : Starter, Primes Part 1, Public Exponent, Primes Part 2, Padding, Signatures Part 1 and Signatures Part 2. Below are the writeups for the ones I managed to complete for the Starter and Primes Part 1 sections :

<br/>

# RSA Starter 1 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img109.png)

As shown in the image above, I just had to find 101^17 mod 22663 which I did using the command shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img110.png)

Flag : 19906

<br/>

# RSA Starter 2 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img111.png)

As shown in the image above, I just had to find 12^65537 mod (17*23) which I did using the command shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img112.png)

Flag : 301

<br/>

# RSA Starter 3 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img113.png)

As shown in the image above, I went to the <a href="https://leimao.github.io/article/RSA-Algorithm/" target="_blank">link</a> that they provided where some of the mathematics behind RSA encryption was explained. The Euler's Totient Function part is shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img115.png)

So since I had the two primes p and q, I had to do (p-1) * (q - 1) to get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img114.png)

Flag : 882564595536224140639625987657529300394956519977044270821168

<br/>

# RSA Starter 4 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img116.png)

As shown in the image above, to get the private key `d`, I have to get the modular multiplicative inverse of e Mod (the Euler totient of N). In the key generation section of the  <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation" target="_blank">RSA Wikipedia article</a>, it is stated that you can get the modular multiplicative inverse using the Extended Euclidean Algorithm as the equation is in a form of Bezout's identity. This is shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img117.png)

And when you go to the <a href="https://en.wikipedia.org/wiki/Modular_multiplicative_inverse" target="_blank">Modular Multiplicative Inverse</a> Wikipedia page, it shows how the Bezout's identity is mathematically used to compute the modular multiplicative inverse :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img118.png)

So I used my Extended Euclidean algorithm from a previous CryptoHack Challenge (Extended GCD (under the Mathematics section of General) ) to compute the private key (the modular multiplicative inverse) :

```python


p = 857504083339712752489993810777
q = 1029224947942998075080348647219
eulerTotient = (p-1) * (q-1)
e = 65537

def extended_gcd(a, m):
    old_r, r = a, m
    old_s, s = 1, 0
    old_t, t = 0, 1

    while (r != 0):
        quotient = int(old_r / r)
        old_r, r = r, (old_r - quotient * r)
        old_s, s = s, (old_s - quotient * s)
        old_t, t = t, (old_t - quotient * t)

    print("Bezout coefficients : ", old_s, " ", old_t)
    print("GCD : ", old_r)

extended_gcd(e, eulerTotient)

```

And when you run the program, you get the private key `d` :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img119.png)

Flag : 121832886702415731577073962957377780195510499965398469843281

Of note, these two videos explaining RSA encryption are incredible :

* <a href="https://www.youtube.com/watch?v=4zahvcJ9glg" target="_blank">Part 1</a>
* <a href="https://www.youtube.com/watch?v=oOcTVTpUsPQ" target="_blank">Part 2</a>

<br/>

# RSA Starter 5 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img120.png)

As shown in the image above, I had to decrypt the ciphertext using the private key I got from the previous challenge. In RSA, the decrypted message (m) = c^d Mod N with c being the ciphertext, d being the private key and N being the modulus.

So I did that and got the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img121.png)

Flag : 13371337

<br/>

# RSA Starter 6 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img122.png)

As shown in the image above, I had to compute the signature or sign the message ("crypto{Immut4ble_m3ssag1ng}"). To do that, I had to first convert the message to a hash (SHA-256) and then sign it with my private key by calculating hash ^ d (private key) MOD N. The private key file contained d and N as shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img123.png)

I wrote this short program to compute the signature and output it in hex :

```python

import hashlib

m = b"crypto{Immut4ble_m3ssag1ng}"

hashedM = int(hashlib.sha256(m).hexdigest(), 16)

d = 11175901210643014262548222473449533091378848269490518850474399681690547281665059317155831692300453197335735728459259392366823302405685389586883670043744683993709123180805154631088513521456979317628012721881537154107239389466063136007337120599915456659758559300673444689263854921332185562706707573660658164991098457874495054854491474065039621922972671588299315846306069845169959451250821044417886630346229021305410340100401530146135418806544340908355106582089082980533651095594192031411679866134256418292249592135441145384466261279428795408721990564658703903787956958168449841491667690491585550160457893350536334242689

N = 15216583654836731327639981224133918855895948374072384050848479908982286890731769486609085918857664046075375253168955058743185664390273058074450390236774324903305663479046566232967297765731625328029814055635316002591227570271271445226094919864475407884459980489638001092788574811554149774028950310695112688723853763743238753349782508121985338746755237819373178699343135091783992299561827389745132880022259873387524273298850340648779897909381979714026837172003953221052431217940632552930880000919436507245150726543040714721553361063311954285289857582079880295199632757829525723874753306371990452491305564061051059885803

s = pow(hashedM, d, N)

print( '{:x}'.format(int(s)) )

```

And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img124.png)

Flag : 6ac9bb8f110b318a40ad8d7e57defdcce2652f5928b5f9b97c1504d7096d7af1d34e477b30f1a08014e8d525b14458b709a77a5fa67d4711bd19da1446f9fb0ffd9fdedc4101bdc9a4b26dd036f11d02f6b56f4926170c643f302d59c4fe8ea678b3ca91b4bb9b2024f2a839bec1514c0242b57e1f5e77999ee67c450982730252bc2c3c35acb4ac06a6ce8b9dbf84e29df0baa7369e0fd26f6dfcfb22a464e05c5b72baba8f78dc742e96542169710918ee2947749477869cb3567180ccbdfe6fdbe85bcaca4bf6da77c8f382bb4c8cd56dee43d1290ca856318c97f1756b789e3cac0c9738f5e9f797314d39a2ededb92583d97124ec6b313c4ea3464037d3

<br/>

# Factoring (Primes Part 1)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img125.png)

As shown in the image above, I had to find the two prime factors for 510143758735509025530880200653196460532653147. To do that, I used this <a href="http://factordb.com/index.php?query=510143758735509025530880200653196460532653147" target="_blank">website</a>. So the smaller prime factor is 19704762736204164635843.

Flag : 19704762736204164635843
