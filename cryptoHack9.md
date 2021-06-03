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


