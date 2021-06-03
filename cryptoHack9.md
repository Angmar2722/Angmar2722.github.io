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

