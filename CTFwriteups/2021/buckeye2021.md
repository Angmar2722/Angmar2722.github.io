---
layout: page
title: Buckeye 2021 CTF Writeup
---
<hr/>

![Buckeye 2021 CTF Writeup](/assets/img/ctfImages/2021/buckeye2021/logo.png)

I participated in <a href="https://ctftime.org/event/1434" target="_blank">Ohio State University's Buckeye CTF 2021</a> event, playing as part of Social Engineering Experts over the weekend (Sat, 23 Oct. 2021, 08:00 SGT — Mon, 25 Oct. 2021, 08:00 SGT). The CTF went really well for us and this is my best performance in terms of ranking in any CTF that I have gone for yet. In the end we ranked 7<sup>th</sup> out of 505 scoring teams.

![Buckeye 2021 CTF Writeup](/assets/img/ctfImages/2021/buckeye2021/scoreboard.png)

I managed to sweep all the crypto challenges and even got a first blood. I also learnt about how neural networks work at a very high level while solving the 'Neurotic' reverse engineering challenge with Diamondroxxx. Overall it was a pretty fun CTF. Note that the challenges marked as 'easy' started out at 100 points whilst the other challenges started at 500 points. On a side note, the site used the <a href="https://github.com/redpwn/rctf" target="_blank">rctf</a> platform which looks minimalist and gorgeous! 

Below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[Pseudo](#pseudo) | Crypto | 476 | 15 | 
|[Super VDF](#super-vdf) | Crypto | 476 | 15 | 
|[Elliptigo](#elliptigo) | Crypto | 465 | 21 | 
|[Neurotic](#neurotic) | Rev | 441 | 33 | 
|[Defective RSA](#defective-rsa) | Crypto | 441 | 33 | 
|[Key Exchange 2](#key-exchange-2) | Crypto | 90 | 34 | 
|[Ret4win](#ret4win) | Pwn | 90 | 58 | 
|[Buttons](#buttons) | Rev | 85 | 166 | 
|[Key Exchange](#key-exchange) | Crypto | 40 | 141 | 
|[Survey](#survey) | Crypto | 1 | 52 | 
|[Sanity Check](#sanity-check) | Misc | 1 | 426 | 

<br/>

<br/>

## Pseudo

![Buckeye 2021 CTF Writeup](/assets/img/ctfImages/2021/buckeye2021/img1.png)

The server source Code provided :

```python

#!/usr/bin/env python3
import random
import os

rand = random.SystemRandom()
FLAG = b"buckeye{?????????????????????}"


def is_prime(n, rounds=32):
    return all(pow(rand.randrange(2, n), n - 1, n) == 1 for _ in range(rounds))


class RNG:
    def __init__(self, p: int, a: int):
        self.p = p
        self.a = a

    def next_bit(self) -> int:
        ans = pow(self.a, (self.p - 1) // 2, self.p)
        self.a += 1
        return int(ans == 1)

    def next_byte(self) -> int:
        ans = 0
        for i in range(8):
            ans |= self.next_bit() << i
        return ans

    def next_bytes(self, n: int) -> bytes:
        return bytes(self.next_byte() for _ in range(n))


def main():
    p = int(input("Give me a prime number: "))

    if not (256 <= p.bit_length() <= 512):
        print("Wrong bit length")
        return

    if not is_prime(p):
        print("Fermat tells me your number isn't prime")
        return

    a = rand.randrange(2, p)
    rng = RNG(p, a)

    plaintext = b"Hello " + os.urandom(48).hex().encode()
    print("Have some ciphertexts:")

    for _ in range(32):
        s = rng.next_bytes(len(plaintext))
        c = bytes(a ^ b for a, b in zip(s, plaintext))
        print(c.hex())

    if plaintext == input("Guess the plaintext:\n").encode():
        print(f"Congrats! Here's the flag: {FLAG}")
    else:
        print("That's wrong")


main()

```
