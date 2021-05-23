---
layout: page
title: Mathematics - Modular Math / Lattices
---
<hr/>

The Mathematics section consists of 22 challenges. The challenges are subdivided into 6 different stages : Modular Math, Lattices, Probability, Brainteasers Part 1, Brainteasers Part 2 and Primes. Below are the writeups for the ones I managed to complete for the Modular Math and Lattices sections :

<br/>

# Quadratic Residues (Modular Math)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img47.png)

As shown in the image above, I have to first find out which of the numbers 14,6 and 11 is a quadratic residue when the modulo is p = 29. It turns out that only 6 is a quadratic residue. Then the challenge says that the flag is the smaller corresponding root to the quadratic residue 6. 

I wrote a program for calculating the quadratic residue for corresponding roots : 

```python

#!/usr/bin/env python3

#x^2 congruent to c mod(p)

p = 29

for i in range (p):
    temp = (i*i) % p
    print((i), " squared mod 5 is : ", temp)

```

When I run my program as shown below, the corresponding roots to a quadratic residue of 6 is 8 and 21. Therefore the flag is 8.

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img48.png)

**Flag :** 8
