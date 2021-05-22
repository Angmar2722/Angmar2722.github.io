---
layout: page
title: General - Mathematics / Data Formats
---
<hr/>

The geneal section consists of 18 challenges. The challenges are subdivided into 4 different stages : Encoding, XOR, Mathematics and Data Formats. Below are the writeups for the ones I managed to complete for the Mathematics and Data Format sections :

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

```python3

#!/usr/bin/env python

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

