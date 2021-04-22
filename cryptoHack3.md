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

