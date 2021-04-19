---
layout: page
title: Introduction
---
<hr/>

The introduction consists of 3 challenges. 

<br/>

# Finding Flags 

As shown in the image below, all you had to do was input the flag `crypto{y0ur_f1rst_fl4g}` into the submit box. So it seems that the flag format for all the cryptoHack challenges is `crypto{flag}`.

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img4.png)

**Flag :** crypto{y0ur_f1rst_fl4g}

<br/>

# Great Snakes 

As shown in the image below, all you had to do was run the Great Snakes python program and then you would obtain the flag.

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img5.png)

The source code of the program : 

```python

#!/usr/bin/env python3

import sys
# import this

if sys.version_info.major == 2:
    print("You are running Python 2, which is no longer supported. Please update to Python 3.")

ords = [81, 64, 75, 66, 70, 93, 73, 72, 1, 92, 109, 2, 84, 109, 66, 75, 70, 90, 2, 92, 79]

print("Here is your flag:")
print("".join(chr(o ^ 0x32) for o in ords))

```

The flag is obtained after running the program :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img6.png)

**Flag :** crypto{z3n_0f_pyth0n}

<br/>

# Network Attacks 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img7.png)

