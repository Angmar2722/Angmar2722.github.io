---
layout: page
title: Introduction
---
<hr/>

The introduction consisted of 3 challenges. The first challenge involved submitting the flag `crypto{y0ur_f1rst_fl4g}`. The second challenge involved running a python scipt and obtaining the flag. This is shown in the image below (the image shows the first two challenges) :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img4.png)

The source code for the second challenge :

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

The flag obtained after running the program :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img5.png)

