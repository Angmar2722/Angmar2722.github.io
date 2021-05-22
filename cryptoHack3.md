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

```python

#!/usr/bin/env python3

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

<br/>

# Modular Arithmetic 1 (Mathematics)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img35.png)

As shown in the image above, I had to calculate a and b and the flag is the smaller of the two integers (a and b). If a is congruent to b mod m, then b = a % m (as explained in the image above). So doing that for the two integers I got 5 and 4 respectively. So the flag was 4 (the smaller integer). Shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img36.png)

**Flag :** 4

<br/>

# Modular Arithmetic 1 (Mathematics)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img37.png)

`3^17 mod 17` gives 3, `5^17 mod 17` gives 5, `7^16 mod 17` gives 1. So `273246787654^65536 mod 65537` gives 1.

**Flag :** 1

<br/>

# Modular Inverting (Mathematics)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img38.png)

3*9 mod 13 gives 1 as 27 mod 13 gives 1. Therefore the flag is 9.

**Flag :** 9

<br/>

# Privacy-Enhanced Mail? (Data Formats)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img39.png)

As shown in the image above, I have to convert the given PEM file (a base 64 encoded DER file) into a DER file in order to access the private exponent "d" of the private RSA key, which is the flag.

Image of the contents of the PEM file :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img41.png)

This <a href="https://www.cryptologie.net/article/260/asn1-vs-der-vs-pem-vs-x509-vs-pkcs7-vs/" target="_blank">link</a> they gave explains the different TLS certificate formats (including DER and ASN.1). I found this <a href="https://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file" target="_blank">answer</a> explaining what a PEM file is to be very useful too.

The Python cryptography documentation was also very useful :
* <a href="https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
" target="_blank">Serialization</a>
* <a href="https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
" target="_blank">RSAPrivateKey</a>
* <a href="https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateNumbers
" target="_blank">RSAPrivateNumbers</a>

In order to convert the PEM file to a DER file and then extract the private exponent "d" I wrote the following code :

```python

#!/usr/bin/env python3
 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key
 
with open("privacy_enhanced_mail_1f696c053d76a78c2c531bb013a92d4a.pem", "rb") as keyfile:

    # Load the PEM format key
    pemkey = serialization.load_pem_private_key(
       keyfile.read(),
       None,
       default_backend()
    )

    # Serialize it to DER format
    derkey = pemkey.private_bytes(
       serialization.Encoding.DER,
       serialization.PrivateFormat.TraditionalOpenSSL,
       serialization.NoEncryption()
    )

    key = load_der_private_key(derkey, password=None)
    print(isinstance(key, rsa.RSAPrivateKey))
    pn = key.private_numbers()
    print(pn.d)
  
```

And after running the program I got the flag (the int private exponent "d") :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img40.png)

**Flag :** 15682700288056331364787171045819973654991149949197959929860861228180021707316851924456205543665565810892674190059831330231436970914474774562714945620519144389785158908994181951348846017432506464163564960993784254153395406799101314760033445065193429592512349952020982932218524462341002102063435489318813316464511621736943938440710470694912336237680219746204595128959161800595216366237538296447335375818871952520026993102148328897083547184286493241191505953601668858941129790966909236941127851370202421135897091086763569884760099112291072056970636380417349019579768748054760104838790424708988260443926906673795975104689

