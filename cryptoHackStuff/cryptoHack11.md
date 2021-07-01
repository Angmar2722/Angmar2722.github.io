---
layout: page
title: Diffie-Hellman - Starter / Man In The Middle / Group Theory / Misc
---
<hr/>

The Diffie-Hellman section consists of 14 challenges. The challenges are subdivided into 4 different stages : Starter, Man In The Middle, Group Theory and Misc. Below are the writeups for the ones I managed to complete for the Starter, Man In The Middle, Group Theory and Misc sections :

<br/>

# Diffie-Hellman Starter 1 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img170.png)

I had to find the modular multiplicative inverse of 209 with respect to the prime 991, which I did so using the Crypto.Util.number library :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img171.png)

<p> <b>Flag :</b> 569 </p>

<br/>

# Diffie-Hellman Starter 2 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img172.png)

I had to find the smallest generator for the finite field where p equalled 28151.

Solve script :

```python

p = 28151

def order(g, p): 
    for i in range(2, p): 
        if pow(g, i, p) == g:
            return i
    return p

for i in range(2,p):
    o = order(i, p)
    if o == p:
        print(i)
        break
        
```

<p> <b>Flag :</b> 7 </p>

<br/>

# Diffie-Hellman Starter 3 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img173.png)

Calculate `g^a mod p` given all 3 parameters.

<p> <b>Flag :</b> 1806857697840726523322586721820911358489420128129248078673933653533930681676181753849411715714173604352323556558783759252661061186320274214883104886050164368129191719707402291577330485499513522368289395359523901406138025022522412429238971591272160519144672389532393673832265070057319485399793101182682177465364396277424717543434017666343807276970864475830391776403957550678362368319776566025118492062196941451265638054400177248572271342548616103967411990437357924 </p>

<br/>

# Diffie-Hellman Starter 4 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img174.png)

The shared secret (s) equals A^b mod p.

<p> <b>Flag :</b> 1174130740413820656533832746034841985877302086316388380165984436672307692443711310285014138545204369495478725102882673427892104539120952393788961051992901649694063179853598311473820341215879965343136351436410522850717408445802043003164658348006577408558693502220285700893404674592567626297571222027902631157072143330043118418467094237965591198440803970726604537807146703763571606861448354607502654664700390453794493176794678917352634029713320615865940720837909466 </p>

<br/>

# Diffie-Hellman Starter 5 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img175.png)

Two files were given.

Source.py :

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
from secret import shared_secret

FLAG = b'crypto{????????????????????????????}'


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data


print(encrypt_flag(shared_secret))

```

And this was decrypt.py :

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
from secret import shared_secret

FLAG = b'crypto{????????????????????????????}'


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data


print(encrypt_flag(shared_secret))

```

The shared secret was the AES key which I could use to decrypt the ciphertext (encrypted flag). My solve script :

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

g = 2
p = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
A = 112218739139542908880564359534373424013016249772931962692237907571990334483528877513809272625610512061159061737608547288558662879685086684299624481742865016924065000555267977830144740364467977206555914781236397216033805882207640219686011643468275165718132888489024688846101943642459655423609111976363316080620471928236879737944217503462265615774774318986375878440978819238346077908864116156831874695817477772477121232820827728424890845769152726027520772901423784
b = 197395083814907028991785772714920885908249341925650951555219049411298436217190605190824934787336279228785809783531814507661385111220639329358048196339626065676869119737979175531770768861808581110311903548567424039264485661330995221907803300824165469977099494284722831845653985392791480264712091293580274947132480402319812110462641143884577706335859190668240694680261160210609506891842793868297672619625924001403035676872189455767944077542198064499486164431451944
B = 1241972460522075344783337556660700537760331108332735677863862813666578639518899293226399921252049655031563612905395145236854443334774555982204857895716383215705498970395379526698761468932147200650513626028263449605755661189525521343142979265044068409405667549241125597387173006460145379759986272191990675988873894208956851773331039747840312455221354589910726982819203421992729738296452820365553759182547255998984882158393688119629609067647494762616719047466973581

encrypted_flag = "39c99bf2f0c14678d6a5416faef954b5893c316fc3c48622ba1fd6a9fe85f3dc72a29c394cf4bc8aff6a7b21cae8e12c"
iv = '737561146ff8194f45290f5766ed6aba'
key = pow(A, b, p)

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))

def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

print(decrypt_flag(key, iv, encrypted_flag))

```

<p> <b>Flag :</b> crypto{sh4r1ng_s3cret5_w1th_fr13nd5} </p>


