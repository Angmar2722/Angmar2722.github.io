---
layout: page
title: Block Ciphers - AES / Block Cipher Modes
---
<hr/>

The Block Ciphers section consists of 22 challenges. The challenges are subdivided into 9 different stages : AES, Block Cipher Modes, ECB, CBC, OFB, CTR, GCM, Other Modes and Other Ciphers. Below are the writeups for the ones I managed to complete for the AES and Block Cipher Modes sections :

<br/>

# Keyed Permutations (AES)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img56.png)

As shown in the image above, I just had to enter the mathematical term for a one-to-one correspondence, a bijection.

**Flag :** crypto{bijection}

<br/>

# Resisting Bruteforce (AES)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img57.png)

As shown in the image above, I just had to enter the name of the best current single-key attack against AES which is a Biclique attacl..

**Flag :** crypto{Biclique}

<br/>

# Structure of AES (AES)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img58.png)

As shown in the image above, I just had to convert the matrix of ASCII characters back to a 16 byte string. 

Original code provided :

```python

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    ????

matrix = [
    [99, 114, 121, 112],
    [116, 111, 123, 105],
    [110, 109, 97, 116],
    [114, 105, 120, 125],
]

print(matrix2bytes(matrix))

```

New Code :

```python

def matrix2bytes(matrix):
    text = ""
    for i in range ( len(matrix) ):
        for j in range ( len(matrix[i]) ):
            text = text + chr(matrix[i][j]  )
    print(text)

matrix = [
    [99, 114, 121, 112],
    [116, 111, 123, 105],
    [110, 109, 97, 116],
    [114, 105, 120, 125],
]

print(matrix2bytes(matrix))

```

And after running the prgram, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img59.png)

**Flag :** crypto{inmatrix}

<br/>

# Round Keys (AES)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img60.png)

As shown in the image above, I just had to XOR each byte of the current state with the corresponding byte of the round key and then use the matrix2bytes function from the previous challenge to output the string (the flag).

Original Code Provided :

```python

state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]


def add_round_key(s, k):
    ???


print(add_round_key(state, round_key))

```

New Code :

```python

state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]

def matrix2bytes(matrix):
    text = ""
    for i in range ( len(matrix) ):
        for j in range ( len(matrix[i]) ):
            text = text + chr(matrix[i][j]  )
    print(text)

def add_round_key(s, k):
    newMatrix = list( list( 0 for i in range ( len(s) ) ) for i in range( len(s) ) )
    for i in range ( len(s) ):
        for j in range ( len(s[i]) ):
            newMatrix[i][j] = s[i][j] ^ k[i][j]
    newMatrix = matrix2bytes(newMatrix)
    print(newMatrix)

print(add_round_key(state, round_key))

```

And after running the prgram, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img61.png)

**Flag :** crypto{r0undk3y}

