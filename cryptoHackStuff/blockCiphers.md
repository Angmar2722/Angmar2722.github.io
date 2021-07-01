---
layout: page
title: Block Ciphers 
---
<hr/>

The Block Ciphers section consists of 22 challenges. The challenges are subdivided into 9 different stages : AES, Block Cipher Modes, ECB, CBC, OFB, CTR, GCM, Other Modes and Other Ciphers. Below are the writeups for the challenges that I managed to complete for this section :

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

<br/>

# Confusion through Substitution (AES)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img62.png)

As shown in the image above, I have to use the given state (matrix of 16 bytes) and pass it into the inverse s-box to fetch the corresponding values and then use the matrix2bytes function made previously in order to obtain the string (the flag).

This <a href="https://www.youtube.com/watch?v=ib8brFaU9O0" target="_blank">video</a> does a pretty good job of explaining how the Rijndael S-Box and its inverse works for encryption/decryption.

Original Code Provided :

```python

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

state = [
    [251, 64, 182, 81],
    [146, 168, 33, 80],
    [199, 159, 195, 24],
    [64, 80, 182, 255],
]


def sub_bytes(s, sbox=s_box):
    ???


print(sub_bytes(state, sbox=inv_s_box))

```

So what I have to do is first convert each integer in the state into a hexadecimal and then split that byte into 2 nibbles where the first nibble corresponds to the row in the inverse S-box and the second nibble corresponds to the column. Then I have to add this corresponding value to a new matrix and then after iterating through all 16 bytes of the original state, I could pass this new state into the previously written matrix2bytes function in order to obtain the flag.

The code I wrote :

```python

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    (0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB),
    (0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB),
    (0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E),
    (0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25),
    (0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92),
    (0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84),
    (0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06),
    (0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B),
    (0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73),
    (0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E),
    (0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B),
    (0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4),
    (0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F),
    (0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF),
    (0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61),
    (0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D),
)

state = [
    [251, 64, 182, 81],
    [146, 168, 33, 80],
    [199, 159, 195, 24],
    [64, 80, 182, 255],
]

def matrix2bytes(matrix):
    text = ""
    for i in range ( len(matrix) ):
        for j in range ( len(matrix[i]) ):
            text = text + chr(matrix[i][j]  )
    print(text)

newMatrix = list( list( 0 for i in range ( len(state) ) ) for i in range( len(state[0]) ) )

def sub_bytes(s, sbox=s_box):
    for i in range ( len(s) ):
        for j in range ( len(s[i]) ):
            temp = str('{:x}'.format( s[i][j] )).upper()
            sbox_row = int(temp[0], 16)
            sbox_column = int(temp[1], 16)
            newValue = inv_s_box[sbox_row][sbox_column]
            newMatrix[i][j] = newValue
    matrix2bytes(newMatrix)

print(sub_bytes(state, sbox=inv_s_box))

``` 
And after running this program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img63.png)

**Flag :** crypto{l1n34rly}

<br/>

# Diffusion through Permutation (AES)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img64.png)

As shown in the image above, the functionality for the mix columns/shift rows and inverse mix columns is already implemented. I am supposed to create the function for the inverse shift row and after making that I should take the state, run inv_mix_columns on it, then inv_shift_rows, convert to bytes using matrix2bytes and then get the flag.

Original Code Provided : 

```python

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    ???


# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


state = [
    [108, 106, 71, 86],
    [96, 62, 38, 72],
    [42, 184, 92, 209],
    [94, 79, 8, 54],
]

```

My code :

```python

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


state = [
    [108, 106, 71, 86],
    [96, 62, 38, 72],
    [42, 184, 92, 209],
    [94, 79, 8, 54],
]

def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def matrix2bytes(matrix):
    text = ""
    for i in range ( len(matrix) ):
        for j in range ( len(matrix[i]) ):
            text = text + chr(matrix[i][j]  )
    print(text)

inv_mix_columns(state)
inv_shift_rows(state)
matrix2bytes(state)

```

And after running the program you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img65.png)

**Flag :** crypto{d1ffUs3R}

<br/>

# Bringing It All Together (AES)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img66.png)

As shown in the image above, I am supposed to construct a program to decrypt the AES-128 ciphertext (with the provided key and key expansion algorithm) by using the previous challenge solutions. 

Original Code Provided :

```python

N_ROUNDS = 10

key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'



def expand_key(master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    columns_per_iteration = len(key_columns)
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]


def decrypt(key, ciphertext):
    round_keys = expand_key(key) # Remember to start from the last round key and work backwards through them when decrypting

    # Convert ciphertext to state matrix

    # Initial add round key step

    for i in range(N_ROUNDS - 1, 0, -1):
        pass # Do round

    # Run final round (skips the InvMixColumns step)

    # Convert state matrix to plaintext

    return plaintext


# print(decrypt(key, ciphertext))

```
I followed the diagram they provided in the image and started in reverse order. A few modifications to my previous functions such as sub_bytes and add_round_key because I realized that instead of creating a new list, I could just modify the existing state (list / matrix). My code :

```python

N_ROUNDS = 10

key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

def expand_key(master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    columns_per_iteration = len(key_columns)
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

def add_round_key(s, k):
    for i in range ( len(s) ):
        for j in range ( len(s[i]) ):
            s[i][j] = s[i][j] ^ k[i][j]

def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

inv_s_box = (
    (0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB),
    (0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB),
    (0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E),
    (0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25),
    (0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92),
    (0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84),
    (0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06),
    (0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B),
    (0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73),
    (0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E),
    (0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B),
    (0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4),
    (0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F),
    (0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF),
    (0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61),
    (0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D),
)

def matrix2bytes(matrix):
    text = ""
    for i in range ( len(matrix) ):
        for j in range ( len(matrix[i]) ):
            text = text + chr(matrix[i][j]  )
    return text

def sub_bytes(s, sbox=s_box):
    for i in range ( len(s) ):
        for j in range ( len(s[i]) ):
            temp = str('{:x}'.format( s[i][j] )).upper()
            if ( len(temp) == 1 ):
                temp = "0" + temp
            sbox_row = int(temp[0], 16)
            sbox_column = int(temp[1], 16)
            newValue = inv_s_box[sbox_row][sbox_column]
            s[i][j] = newValue

# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)
    

def decrypt(key, ciphertext):
    round_keys = expand_key(key) # Remember to start from the last round key and work backwards through them when decrypting

    # Convert ciphertext to state matrix
    state = bytes2matrix(ciphertext)

    # Initial add round key step
    currentMatrix = add_round_key(state, round_keys[N_ROUNDS])

    for i in range(N_ROUNDS - 1, 0, -1):
        inv_shift_rows(state)
        sub_bytes(state, sbox=inv_s_box)
        add_round_key(state, round_keys[i] )
        inv_mix_columns(state)

    # Run final round (skips the InvMixColumns step)
    inv_shift_rows(state)
    sub_bytes(state, sbox=inv_s_box)
    add_round_key(state, round_keys[0] )

    # Convert state matrix to plaintext
    plaintext = matrix2bytes(state)
    return plaintext

flag = decrypt(key, ciphertext)
print(flag)

```

And after running the program you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img67.png)

**Flag :** crypto{MYAES128}

<br/>

# Block Cipher Mode Starter (Block Cipher Modes)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img68.png)

When you go the <a href="http://aes.cryptohack.org/block_cipher_starter/" target="_blank">link</a> shown in the image above, it takes you to a page which describes the challenge, shows the source code, has functions for interacting with the code and displaying output as well as useful debugging tools :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img69.png)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img70.png)

When I cliked on `Encrypt_Flag()`, it gave me a hex encoded ciphertext :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img71.png)

I then passed that ciphertext into the `decrypt` function and got some hex encoded data :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img72.png)

And after using the ASCII-hex conversion tool on the page, I got the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img73.png)

**Flag :** crypto{bl0ck_c1ph3r5_4r3_f457_!}

<br/>

# Passwords as Keys (Block Cipher Modes)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img74.png)

When you go the <a href="http://aes.cryptohack.org/passwords_as_keys/" target="_blank">link</a> shown in the image above, it takes you to a page which describes the challenge, shows the source code, has functions for interacting with the code and displaying output as well as useful debugging tools, just like the last challenge. 

Source Code Provided :

```python

from Crypto.Cipher import AES
import hashlib
import random


# /usr/share/dict/words from
# https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
with open("/usr/share/dict/words") as f:
    words = [w.strip() for w in f.readlines()]
keyword = random.choice(words)

KEY = hashlib.md5(keyword.encode()).digest()
FLAG = ?


@chal.route('/passwords_as_keys/decrypt/<ciphertext>/<password_hash>/')
def decrypt(ciphertext, password_hash):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/passwords_as_keys/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}
    
```
First, I used `Encrypt_Flag()` function to get the flag ciphertext. Then I used looped through each word in the dictionary and for each word, converted it to its md5 hash and then inputted this flag ciphertext and hash into the `decrypt` function provided. I then compared the decoded string (I had to decode in latin-1 as opposed to utf-8) to the the flag format "crypto{". If it matched, I would print the flag.

My code : 

```python

from Crypto.Cipher import AES
import hashlib
import random

flagCipherText = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"

# /usr/share/dict/words from
# https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
with open("/usr/share/dict/words") as f:
    words = [w.strip() for w in f.readlines()]

def decrypt(ciphertext, password_hash):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return decrypted.hex()

for i in range ( len(words) ):
    keyword = words[i]
    keyGuess = hashlib.md5(keyword.encode()).digest()
    keyGuess = keyGuess.hex()
    guessFlag = decrypt(flagCipherText, keyGuess)
    decoded = bytes.fromhex(guessFlag).decode('latin-1')
    if (decoded.isprintable() and decoded[0] == "c" and decoded[1] == "r" and decoded[2] == "y" and decoded[3] == "p" and decoded[4] == "t" and decoded[5] == "o" and decoded[6] == "{"):
        print(decoded)

```

And after running the program, I got the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img75.png)

**Flag :** crypto{k3y5__r__n07__p455w0rdz?}

<br/>

# ECB Oracle (ECB)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img76.png)

When you go the <a href="http://aes.cryptohack.org/ecb_oracle/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

Source Code Provided :

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


KEY = ?
FLAG = ?


@chal.route('/ecb_oracle/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}

    return {"ciphertext": encrypted.hex()}

```

So this program is running on a server where based on a given input (plaintext), it returns an encryped ciphertext in hex. The encryption used is AES and the mode of operation is ECB (electronic codebook) which has many, many vulnerabilities.

Before I learnt how to crack this challenge, I needed to learn how to communicate with the server. To do that, I used the `requests` package in Python. Here is a <a href="https://docs.python-requests.org/en/master/user/quickstart/#make-a-request" target="_blank">link</a> to the quickstart documentation for using requests. This <a href="https://www.youtube.com/watch?v=Rk0NIQfEXBA" target="_blank">video</a> from Computerphile explains popular modes of operation really well while this <a href="https://www.youtube.com/watch?v=R3NosHMSi0o" target="_blank">video</a> explains how padding and the cryptographic message syntax (CMS) works.

So to solve this challenge, I have to exploit the fact that ECB takes in a block of bytes (16 bytes in the case of AES) and then outputs the ciphertext after encryption it with the AES key. If the same plaintext (block of bytes) is inputted again, the same ciphertext would be outputted. So it is very easy to establish patterns amongst the ciphertext using ECB.

What I did was that I first tried to find the length of the flag. So when I give the encryption algorithm 1 byte of input ("00" in hex which is 1 byte), it gave me a ciphertext of length 64 in hex (32 bytes). So I created a loop which would have a counter which would be incremented and multiplied with the input "00" each time and then get the length of the resulting ciphertext until the original cipher length and new cipher length differed (so when the ciphertext changed from 32 bytes to 48 bytes). One thing I forgot was that when padding, if the last unoccupied byte (the 16th byte in a block) is occupied, it creates a new block of bytes. So if at the 7th byte (00000000000000 as the input) resulted in the output ciphertext of 48 bytes, it means that the 7th byte is the last byte which occupied the 32nd byte slot. I was overcounting my key length by one byte (so I was assuming that the key length was 26 bytes instead of the actual 25). To get the key length, I subtracted the counter (which was tracking the 00s input) from the original key length of 32 bytes (so 32-7 = 25, but I did 32-6 = 26 in my program).

Getting the key length wasn't the main part of solving the challenge. What I did was that I realized that the key was within 32 bytes (or 2 blocks) so if I used the input injected and prepended before the flag and focused on the 3rd block (bytes 33 - 48), I could get the flag one byte at a time. So say I input 47 bytes of zeroes into the encryption program, what it would do is add the 47 bytes and then add the flag (so the first byte of the flag would occupy the 48th byte slot) and so on, and then encrypt it and give the ciphertext. So if I added 47 zeroes and saw the ciphertext, the equivalent hex (ciphertext) would be 47 zeroes followed by the flag. Since I know that the flag format is "crypto{" ), this would be 47 zeroes followed by a "c" and so on. So if I restricted my outputted ciphertext to the 33rd to 48th bytes (the 3rd block), what I could do was input 47 zeroes and check the hex (ciphertext) and compare that to the ciphertext (hex) resulting from 47 zeroes and a readable/printable ASCII character (from 33 in decimal "!" to 126 in decimal, though in my program, I looped only till 125 as I assumed that the ASCII character 126 (the wavy line) would not be part of the flag). 

Now if I got the first byte of the flag, I could decrease my input to 46 zeroes and compare the resulting hex ciphertext to the ciphertext resulting from 46 zeroes and the first byte of the flag as well as an ASCII character (I used a loop to go from 33 to 126 in ASCII and if the hex ciphertext matched, that would be the byte of the flag). So each time I got an additonal byte of the flag, I could add it to the flag variable and then reduce the number of zeroes input by one, check the ciphertext and compare it with the ciphertext resulting from the equivalent reduced number of zeroes input along with the flag currently known as well as one byte for the ASCII character guess (the new byte of the flag to get). So each time, I am comparing two hex ciphertexts and if they match, the ASCII character which produced that hex is the byte of the flag. I am using the property of ECB where idential plaintexts yield idential ciphertexts with the same key, which highlights how unsafe ECB really is. Even though the AES is implemented correctly, the weakness of ECB allows me to get the flag.

It is important to note that I was only focusing on the third block and effectively moving the flag and zeroes input down by one each time. The program took around 31 minutes to run, clearly it could be optimized way, way more and reduce the runtime. And since I was using the wrong flag length (26 instead of 25), the program never stopped as I would only stop it if the flag length was 26 (so after getting the flag I had to exit manually). Next time, it would be better to put the correct flag length (obviously) and maybe even a check for the "}" as the closing brace is the last part of the flag in most challenges in CryptoHack and CTFs. So if I reached the closing brace, I could exit the program. Most of what I learnt came from <a href="https://godiego.tech/posts/AES-128-padding-attack/" target="_blank">this</a> excellent CTF writeup.

This is the code that I wrote (Flag length error is corrected in this version) :

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests

def getLength(guess):
    payloadURL = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + guess + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    return getCiphertextLengthInBytes( temp['ciphertext'] )

def getCiphertextLengthInBytes(ciphertext):
    return len(ciphertext) // 2

def getHex(guess):
    payloadURL = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + guess + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    temp = temp['ciphertext']
    return temp[64:96]

length = 0

def getFlagLength():
    c = 1
    guess = "00" * c
    originalLength = getLength(guess)
    print(originalLength)
    check = True
    c = 1
    while (check == True):
        guess = "00" * c
        length = getLength(guess)
        if(length == originalLength):
            c = c + 1
        elif (length != originalLength):
            #Originally wrote this (which increased flag length by 1) : c = c - 1
            check = False
            break
    return (originalLength - c)
        
#flagLength = getFlagLength() 
#print(flagLength)

flag = ""

end = True 

while (end == True):

    payload = "00"*(47-len(flag))
    hex = getHex(payload)

    for i in range(33, 126):
        temp = flag + chr(i)
        payload = "00"*(47-len(flag)) + temp.encode("utf-8").hex()
        if(hex == getHex(payload)):
            flag = flag + chr(i)
            print ("Flag: ", flag)
            if (len(flag) == flagLength):
                break
        if (len(flag) == flagLength):
            end = False

```

And after running the program, you slowly get the flag (I had to manually quit as my flag length was wrong, but the code still worked well enough) :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img77.png)

**Flag :** crypto{p3n6u1n5_h473_3cb}

I guess the "penguins hate ECB" flag relates to the iconic <a href="https://blog.filippo.io/the-ecb-penguin/" target="_blank">ECB Penguin</a>.

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img78.png)

<br/>

# ECB CBC WTF (CBC)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img81.png)

When you go the <a href="http://aes.cryptohack.org/ecbcbcwtf/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img80.png)

Original Code Provided :

```python

from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/ecbcbcwtf/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/ecbcbcwtf/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}

```

So what we have here is a decryption function using CBC (Cipher Block Chaining) and decryption using ECB. The diagram they provided was very useful. What I did was first divide the flag ciphertext into 3 blocks (16 bytes of 32 hex characters each). I passed in the last block into the decryption function and XORed that value with the second block of ciphertext (as that is how the cipher block chaining in CBC works). This would give me the last part of the flag. I then did the same thing, I passed in the second cipher block into the decrypt function and XORed that value with the first block of the flag cipher. By then the entirety of the flag was printed, I didn't even have to get the first block of plaintext!

The code that I wrote :

```python

import requests
import textwrap

def hexToInt(hexString):
    return int(hexString, 16)

def xor(x, y):
    return '{:x}'.format(x ^ y)

def getHex(input):
    payloadURL = "http://aes.cryptohack.org/ecbcbcwtf/decrypt/" + input + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    temp = temp['plaintext']
    return temp

flagCipher = "9c08a7f404a18e41792f3e0ba29c2ee211402550da530e5f877ab7b43be68ac287759e09226c9d8d2556e8d14cc20dfc"

flagCipherList = textwrap.wrap(flagCipher, 32)

halfStep = getHex(flagCipherList[2])
lastPlaintextBlock = xor( hexToInt(halfStep), hexToInt(flagCipherList[1]) )

flag = lastPlaintextBlock

halfStep = getHex(flagCipherList[1])
lastPlaintextBlock = xor( hexToInt(halfStep), hexToInt(flagCipherList[0]) )

flag = lastPlaintextBlock + flag

print(bytes.fromhex(flag).decode('utf-8'))

```
And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img79.png)

<p> <b>Flag :</b> crypto{3cb_5uck5_4v01d_17_!!!!!} </p>

<br/>

# Flipping Cookie (CBC)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img82.png)

When you go the <a href="http://aes.cryptohack.org/flipping_cookie/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img83.png)

Source Code Provided :

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta


KEY = ?
FLAG = ?


@chal.route('/flipping_cookie/check_admin/<cookie>/<iv>/')
def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}

    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}


@chal.route('/flipping_cookie/get_cookie/')
def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    cookie = f"admin=False;expiry={expires_at}".encode()

    iv = os.urandom(16)
    padded = pad(cookie, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()

    return {"cookie": ciphertext}

```

So the objective of this challenge is to change the admin parameter in the cookie from false to true. If that cookie (admin = true) along with the initialization vector (IV) is then inputted into the decrypt function, you get the flag. This kind of exploit is known as a CBC byte/bit flipping attack. This <a href="https://resources.infosecinstitute.com/topic/cbc-byte-flipping-attack-101-approach/" target="_blank">resource</a> beautifully explains how the attack works while the image below came from this <a href="https://crypto.stackexchange.com/questions/66085/bit-flipping-attack-on-cbc-mode" target="_blank">link</a>.

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img85.png)

So in order to get the flag, I have to change the previous block of ciphertext. But in this case, the first block contains the admin parameter and value so this means that I have to modify the IV. When you get the cookie by calling the get_cookie function, it returns 48 bytes of which the first 16 bytes is the IV, the next 16 is block 1 (which contains admin) and then the next 16 is block 2. Also, the text is padded but that only effects the second block as the original cookie size is 29 bytes and the padded cookie adds 3 extra bytes at the end of the second block. 

Suppose you are encrypting the first block using CBC and the resulting ciphertext is C1. When decrypting in CBC, the second block of plaintext (P2) is calculated by C1 XOR C2 (with C2 being the decrypted block from the input cipher of block 2). The byte flip attack is based on the fact that when you change a byte at a particular position in a preceding block (cipher block) and then XOR with the next block for getting the plaintext (like C1 XOR C2), the byte that you change in a ciphertext will ONLY affect a byte at the same offset of next plaintext. This means that if I changed the second byte of C1, when XORed with C2 to give P2, the second byte of P2 is changed. So if I do C1(some byte position) XOR C2(some byte position) XOR (some value which is in the known plaintext), that would give me 0 as C1 XOR C2 would yield the plaintext at the byte position specified and that plaintext XORed with the known plaintext at that position would give 0 (as 1 XOR 1 gives 0). And if that calculation ( C1(some position) XOR C2(some position) XOR (known value at the position) = 0) is XORed with a value that you want to change or flip to at that byte position, 0 XOR that value would yield that value. 

In this challenge, the first block is the one which has the admin parameter, so this means that instead of exploiting a previous cipher block, I need to exploit the IV itself (as shown in the image above) as the IV XOR C1 (decrypted first cipher block passed through) yields the plaintext. 

So in this case, the padded cookie is something like "admin=False;expiry=1622164029\x03\x03\x03" where block 1 would be "admin=False;expi". This means that the position of the false in admin=false is 6 to 10 (counting from 0, 10 inclusive). So I have to change the correspond bytes in the IV in order to change the admin parameter from false to true. But "false" is 5 bytes and "true" ins only 4, so in my code I added a ";" next to true as the decryption function in the server code splits the cookie based on the seperator ";". So for byte 7 (position 6) of the IV, I XORed the current IV byte at position 6 with the current value of plaintext (the "f" in false) and XORed that with the value of the plaintext that I do want (the "t" in true). So I did the same thing by looping through the 5 bytes and creating a new, exploited IV. So now if I passed that changed IV along with the untouched cookie into the decryption function in the server, what the code would do is IV(byte position) XOR Block 1 cipher(byte position) which gives the plaintext (as IV XOR C1 gives P1) and when that is XORed with the known value ("false"), each byte is 0 and then that is XORed with the value to be changed byte (the "true;") which gives the desired value. 

So the changed IV tricks the program into checking that yes, admin is equal to true and since that is the case, the flag is printed.

The code that I wrote :

```python

import requests
import textwrap
from datetime import datetime, timedelta
from Crypto.Util.Padding import pad, unpad
import binascii

def hexToInt(hexString):
    return int(hexString, 16)

def xor(x, y):
    return '{:x}'.format(x ^ y)

def decrypt(cookie, iv):
    payloadURL = "http://aes.cryptohack.org/flipping_cookie/check_admin/" + cookie + "/" + iv + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    flag = temp['flag']
    return flag

getCookieURL = "http://aes.cryptohack.org/flipping_cookie/get_cookie/" 
r = requests.get(getCookieURL)
temp = r.json()
cookie = temp['cookie']

cookieCipherList = textwrap.wrap(cookie, 32)
iv = cookieCipherList[0]

print("")
print("The IV is                             : ", iv)

expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
cookieTest = f"admin=False;expiry={expires_at}".encode()
print("Original Cookie Format                : ", cookieTest)
cookieTest = pad(cookieTest, 16)
print("Padded Cookie Format                  : ", cookieTest)

blockToExploit = cookieTest[0 : 16]
print("First block which should be exploited : ", blockToExploit)

print("The position of the 'false' in admin=false is 6 to 10 (10 inclusive)")

ivByteList = textwrap.wrap(iv, 2)

word = "false"
word2 = "true;"
c = 0

for i in range (6, 11):
    temp = xor(  ord(word[c]), ord(word2[c])  )
    temp2 = hexToInt(ivByteList[i])
    ivByteList[i] = xor(hexToInt(temp), temp2)
    c = c + 1

finalIV = ''.join(ivByteList)
print("Exploited IV to be injected           : ", finalIV)
print(finalIV)
print("")

flag =  decrypt(cookieCipherList[1] + cookieCipherList[2], finalIV)
print(flag)

```

And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img84.png)

**Flag :** crypto{4u7h3n71c4710n_15_3553n714l}

<br/>

# Lazy CBC (CBC)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img90.png)

When you go the <a href="http://aes.cryptohack.org/lazy_cbc/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img91.png)

Source Code Provided :

```python

from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/lazy_cbc/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)
    if len(plaintext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    encrypted = cipher.encrypt(plaintext)

    return {"ciphertext": encrypted.hex()}


@chal.route('/lazy_cbc/get_flag/<key>/')
def get_flag(key):
    key = bytes.fromhex(key)

    if key == KEY:
        return {"plaintext": FLAG.encode().hex()}
    else:
        return {"error": "invalid key"}


@chal.route('/lazy_cbc/receive/<ciphertext>/')
def receive(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    if len(ciphertext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    decrypted = cipher.decrypt(ciphertext)

    try:
        decrypted.decode() # ensure plaintext is valid ascii
    except UnicodeDecodeError:
        return {"error": "Invalid plaintext: " + decrypted.hex()}

    return {"success": "Your message has been received"}
    
```
So the objective of this challenge is to find the key as the key is used as the IV. This <a href="https://cedricvanrompay.gitlab.io/cryptopals/challenges/27.html" target="_blank">resource</a> beautifully explains how I could recover the IV given that the key is reused as the IV throughout the encryption process.

This image below (from the resource linked above) more or less explains what I have to do :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img92.png)

So I have three functions in this challenge. The first function encrypt allows me to input any plaintext (in hex) of my choosing and as long as it is an integral multiple of 16 (one block size), it will output the encrypted text (using the key as key as well as IV). So I can get any encrypted text from an appropriate plaintext. My second function get_flag takes in my key (IV - the terms key and IV will be used interchangeably in this challenge) and if it matches the actual key, it will print out the flag in hex. My third function is called receive and it takes in a ciphertext but it is really a decryption function. If the input ciphertext is an integral multiple of 16, then this function would process it in two ways. After decrypting the ciphertext, if the decreypted text is printable (if it is ASCII characters), it will print "Your message has been received". If the decrypted text is not printable, it will print "Invalid plaintext" and more importantly the decrypted hex. So I need to make sure that whatever I input into this receive function is not printable so that I can get the decrypted hex.

What the resource explained was that suppose I have three cipher blocks. Using CBC decryption, the first cipher block (C1) is decrypted with the key and then XORed with the IV and that gives the first plaintext block (P1). Moreover, the first cipher block is XORed with the decrypted second cipher block (C2) and that gives P2 and so on (as shown above). So we need to find the IV/key and we can get/control C1 (by using the encryption function) as well P1 (as that is what we input into the encrypt function). So P1 = decrypted C1 (DC1) XOR IV and hence IV = DC1 XOR P1. Now suppose C3 was the same as C1. So during decryption, DC1 (as C1 is decrypted) XOR C2 = P3. Now if C2 was equal to 0, this would be DC1 XOR 0 = P3 which is DC1 = P3. So if we get the encrypted cipher block for C1, we change C2 to 0 and we input C1 in the third block, we will get DC1 as that is P3. We can get P3 using the receive (basically decrypt) function assuming that the output is not printable (so that the decrypted hex is printed).

So what I did was first find 16 bytes of an unprintable hex so "12339312123393121233931212339312". I then passed 3 bytes of that into the encrypt function and got 3 cipher blocks. Now I made C2 = 0 and C3 = C1. After that, I passed these three cipher blocks into receive and then got 3 plaintext blocks (not really plaintext as not printable which is how we got the decrypted hex in the first place). So what I did was pass C1 in place of C3 and since C2 is 0, DC1 (in the third block) equals P3 (which is the third block output I got from receive). So now I have DC1. And since DC1 XOR IV = P1 (P1 is the first decrypted block of my output from receive), this means that the IV = DC1 XOR P1. So by controlling C1 and C2 and using P1 and P3 by using the encrypt and receive functions, I got the IV. Now all I had to do was pass this IV into the getFlag function, get the hex encoded flag, decode it to ASCII and then print out the flag.

The code that I wrote :

```python

from typing import final
import requests
import textwrap

def hexToInt(hexString):
    return int(hexString, 16)

def xor(x, y):
    return '{:x}'.format(x ^ y)

def encrypt(c):
    if len(c) % 16 != 0:
        return "Data length must be multiple of 16"
    payloadURL = "http://aes.cryptohack.org/lazy_cbc/encrypt/" + c + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    cipher = temp['ciphertext']
    return cipher

def receive(c):
    if len(c) % 16 != 0:
        return "Data length must be multiple of 16"
    payloadURL = "http://aes.cryptohack.org/lazy_cbc/receive/" + c + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    temp = temp['error'] 
    return temp[19:]

def getFlag(key):
    payloadURL = "http://aes.cryptohack.org/lazy_cbc/get_flag/" + key + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    return (temp['plaintext'] )

unprintableHex = "12339312123393121233931212339312"
encryptedBlocks = encrypt(unprintableHex*3)
encryptedBlockList = textwrap.wrap(encryptedBlocks, 32)
encryptedBlockList[1] = "0" * 32
encryptedBlockList[2] = encryptedBlockList[0]
encryptedBlocks = ''.join(encryptedBlockList)

temp = receive(encryptedBlocks)
temp = textwrap.wrap(temp, 32)
decryptedBlockOne = temp[2]

keyOrIV = xor(hexToInt(decryptedBlockOne), hexToInt(unprintableHex))

flag = getFlag(keyOrIV)
print(bytes.fromhex(flag).decode('utf-8'))

```

And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img93.png)

<p> <b>Flag :</b> crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?} </p>

<br/>

# Symmetry (OFB)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img86.png)

When you go the <a href="http://aes.cryptohack.org/symmetry/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img87.png)

Source Code Provided :

```python

from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/symmetry/encrypt/<plaintext>/<iv>/')
def encrypt(plaintext, iv):
    plaintext = bytes.fromhex(plaintext)
    iv = bytes.fromhex(iv)
    if len(iv) != 16:
        return {"error": "IV length must be 16"}

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(plaintext)
    ciphertext = encrypted.hex()

    return {"ciphertext": ciphertext}


@chal.route('/symmetry/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}
    
```

The way OFB (Output Feedback Mode) works is shown in the image below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img89.png)

So an IV is encrypted using a block cipher like AES (lets call this is the encrypted IV or eIV) and then XORed with the plaintext block in order to get the ciphertext block. And the next block uses the previous block's encrypted IV block (eIV) and encrypts that and XOrs it with the corresponding plaintext block to get the next ciphertext block and so on. So the block that gets encrypted is the IV instead of the plaintext (that is just XORed later with the encrypted IV).

So in our code, we have two functions. The encrypt_flag function returns the ciphertext of which the first 16 bytes is the IV and the next 33 bytes (so the last byte or 33rd byte is the "}" in the flag format "crypto{...}" ) is the flag. What we have to do is get each block's encrypted IV (eIV) and then XOR that with the corresponding ciphertext block which we got from encrypt_flag in order to get each block of the flag.

To get the first eIV, what you could do is create a dummy or test plaintext which you pass into the other encrypt function that they provided along with the IV used for the flag encryption in order to get some ciphertext. XORing that ciphertext block with the corresponding test plaintext block yields the eIV. You could do this for the next block as in this challenge, we are basically looking at 2 blocks or 32 bytes as the last byte is the "}". So the dummy plaintext block should be 32 bytes and when you XOR the second ciphertext block (which you get by passing the 32 byte dummy text into the encrypt function) with the second plaintext block from the test/dummy input, you get the next encrypted IV. So now that we have both encrypted IVs, we can XOR each eIV with the corresponding flag cipher block in order to get the flag. I used a loop to do this. And once we get the flag hex, we decode it to ASCII and add the "}" in order to get the complete flag.

The code that I wrote :

```python

import requests
import textwrap

def hexToInt(hexString):
    return int(hexString, 16)

def xor(x, y):
    return '{:x}'.format(x ^ y)

def encryptFlag():
    payloadURL = "http://aes.cryptohack.org/symmetry/encrypt_flag/" 
    r = requests.get(payloadURL)
    temp = r.json()
    return temp['ciphertext']

def getCipher(plaintext, iv):
    payloadURL = "http://aes.cryptohack.org/symmetry/encrypt/" + plaintext + "/" + iv + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    return temp['ciphertext']

receivedCipher = encryptFlag()
iv = receivedCipher[0:32]

flagCipher = receivedCipher[32:]
firstBlockFlagCipher = flagCipher[0:32]
secondBlockFlagCipher = flagCipher[32:64]
thirdBlockFlagCipher = flagCipher[64:]
blockFlagCipherList = [firstBlockFlagCipher, secondBlockFlagCipher, thirdBlockFlagCipher]

testPlaintext = ("peruperuperuperu"*2).encode("utf-8").hex()
testCiphertext = getCipher(testPlaintext, iv)
testCiphertextList = textwrap.wrap(testCiphertext, 32)

flag = ""

for i in range (2):
    eIV = xor(hexToInt(testCiphertextList[i]), hexToInt(testPlaintext[0:32]))
    flag = flag + xor(hexToInt(eIV), hexToInt(blockFlagCipherList[i]))

print(bytes.fromhex(flag).decode('utf-8') + "}")

```
And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img88.png)

<p> <b>Flag :</b> crypto{0fb_15_5ymm37r1c4l_!!!11!} </p>

<br/>

# Bean Counter (CTR)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img94.png)

When you go the <a href="http://aes.cryptohack.org/bean_counter/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img95.png)

Source Code Provided :

```python

from Crypto.Cipher import AES


KEY = ?


class StepUpCounter(object):
    def __init__(self, value=os.urandom(16), step_up=False):
        self.value = value.hex()
        self.step = 1
        self.stup = step_up

    def increment(self):
        if self.stup:
            self.newIV = hex(int(self.value, 16) + self.step)
        else:
            self.newIV = hex(int(self.value, 16) - self.stup)
        self.value = self.newIV[2:len(self.newIV)]
        return bytes.fromhex(self.value.zfill(32))

    def __repr__(self):
        self.increment()
        return self.value



@chal.route('/bean_counter/encrypt/')
def encrypt():
    cipher = AES.new(KEY, AES.MODE_ECB)
    ctr = StepUpCounter()

    out = []
    with open("challenge_files/bean_flag.png", 'rb') as f:
        block = f.read(16)
        while block:
            keystream = cipher.encrypt(ctr.increment())
            xored = [a^b for a, b in zip(block, keystream)]
            out.append(bytes(xored).hex())
            block = f.read(16)

    return {"encrypted": ''.join(out)}
    
```

So how CTR (counter) mode works is that a nonce (something like an IV) is used where for the first block of data, a nonce is fed into the encryption algorithm and the resulting encrypted nonce is XORed with the plaintext. For the next block of data, the nonce is incremented by one, fed into the encryptor and this encrypted nonce is XORed with the second block of plaintext and so on. So instead of encrypting the plaintext, in CTR mode, the nonce is encrypted and incremented for the next block.

In the source code provided, we have a function `encrypt()` which encrypts the bytes of the `bean_flag.png` file and outputs the ciphertext as well as a poorly written `StepUpCounter` class.

The cipher is generated using ECB and a `ctr` object (initialized in the encrypt function) is created from the `StepUpCounter` class. The glaringly obvious mistake is evident in the code for this class. When the `ctr` object is created In the encrypt function), no initialization value is passed in so in the `init` function for the class, the default value of os.urandom(16) is used for the `value` attribute and the default value of false is used for the `step_up` parameter. When the `increment` function is called for this class, since the `ctr` object has initialized `step_up` as false, for increment, `self.newIV = hex(int(self.value, 16) - self.stup)` as the self.stup != true but rather false. And since you are subtracting self.stup which is false from the value and converting that to hex, that is effectively just the value and nothing changes as value - false equals value. This value in hex is also the newIV and this is returned. The zfill function simply adds zeroes to the left of the string until the string is equal to the width specified in zfill. So increment is returning the same value each time.

Since the ctr object is initialized outside the opening of the bean_flag image file, it means that a single value (the 16 byte os.urandom) is initialized. This same is value is used again and again each time 16 bytes (a block) is read from the imgae. So each time a block is read, the keystream parameter is just the same encrypted value passed from the StepUpCounter (so this is the encrypted nonce or IV or whatever you want to call it). This same eIV (I am calling it an encrypted IV) is used again and again (reused) and each byte of it is XORed with a corresponding byte from the image using the zip function. So the first byte of eIV is XORed with the first byte of the block read, second byte of eIV is XORed with the second byte of the block currently being read and so on.

In this program, ECB is used to encrypt the IV to give eIV but this program still behaves like a ctr mode because this eIV is then XORed with the plaintext (the image flag bytes) to give corresponding ciphertext blocks. So if eIV XOR plaintext block gives ciphertext block, and since I know the ciphertext block (as the encrypt function outputs that), if I can find eIV, I can do eIV XOR ciphertext block to get the corresponding plaintext block (the image flag bytes in this case).

So we know that the image is a PNG file. In a PNG file, the first 16 bytes are always the same, they have a standard header ( b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'). I checked this when I ran my program and tested it with two different PNGs and printed out the first 16 bytes. So if the first 16 bytes are the same for all PNGs, we can get the first plaintext block (this header). So I can get the eIV as eIV = P1 (first plaintext block) XOR C1 (the first ciphertext block we received from encrypt). So now that we have eIV, I can XOR each ciphertext block with the eIV to get the corresponding plaintext block. I also used zfill(32) incase the decrypted block (the plaintext) was not 32 hex characters (or 16 bytes). I then created a new image file from this decrypted block and then got the flag when I opened that image file.

The code that I wrote :

```python

import requests
import textwrap

def hexToInt(hexString):
    return int(hexString, 16)

def xor(x, y):
    return '{:x}'.format(x ^ y)

def encrypt():
    payloadURL = "http://aes.cryptohack.org/bean_counter/encrypt/"
    r = requests.get(payloadURL)
    temp = r.json()
    cipher = temp['encrypted']
    return cipher

def test():
    with open("bean_flag.png", 'rb') as f:
        block = f.read(16)
        print("The first 16 bytes (block) of a png is : ", block)

def test2():
    with open("bean_flag2.png", 'rb') as f:
        block = f.read(16)
        print("The first 16 bytes (block) of a png is : ", block)
        return block.hex()

test()
test2()

ciphertext = encrypt()
firstBlockOfCipherText = ciphertext[0:32]
plaintextPNGFirstBlockHex = test2()

eIV = xor(hexToInt(plaintextPNGFirstBlockHex), hexToInt(firstBlockOfCipherText))
ciphertextList = textwrap.wrap(ciphertext, 32)

decrypted = ""

for i in range(len(ciphertextList)):
    temp = xor(hexToInt(ciphertextList[i]), hexToInt(eIV))
    temp = temp.zfill(32)
    decrypted = decrypted + temp

with open('image.png', 'wb') as file:
    file.write(bytes.fromhex(decrypted))
    
```

When you run the program, you can see that the first 16 bytes are the same for different PNGs :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img96.png)

And when you open the resulting image.png file, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img97.png)

**Flag :** crypto{hex_bytes_beans}

<br/>

# CTRIME (CTR)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img98.png)

When you go the <a href="http://aes.cryptohack.org/ctrime/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img99.png)

Source Code Provided :

```python

from Crypto.Cipher import AES
from Crypto.Util import Counter
import zlib


KEY = ?
FLAG = ?


@chal.route('/ctrime/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    iv = int.from_bytes(os.urandom(16), 'big')
    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))
    encrypted = cipher.encrypt(zlib.compress(plaintext + FLAG.encode()))

    return {"ciphertext": encrypted.hex()}
    
```

So in this challenge, we have an encrypt function which takes in a hex encoded plaintext and returns a ciphertext. The mode of operation is CTR and the encryption used is AES. The interesting thing here is that zlib.compress is used to compress the plaintext prepended to the flag and then this compressed data is encrypted and returned.

This <a href="https://www.euccas.me/zlib/" target="_blank">resource</a> thoroughly explains how zlib works while this <a href="https://ctftime.org/writeup/11327" target="_blank">CTF writeup</a> proved to be very useful. This attack (and the name of the challenge) is based on the <a href="https://en.wikipedia.org/wiki/CRIME" target="_blank">CRIME</a> attack.

Since zlib.compress reduces data when there are identical bytes (within a given sliding window), we can use this knowledge of reduced bytes to our advantage. Since we know that the flag format is "crypto{", say we wanted to find the next byte of the flag. If we loop through and append every printable ASCII character to "crypto{" and check which character produces a smaller byte length (by checking the length of the returned ciphertext), the only unique byte which produces this smallest length is the next byte of the flag. This is shown in the image below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img101.png)

As shown in the image above, the only byte which produces a smaller byte length than 70 is the "C" in "crypto{C" which means that the C byte is being compressed by zlib which means that this is the next flag byte. So we could keep repeating this procedure, loop through every printable ASCII character and append it to the flag until a smaller ciphertext length is returned when compared to every other value in this iteration. One thing to keep note of is the sliding window. When I first coded the solution, I was getting a lot of exclamation marks for my flag after "crypto{CRIM" and this was because if no smaller byte length was found, I would append the first byte in the loop which is ASCII 33 or "!". I noticed that if I removed the c in "crypto{CRIM" and appended ASCII values to "rypto{CRIM", then I would get the next byte "E" using the same method. So this means that after every 11 bytes, I should remove the first byte of the flag guess because the sliding window searches 11 bytes only. With that in mind this is the solution that I wrote :

```python

from typing import ByteString
import requests
import textwrap

def getCiphertext(plaintext):
    payloadURL = "http://aes.cryptohack.org/ctrime/encrypt/" + plaintext + "/"
    r = requests.get(payloadURL)
    temp = r.json()
    return temp['ciphertext']


flagLastByte = ""
realFlag = "crypto{"
tempFlag = "crypto{"

while(flagLastByte != "}"):

    startChar = 33

    for i in range(startChar, 127):

        temp = tempFlag + chr(i)
        hexString = temp.encode("utf-8").hex()
        ciphertext = getCiphertext(hexString)
        if (i == startChar):
            bestLength = len(ciphertext)
            flagLastByte = chr(i)
        if(bestLength > len(ciphertext)):
            flagLastByte = chr(i)
            break

    realFlag = realFlag + flagLastByte
    tempFlag = tempFlag + flagLastByte

    if(len(tempFlag) == 11):
        tempFlag = tempFlag[1:]

    print(realFlag)

```

And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img100.png)

**Flag :** crypto{CRIME_571ll_p4y5}

<br/>

# Stream of Consciousness (CTR)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img102.png)

When you go the <a href="http://aes.cryptohack.org/stream_consciousness/" target="_blank">link</a> shown in the image above, it shows you the source code and additional tools like the previous challenges. 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img103.png)

Source Code Provided :

```python

from Crypto.Cipher import AES
from Crypto.Util import Counter
import random


KEY = ?
TEXT = ['???', '???', ..., FLAG]


@chal.route('/stream_consciousness/encrypt/')
def encrypt():
    random_line = random.choice(TEXT)

    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))
    encrypted = cipher.encrypt(random_line.encode())

    return {"ciphertext": encrypted.hex()}
    
```

So what we have here is an array/list of random words. When the `encrypt()` function is called, a random word from this list is chosen. It is then encrypted with the same key and IV (nonce) each time the function is called. So here we have key and nonce reuse (as shown in the code above). Initially I thought that there was something wrong with the nonce as it was initialized as counter=Counter.new(128). Turns out that is just the <a href="https://pythonhosted.org/pycrypto/Crypto.Util.Counter-module.html" target="_blank">default</a> setting with the initial value as 1. So the nonce is fine. But the vulnerability lies in the fact that the key/nonce is reused each time encrypt is called.

After a bit of Googling, it was very evident that this was a big mistake. This <a href="https://crypto.stackexchange.com/questions/10505/reusing-keys-with-aes-cbc#:~:text=If%20a%20key%2FIV%20pair,the%20IV%2C%20not%20the%20plaintext." target="_blank">answer</a> explains why while I found this <a href="https://crypto.stackexchange.com/questions/2991/why-must-iv-key-pairs-not-be-reused-in-ctr-mode" target="_blank">answer</a> to be even better and used this as the basis for my attack. The summary of the answer is shown in the image below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img104.png)

So what is being said is that say you have two ciphertexts (C1 and C2) which are encrypted using the same key/nonce. This means that EN (the encrypted nonce) is the same each time in CTR mode for both encryptions which means that C1 = EN1 XOR P1 and C2 = EN1 XOR P2 (with P1 and P2 being plaintexts 1 and 2 respectively). So if we do C1 XOR C2, this is equal to EN1 XOR P1 XOR EN1 XOR P2 and since EN1 XOR EN1 = 0, this means that C1 XOR C2 = P1 XOR P2. And since we have the encrypt function, we can call it and get two ciphertexts each time. So now that we have C1 and C2 then what? We need to know the XOR of P1 and P2 but howwwww?

We know that the flag format is "crypto{" which means that we partly know one of the plaintexts. So if we do C1 XOR C2 and XOR the first 7 bytes of that with "crypto{", we will get the other plaintext (when the flag is XORed with the other plaintext) as P1 (flag) XOR P2 (other plaintext) = C1 XOR C2 (the ciphertexts we got from encrypt). So if do C1 XOR C2 XOR crypto{, we can get many possible P2s and many of them will not be printable (plaintext ASCII). Of the ones which are plaintext, there will be many options as the original list of words is of an unknown but presumably varied length.

I wrote the code below to achieve this :

```python

import requests
from pwn import xor
from requests.api import get


def getCiphertext():
   payloadURL = "http://aes.cryptohack.org/stream_consciousness/encrypt/"
   r = requests.get(payloadURL)
   temp = r.json()
   cipher = temp['ciphertext']
   return bytes.fromhex(cipher)

flagFormat = b"crypto{" 
check = False
 
while(check == False):
    c1 = getCiphertext()
    c2 = getCiphertext()  

    if (c1 != c2):
    
       c1XORc2 = xor(c1, c2)
       p2 = xor(c1XORc2[:len(flagFormat)], flagFormat)
       
       if ( p2.isascii() ):
           print(p2.decode('utf-8'))
  
```

So in the code above, I get two ciphertexts from the server (C1 and C2) and if they are not the same, I first XOR them and then XOR that result with the flag format (currently "crypto{"). After that, I check if the result (P2) is printable and if so, I print it.

When I ran the program, I got something like this :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img105.png)

Notice that there is a word " It can' " printed. This means that the 8th byte of that word has to be a "t" so that it spells out as "It can't ". So in this manner, based on this partially printed plaintext, we can use this guess and substitute it for the flag format. So when I first used "crypto{" as the flag format, I got these possible plaintexts (partial) :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img106.png)

So for my guess, I used "No, I'll" as the 'l' was missing in the original 7 bytes ("No I'l"). So I used these 8 bytes as my flag format and did the same process (C1 XOR C2 XOR 8 bytes of "No I'll") to get another set of more complete (by 1 byte usually) plaintexts. I then checked them I tried to see which one I could expand or fill out (guess) and then used that as my next flag format. I kept repeating this process until I got the flag. Here is the evolution of my guesses :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img107.png)

And towards the end, I found these values (including the flag) :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img108.png)

Special thanks to <a href="https://cryptohack.org/user/rootdiver/" target="_blank">rootdiver</a> for his kind help and patience, since I didn't know how to proceed. ALso thanks to him, I have now started using bytes instead of hex and I now know a way to easily check if a string is ASCII, using `isascii()`. Thanks rootdiver :D

**Flag :** crypto{k3y57r34m_r3u53_15_f474l}



