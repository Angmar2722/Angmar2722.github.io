---
layout: page
title: Logging In
---
<hr/>

When creating an account with this platform, apart from the usual settings of providing an email as well as a password for the account, they had a crypto challenge just for creating an account with the website.

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img1.png)

``` python

#!/usr/bin/env python3

str1 = input("Enter the Ceasar ciphertext that you want to decrypt : ")
#str1 = "QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD"
#Key Shift : 23
#Decrupted Text : THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
arr1 = list(str1)

sortedArray = list(str1)
        
str2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
arr2 = list(str2)
arr3 = list(str2)

spaceArray = [0] * len(str1)
for i in range( len(arr1) ):
    if arr1[i] == ' ':
        spaceArray[i] = "1"

def shiftArray(rightShift):
    arrPositionLength = len(arr2) - 1
    for i in range( len(arr2) ):
        if (i + rightShift) <= arrPositionLength:
            arr3[i] = arr2[i + rightShift]
        else:
            positiveGap = arrPositionLength - i
            arr3[i] = arr2[i + positiveGap]
            negativeGap = (rightShift - positiveGap) - 1
            if negativeGap >= 0 :
                arr3[i] = arr2[negativeGap]
    return arr3

def getDecryptedTextWithShift(rightShift):
    shiftedArray = shiftArray(rightShift)
    for i in range( len(arr1) ):
        for f in  range( len(shiftedArray) ):
            if (shiftedArray[f] == arr1[i]) :
                sortedArray[i] = arr2[f]
    decryptedText = ""
    for i in range( len(sortedArray) ):
        if spaceArray[i] != 1:
            decryptedText = decryptedText + sortedArray[i]
        else:
            decryptedText = decryptedText + " "
    return decryptedText
        

for i in range( 26 ):
    text = getDecryptedTextWithShift(i)
    print("The right shift is ", i, " and the decrypted text is : ", text)        

```

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img2.png)

