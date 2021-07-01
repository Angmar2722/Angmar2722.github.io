---
layout: page
title: Mathematics -Probability / Brainteasers Parts 1 & 2 / Primes
---
<hr/>

The Mathematics section consists of 22 challenges. The challenges are subdivided into 6 different stages : Modular Math, Lattices, Probability, Brainteasers Part 1, Brainteasers Part 2 and Primes. Below are the writeups for the ones I managed to complete for the Probability, Brainteasers Part 1, Brainteasers Part 2 and Primes sections :

<br/>

# Successive Powers (Brainteasers Part 1)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img176.png)

Because these numbers are successive powers of x, we can write the following system of equations:

1. $$ 588x \equiv 665\ (\text{mod}\ p) $$ 
2. $$ 665x \equiv 216\ (\text{mod}\ p) $$ 
3. $$ 216x \equiv 113\ (\text{mod}\ p) $$ 
4. $$ 113x \equiv 642\ (\text{mod}\ p) $$ 
5. $$ 642x \equiv 4\ (\text{mod}\ p) $$ 
6. $$ 4x \equiv 836\ (\text{mod}\ p) $$ 
7. $$ 836x \equiv 114\ (\text{mod}\ p) $$ 
8. $$ 114x \equiv 851\ (\text{mod}\ p) $$ 
9. $$ 851x \equiv 492\ (\text{mod}\ p) $$ 
10. $$ 492x \equiv 819\ (\text{mod}\ p) $$ 
11. $$ 819x \equiv 237\ (\text{mod}\ p) $$ 

From this set of equations, by subtracting equation `4` from `8` we get :

$$ x \equiv 209\ (\text{mod}\ p) $$ 

Since p is bigger than 851 (because 851 is one of the powers of x listed in the question), we know that x equals 209. With that I made a short script to find out which prime between 851 and 1000 satisfys the 10th equation (arbitrarily chosen) :

```python

lower = 851
upper = 999

primeList = []
for num in range(lower, upper + 1):
   if num > 1:
       for i in range(2, num):
           if (num % i) == 0:
               break
       else:
           primeList.append(num)

x = 209

for i in range(len(primeList)):
    if(819*x % primeList[i] == 237):
        print(primeList[i])

```

<p> <b>Flag :</b> crypto{919,209} </p>
