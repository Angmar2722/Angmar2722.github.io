---
layout: page
title: HSCTF 2021 CTF Writeup
---
<hr/>

![HSCTF 2021 Writeup](/assets/img/ctfImages/hsctf2021/logo.png)

Me and my team (Isengard) competed in <a href="https://ctftime.org/event/1264" target="_blank">West Windsor-Plainsboro High School North's HSCTF</a> event (Tuesday, 15 June 2021, 08:00 SGT — Sat, 19 June 2021, 20:00 SGT). This was my longest CTF yet (4.5 days). Originally the CTF was supposed to start at 8 pm on Monday 14th June but it was delayed by 12 hours due to some technical difficulties. We ranked 57th out of 1165 scoring teams and this was easily our best showing yet (we scored over 10k points!!).

I managed to solve 18 challenges (though there was some confusion over one of them due to team miscommunicaiton) and a lot of these challenges were solved by collaborating closely with and learning from my teammate and great friend **Diamondroxxx**. 

Below are the writeups :

<br/>

# Regulus-Calendula, AKA 'Squeakers' (Cryptography)

![HSCTF 2021 Writeup](/assets/img/ctfImages/hsctf2021/img1.png)

Source Code provided :

```python

from collections import Counter
from Crypto.Util.number import *
import sys
import random
import sympy
flag = open('flag.txt','rb').read()
print("Loading... this may take a while.")
p,q = getPrime(4096),getPrime(4096)
e = 0x10001
n = p*q
m = random.randrange(0,n)
c = pow(m,e,n)
d = sympy.mod_inverse(e,(p-1)*(q-1))
def menu(guesses):
    print()
    print("1. Source")
    print("2. Public key")
    print("3. Decrypt")
    print("4. Play")
    print("\nYou have "+str(guesses)+" guesses left.")
    choice = input(": ").strip()
    if choice=="1":
        f = open(__file__)
        print()
        print(f.read())
        print()
        menu(guesses)
    elif choice=="2":
        print("\nn = "+str(n))
        print("e = 65537")
        menu(guesses)
    elif choice=="3":
        d_ = int(input("What is the private key?\n: "))
        if (pow(c,d_,n)==m):
            print("Congrats! Here is your flag:")
            print(flag)
            sys.exit()
        else:
            print("\nSorry, that is incorrect.")
            menu(guesses)
    elif choice=="4":
        if guesses==0:
            print("Sorry, you have no more guesses.")
            menu(0)
        else:
            if guesses>8:
                code = list(hex(p)[2:])
            else:
                code = list(hex(q)[2:])
            guess = input("Make a guess.\n: ")
            while len(guess)!=1024:
                guess = input("Try again.\n: ")
            guess = list(guess)
            a = "".join(["1" if guess[i]==code[i] else "0" for i in range(1024)])
            print(a)
            guesses-=1
            menu(guesses)
    else:
        print("That is not a valid choice.")
        menu(guesses)
while 1:
    menu(16)

```

When you first connect to the server, you had to provide a proof of work by running the command that they provide. This <a href="https://github.com/Angmar2722/Angmar2722.github.io/blob/master/assets/ctfFiles/hsctf2021/proofOfWork.py" target="_blank">file</a>
 is the code for the proof of work incase anyone was interested.
 
So when we connect to the server, two 4096 bit primes are generated, a random integer (between 0 and the modulus n) message `m` is created and the corresponding ciphertext and private key `d` is generated as shown by the source code above. We have 4 options. Choosing the first option simply displays the source code shown above. The second option provides us with the public key - the modulus and public exponent (65537 in this case). The third option is the win state for obtaining the flag, we have to provide the exact private key that they used and if it matches, we get the flag. But how would we go about doing so since it is almost impossible to factor a 2048 bit RSA key, much less a 8192 bit one!!!! Well thats where the fourth option provides us with some interesting results.

We have 16 guesses. The first 8 guesses allows us to input upto 1024 hex characters and then this input will be checked against the prime `p` character by character and if it matches, a 1 will be outputted and if it doesn't, a 0 will be outputted. So for example, if we input 1024 "a"s (all of this is in hexadecimal), we would get all the "a"s in the prime `p`. Note that a 4096 bit prime would be 1024 hex characters as each hex value is a nibble (4 bits). Since there are 16 hex characters (from 0 to f), if we have only 8 guesses for p, we would probably get around half of the known bits (around 512 out of 1024 hex characters, this value varies with the primes generated but when we tested it, we got around 490-530 each time). Once we used up the first 8 guesses, the next 8 guesses are the same thing but this time, it is for the other prime `q`. So in the end, we would get approximately half of the bits of p and q, so how could we use that to our advantage???

After some Googling, we found certain papers such as this <a href="https://eprint.iacr.org/2008/510.pdf" target="_blank">one</a> and <a href="http://souravsengupta.com/publications/2010_africacrypt.pdf" target="_blank">this one</a> which explained that the modulus could be factored given at least 57% of random bits of p and q. A variant of the Heninger Scacham algebraic reconstruction algorithm would have to be used in order to obtain the two primes. This all sounds good in theory but we only have around 50% of the bits on average, so how could we juice that number up to the magic 57-60% range. Well suppose for each of the 8 guesses for p and q, if we guessed from 0 to 7 for each, we would know all the characters from 0 to 7 in the prime. The remaining unknown ones (8 to f) have one common feature, that is for each nibble, the most significant bit is always going to be 1. Think about, 8 is 1000 in binary and f is 1111. So we now know that for the remaining 512 nibbles (nibbles, hex characters, these terms will be used interchangeably), all of them have a 1 in their MSB. This means that aside from the 50% or 2048 bits that we know for each prime on average, we could obtain another 512 bits (from the MSB of 1) which gives us 62.5% of known bits for each prime.

Now that we have around 62.5% of the bits of p and q respectively, we could use one of these algebraic reconstruction algorithms in order to obtain the two primes. This part also took us a long time to figure out as we failed to efficiently and properly implement alot of the pseudocode shown in some of the papers that we read. Eventually we found that we could use this incredible <a href="https://hal.inria.fr/hal-01276452/document" target="_blank">paper</a> as it had the code for just what we needed (note that it is written in Python 2). So after slightly modifying for our needs and testing it for some primes we now had our reconstruction algorithm! Curiously, this did not work all the time given atleast 60% of the bits of p and q. Sometimes it would get 4096 bit primes in an instant (in like only a few seconds) and other times, it would fail to get even 16 bit primes.... Well we tested it out and realized that it worked most of the time and worked incredibly fast for the 4096 bit primes so we figured that it would only take about one to two attempts of connecting to the server to get the primes as each time you connect, a new prime is generated so you could do this to get a more favourable outcome :)

Well after this, we wrote a script that passes the inputs (0 to 7) 1024 times for each of the 8 guesses for p and q, obtains the modulus, uses the reconstruction algorithm and outputs it back to the server in order to obtain the flag. Running the proof of work took 2 minutes, generating the primes can take more than 2 minutes sometimes (as these are 4096 bits) and this coupled with the fact that we weren't sure that the reconstruction algorithm would work everytime made us really nervous and anxious when we first ran our script as for many minutes, we were super tensed. It turns out that in the first try itself, we got the primes!!!!! After this, we just calculated the totient and hence the private key `d` and then gave that to the server and then got the flag :D

Curiously, even after running the same script for the second and third time, we got the flag in both cases which means that this algorithm really does work most of the times which was awesome!

The solve script :

```python

import sys
from pwn import *
sys.setrecursionlimit(10000)
from Crypto.Util.number import *
pans = 0
qans = 0

def Backtrack_factor_msb_pq_recursion(p1,q1,i):
	if (i+1)==n: 				# Check if candidates of p and q are factors of N
		if int(p1 + '1', 2) * int(q1 + '1', 2) == N_NUM:
			global pans, qans
			pans, qans = int(p1 + '1', 2), int(q1 + '1', 2)
			raise

	else:
		k=i+1
		if ((p[i] != 'b') and (q[i] != 'b')): # if ith bit of p and q are known
			r= int((p1 + p[i]),2)
			s= int(q1 + q[i],2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)			# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3): 
				Backtrack_factor_msb_pq_recursion(p1 + p[i],q1 + q[i],i+1)
		
		elif ((p[i] != 'b') and (q[i] == 'b')):		# if ith bit of p is unknown and q is known
			r=int((p1 + p[i]),2)
			s=int(q1 + '0',2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)			# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3): 
				Backtrack_factor_msb_pq_recursion(p1 + p[i],q1 + '0',i+1)
			s= int(q1 + '1',2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)			# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + p[i],q1 + '1',i+1)
		
		elif ((p[i] == 'b') and (q[i] != 'b')):		# if ith bit of q is unknown and p is known
			s=int(q1 + q[i],2)
			r= int(p1 + '0',2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)			# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3):				
				Backtrack_factor_msb_pq_recursion(p1 + '0',q1 + q[i],i+1)
			r= int(p1 + '1',2)
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '1',q1 + q[i],i+1)
				
		elif ((p[i] == 'b') and (q[i] == 'b')):			# if ith bit of p and q are unknown
			r=  int(p1 + '0',2)
			s=  int(q1 + '0',2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)				# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '0',q1 + '0',i+1)
				
			r=  int(p1 + '1',2)
			s=  int(q1 + '0',2)
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '1',q1 + '0',i+1)
			
			r=  int(p1 + '0',2)
			s=  int(q1 + '1',2)
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '0',q1 + '1',i+1)
			
			r=  int(p1 + '1',2)
			s=  int(q1 + '1',2)
			
			if (abs(s - (R/r)) <= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '1',q1 + '1',i+1)

#r = process(["python", "regulus-calendula/regulus-calendula.py"])
r = remote("regulus-calendula.hsc.tf", 1337)
r.recvline()
r.recvline()
r.recvline()
print(r.recvline().strip())
ans = str(raw_input("ans: "))
r.sendline(ans)
r.recvline()
r.recvline()
print(r.recvline())
r.sendlineafter(": ", "2")
r.recvline()
N_NUM = int(r.recvline().split(" ")[-1])
N = bin(N_NUM)[2:]
n = 4096
r.recvline()
print(r.recvline())

guessp = []
guessq = []

PRIME_SIZE = 4096

for i in range(8):
    r.sendlineafter(": ", "4")
    r.sendlineafter(": ", str(i)*(PRIME_SIZE//4))
    guessp.append(r.recvline())
for i in range(8):
    r.sendlineafter(": ", "4")
    r.sendlineafter(": ", str(i)*(PRIME_SIZE//4))
    guessq.append(r.recvline())

#print(guessp, guessq)

p = ["1"] + ["b"]*(PRIME_SIZE-2) + ["1"]
for i in range(8):
    for c in range(PRIME_SIZE//4):
        if guessp[i][c] == "1":
            p[c*4:c*4+4] = list("0000" + bin(i)[2:])[-4:]
        else:
            if p[c*4] == "b":
                p[c*4] = "1"
p = "".join(p)
#print(p)

q = ["1"] + ["b"]*(PRIME_SIZE-2) + ["1"]
for i in range(8):
    for c in range(PRIME_SIZE//4):
        if guessq[i][c] == "1":
            q[c*4:c*4+4] = list("0000" + bin(i)[2:])[-4:]
        else:
            if q[c*4] == "b":
                q[c*4] = "1"
q = "".join(q)
#print(q)


print("solving")
try:
	Backtrack_factor_msb_pq_recursion(p[0],q[0],1)
except:
	pass

phi = (pans-1)*(qans-1)
d = inverse(65537, phi)
r.sendlineafter(": ", "3")
r.sendlineafter(": ", str(d))
print(r.recvall())
print("done")

```

And as shown below, after running it and waiting for a few minutes, you get the flag :

![HSCTF 2021 Writeup](/assets/img/ctfImages/hsctf2021/img2.png)

Solving this challenge was a really special moment for me personally since this was the 8th least solved challenge out of the 50 challenges in the CTF and of the 28 teams which solved it, I noticed that all of them were in the top 50. This was probably the first truly hard CTF problem that I managed to solve in terms of the number of solves by all teams. Me and Diamondroxxx spent nearly 13 hours straight on this challenge, from 6 pm Friday to 7 am Saturday and during that time, we thought of using a SAT solver (Boolean satisfiability problem solver), we were stuck over the implementation of the reconstruction algorithm, and times we had no idea what we were doing or what we had to do, but we persevered and finally got it and boy did that feel great. Hopefully solving this challenge proves to be a stepping stone and major milestone in my CTF/cybersecurity learning journey :D  

<p> <b>Flag :</b> flag{P0g_Po5_pOG_i_Sh0Ok_mY-pHoN3_t0_5O_kMs_leTs_goOOoO0oO} </p>
