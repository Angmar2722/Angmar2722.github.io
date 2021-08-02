---
layout: page
title: UIUCTF 2021 CTF Writeup
---
<hr/>

![UIUCTF 2021 Writeup](/assets/img/ctfImages/uiuctf2021/logo.png)

I participated in the [University of Illinois Urbana-Champaign's UIUCTF 2021](https://ctftime.org/event/1372) event which took place from Sat, 31 July 2021, 08:00 SGT — Mon, 02 Aug. 2021, 08:00 SGT. I wasn't keen on participating in this CTF but since I joined a new team, I thought I would give it a shot and try out this new experience. I joined the team [Social Engineering Experts](https://ctftime.org/team/154571). I was looking at some Singaporean teams on CTFtime and saw that this team had a form which had a mini cryptography challenge to solve in order to get invited. I thought that now would be a good time to level up and join a bigger team instead of playing with small groups of people who I know. Also one of the leaders [Zeyu](https://zeyu2001.gitbook.io/ctfs/) has some well written writeups so make sure to check that out for the challenges that he solved in this CTF.

Playing in this team was a great experience. The players used [HedgeDoc](https://hedgedoc.org/) to collaborate, work on and share solutions to various challenges. The Discord server was well organised and since I have no clue how to do even basic web or Rev challenges, it was pretty nice knowing that someone out there was working on those. Great experience! This was definitely the most successful CTF that I have participated in so far as we ranked 18th out of 658 scoring teams. I managed to solve 7 challenges (mostly focused on the cryptography challenges) :

![UIUCTF 2021 Writeup](/assets/img/ctfImages/uiuctf2021/img1.png)

I spent an insane amount of time on the cryptography challenge "pow_erful" and finally managed to solve it at 3:50 am, a few hours before the CTF ended. These are the timestamps of the challenges that I solved :

![UIUCTF 2021 Writeup](/assets/img/ctfImages/uiuctf2021/img2.png)

There were only 4 cryptography challenges of which I solved 3 and Zeyu solved the other one. I wished there were more challenges but all in all, it was once again a great experience. This time, the majority of my time was focused on learning about Bitcoin for the 'pow_erful' challenge which was pretty cool since I had no idea how cryptocurrencies worked in general. I couldn't spend enough time on this CTF since I had to do some school work and also watched the most bizarre Olympics Men's 100m finals I have ever seen. I still cannot belive that Marcell Jacobs of Italy clocked a 9.80s 100m when he was a long jumper the prior year and only recently started training for sprints (and only very recently cracked the 10s barrier for the 100m). Maybe this will be the start of a great career for him? Anyways, below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[Pow-erful](#pow-erful) | Crypto | 390 | 16 |
|[Dhke-adventure](#dhke-adventure) | Crypto | 65 | 64 | 
|[Dhke-intro](#dhke-intro) | Crypto | 50 | 166 | 
|[Pwn Warmup](#pwn-warmup) | Pwn | 50 | 214 | 
|[Wasmbaby](#wasmbaby) | Web | 50 | 372 | 
|[Feedback Survey](#feedback-survey) | Meta | 1 | 167 | 
|[Join our Discord](#join-our-discord) | Meta | 1 | 417 | 

<br/>

<br/>

## Pow-erful

![UIUCTF 2021 Writeup](/assets/img/ctfImages/uiuctf2021/img3.png)

Server code provided :

```python

import os
import secrets
import hashlib

# 2^64 = a lot of hashes, gpu go brr
FLAG_DIFFICULTY = 64

def main():
    for difficulty in range(1, FLAG_DIFFICULTY):
        print("You are on: Level", difficulty, "/", FLAG_DIFFICULTY)
        print("Please complete this Proof of Work to advance to the next level")
        print()

        power = ((1 << difficulty) - 1).to_bytes(32, 'big')
        request = secrets.token_bytes(2)
        print("sha256(", request.hex(), "|| nonce ) &", power.hex(), "== 0")
        nonce = bytes.fromhex(input("nonce = "))
        print()

        hash = hashlib.sha256(request + nonce).digest()
        if not all(a & b == 0 for a, b in zip(hash, power)):
            print("Incorrect PoW")
            return
        print("Correct")

    print("Congrats!")
    print(os.environ["FLAG"])

if __name__ == "__main__":
    main()

```
