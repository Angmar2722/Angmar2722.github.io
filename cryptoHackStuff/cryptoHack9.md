---
layout: page
title: RSA - Starter / Primes Part 1 / Public Exponent
---
<hr/>

The RSA section consists of 29 challenges. The challenges are subdivided into 7 different stages : Starter, Primes Part 1, Public Exponent, Primes Part 2, Padding, Signatures Part 1 and Signatures Part 2. Below are the writeups for the ones I managed to complete for the Starter, Primes Part 1 and Public Exponent sections :

<br/>

# RSA Starter 1 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img109.png)

As shown in the image above, I just had to find 101^17 mod 22663 which I did using the command shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img110.png)

Flag : 19906

<br/>

# RSA Starter 2 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img111.png)

As shown in the image above, I just had to find 12^65537 mod (17*23) which I did using the command shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img112.png)

Flag : 301

<br/>

# RSA Starter 3 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img113.png)

As shown in the image above, I went to the <a href="https://leimao.github.io/article/RSA-Algorithm/" target="_blank">link</a> that they provided where some of the mathematics behind RSA encryption was explained. The Euler's Totient Function part is shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img115.png)

So since I had the two primes p and q, I had to do (p-1) * (q - 1) to get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img114.png)

Flag : 882564595536224140639625987657529300394956519977044270821168

<br/>

# RSA Starter 4 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img116.png)

As shown in the image above, to get the private key `d`, I have to get the modular multiplicative inverse of e Mod (the Euler totient of N). In the key generation section of the  <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation" target="_blank">RSA Wikipedia article</a>, it is stated that you can get the modular multiplicative inverse using the Extended Euclidean Algorithm as the equation is in a form of Bezout's identity. This is shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img117.png)

And when you go to the <a href="https://en.wikipedia.org/wiki/Modular_multiplicative_inverse" target="_blank">Modular Multiplicative Inverse</a> Wikipedia page, it shows how the Bezout's identity is mathematically used to compute the modular multiplicative inverse :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img118.png)

So I used my Extended Euclidean algorithm from a previous CryptoHack Challenge (Extended GCD (under the Mathematics section of General) ) to compute the private key (the modular multiplicative inverse) :

```python


p = 857504083339712752489993810777
q = 1029224947942998075080348647219
eulerTotient = (p-1) * (q-1)
e = 65537

def extended_gcd(a, m):
    old_r, r = a, m
    old_s, s = 1, 0
    old_t, t = 0, 1

    while (r != 0):
        quotient = int(old_r / r)
        old_r, r = r, (old_r - quotient * r)
        old_s, s = s, (old_s - quotient * s)
        old_t, t = t, (old_t - quotient * t)

    print("Bezout coefficients : ", old_s, " ", old_t)
    print("GCD : ", old_r)

extended_gcd(e, eulerTotient)

```

And when you run the program, you get the private key `d` :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img119.png)

Flag : 121832886702415731577073962957377780195510499965398469843281

Of note, these two videos explaining RSA encryption are incredible :

* <a href="https://www.youtube.com/watch?v=4zahvcJ9glg" target="_blank">Part 1</a>
* <a href="https://www.youtube.com/watch?v=oOcTVTpUsPQ" target="_blank">Part 2</a>

<br/>

# RSA Starter 5 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img120.png)

As shown in the image above, I had to decrypt the ciphertext using the private key I got from the previous challenge. In RSA, the decrypted message (m) = c^d Mod N with c being the ciphertext, d being the private key and N being the modulus.

So I did that and got the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img121.png)

Flag : 13371337

<br/>

# RSA Starter 6 (Starter)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img122.png)

As shown in the image above, I had to compute the signature or sign the message ("crypto{Immut4ble_m3ssag1ng}"). To do that, I had to first convert the message to a hash (SHA-256) and then sign it with my private key by calculating hash ^ d (private key) MOD N. The private key file contained d and N as shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img123.png)

I wrote this short program to compute the signature and output it in hex :

```python

import hashlib

m = b"crypto{Immut4ble_m3ssag1ng}"

hashedM = int(hashlib.sha256(m).hexdigest(), 16)

d = 11175901210643014262548222473449533091378848269490518850474399681690547281665059317155831692300453197335735728459259392366823302405685389586883670043744683993709123180805154631088513521456979317628012721881537154107239389466063136007337120599915456659758559300673444689263854921332185562706707573660658164991098457874495054854491474065039621922972671588299315846306069845169959451250821044417886630346229021305410340100401530146135418806544340908355106582089082980533651095594192031411679866134256418292249592135441145384466261279428795408721990564658703903787956958168449841491667690491585550160457893350536334242689

N = 15216583654836731327639981224133918855895948374072384050848479908982286890731769486609085918857664046075375253168955058743185664390273058074450390236774324903305663479046566232967297765731625328029814055635316002591227570271271445226094919864475407884459980489638001092788574811554149774028950310695112688723853763743238753349782508121985338746755237819373178699343135091783992299561827389745132880022259873387524273298850340648779897909381979714026837172003953221052431217940632552930880000919436507245150726543040714721553361063311954285289857582079880295199632757829525723874753306371990452491305564061051059885803

s = pow(hashedM, d, N)

print( '{:x}'.format(int(s)) )

```

And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img124.png)

Flag : 6ac9bb8f110b318a40ad8d7e57defdcce2652f5928b5f9b97c1504d7096d7af1d34e477b30f1a08014e8d525b14458b709a77a5fa67d4711bd19da1446f9fb0ffd9fdedc4101bdc9a4b26dd036f11d02f6b56f4926170c643f302d59c4fe8ea678b3ca91b4bb9b2024f2a839bec1514c0242b57e1f5e77999ee67c450982730252bc2c3c35acb4ac06a6ce8b9dbf84e29df0baa7369e0fd26f6dfcfb22a464e05c5b72baba8f78dc742e96542169710918ee2947749477869cb3567180ccbdfe6fdbe85bcaca4bf6da77c8f382bb4c8cd56dee43d1290ca856318c97f1756b789e3cac0c9738f5e9f797314d39a2ededb92583d97124ec6b313c4ea3464037d3

<br/>

# Factoring (Primes Part 1)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img125.png)

As shown in the image above, I had to find the two prime factors for 510143758735509025530880200653196460532653147. To do that, I used this <a href="http://factordb.com/index.php?query=510143758735509025530880200653196460532653147" target="_blank">website</a>. So the smaller prime factor is 19704762736204164635843.

Flag : 19704762736204164635843

<br/>

# Inferius Prime (Primes Part 1)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img126.png)

There were two files, an output.txt file and an inferius.py file.

Contents of output.txt :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img127.png)

Source code of inferius.py :

```python

#!/usr/bin/env python3

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD

e = 3

# n will be 8 * (100 + 100) = 1600 bits strong which is pretty good
while True:
    p = getPrime(100)
    q = getPrime(100)
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    if d != -1 and GCD(e, phi) == 1:
        break

n = p * q

flag = b"XXXXXXXXXXXXXXXXXXXXXXX"
pt = bytes_to_long(flag)
ct = pow(pt, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ct}")

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)
assert decrypted == flag

```
So I have the ciphertext (ct), I have the exponent (e) and I have the modulus (N). So N = 742449129124467073921545687640895127535705902454369756401331 and I found its prime factors (p and q) using the same <a href="http://factordb.com/index.php?query=742449129124467073921545687640895127535705902454369756401331" target="_blank">website</a> in the previous challenge. So now that I have p and q, I could calculate the Euler totient and from that calculate the private key d. After that, the plaintext is is obtained by ct ^ d MOD N.

My code :

```python

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD

n = 742449129124467073921545687640895127535705902454369756401331
e = 3
ct = 39207274348578481322317340648475596807303160111338236677373

p = 752708788837165590355094155871
q = 986369682585281993933185289261

eulerTotient = (p-1) * (q-1)

d = pow(e, -1, eulerTotient)

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)

print(decrypted)

```

Note that for getting the modular multiplicative inverse, instead of the long extended euclidean algorithm I wrote in one of the previous challenges, I just used the line `d = pow(e, -1, eulerTotient)` instead.

And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img128.png)

**Flag :** crypto{N33d_b1g_pR1m35}

<br/>

# Monoprime (Primes Part 1)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img129.png)

We have one file given to us (output.txt) :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img130.png)

So we have the ciphertext, exponent and modulus. Since n is prime, this means that the totient is (n-1).

So I wrote this script :

```python

from Crypto.Util.number import long_to_bytes

n = 171731371218065444125482536302245915415603318380280392385291836472299752747934607246477508507827284075763910264995326010251268493630501989810855418416643352631102434317900028697993224868629935657273062472544675693365930943308086634291936846505861203914449338007760990051788980485462592823446469606824421932591                                                                  
e = 65537
ct = 161367550346730604451454756189028938964941280347662098798775466019463375610700074840105776873791605070092554650190486030367121011578171525759600774739890458414593857709994072516290998135846956596662071379067305011746842247628316996977338024343628757374524136260758515864509435302781735938531030576289086798942  

eulerTotient = (n-1)

d = pow(e, -1, eulerTotient)

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)

print(decrypted)

```

And after running the script, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img131.png)

**Flag :** crypto{0n3_pr1m3_41n7_pr1m3_l0l}

<br/>

# Square Eyes (Primes Part 1)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img132.png)

We have a file, output.txt which contains N, e and c (ciphertext). I used the same website 2 challenges earlier to get the repeated prime factor (p) of N. I could have also found p by finding the squareroot of N as N = p^2. And since p is repeated, the totient function = p(p-1) as explained <a href="https://cs.stackexchange.com/questions/50906/what-if-p-and-q-are-not-distinct-in-rsa-crypto-system-what-could-go-wrong" target="_blank">here</a>.
And the rest of the script was the same as in the previous challenges :

```python

from Crypto.Util.number import long_to_bytes
import math

n = 535860808044009550029177135708168016201451343147313565371014459027743491739422885443084705720731409713775527993719682583669164873806842043288439828071789970694759080842162253955259590552283047728782812946845160334801782088068154453021936721710269050985805054692096738777321796153384024897615594493453068138341203673749514094546000253631902991617197847584519694152122765406982133526594928685232381934742152195861380221224370858128736975959176861651044370378539093990198336298572944512738570839396588590096813217791191895941380464803377602779240663133834952329316862399581950590588006371221334128215409197603236942597674756728212232134056562716399155080108881105952768189193728827484667349378091100068224404684701674782399200373192433062767622841264055426035349769018117299620554803902490432339600566432246795818167460916180647394169157647245603555692735630862148715428791242764799469896924753470539857080767170052783918273180304835318388177089674231640910337743789750979216202573226794240332797892868276309400253925932223895530714169648116569013581643192341931800785254715083294526325980247219218364118877864892068185905587410977152737936310734712276956663192182487672474651103240004173381041237906849437490609652395748868434296753449
e = 65537
c = 222502885974182429500948389840563415291534726891354573907329512556439632810921927905220486727807436668035929302442754225952786602492250448020341217733646472982286222338860566076161977786095675944552232391481278782019346283900959677167026636830252067048759720251671811058647569724495547940966885025629807079171218371644528053562232396674283745310132242492367274184667845174514466834132589971388067076980563188513333661165819462428837210575342101036356974189393390097403614434491507672459254969638032776897417674577487775755539964915035731988499983726435005007850876000232292458554577437739427313453671492956668188219600633325930981748162455965093222648173134777571527681591366164711307355510889316052064146089646772869610726671696699221157985834325663661400034831442431209123478778078255846830522226390964119818784903330200488705212765569163495571851459355520398928214206285080883954881888668509262455490889283862560453598662919522224935145694435885396500780651530829377030371611921181207362217397805303962112100190783763061909945889717878397740711340114311597934724670601992737526668932871436226135393872881664511222789565256059138002651403875484920711316522536260604255269532161594824301047729082877262812899724246757871448545439896

p = 23148667521998097720857168827790771337662483716348435477360567409355026169165934446949809664595523770853897203103759106983985113264049057416908191166720008503275951625738975666019029172377653170602440373579593292576530667773951407647222757756437867216095193174201323278896027294517792607881861855264600525772460745259440301156930943255240915685718552334192230264780355799179037816026330705422484000086542362084006958158550346395941862383925942033730030004606360308379776255436206440529441711859246811586652746028418496020145441513037535475380962562108920699929022900677901988508936509354385660735694568216631382653107

eulerTotient = p * (p-1)

d = pow(e, -1, eulerTotient)

pt = pow(c, d, n)
decrypted = long_to_bytes(pt)

print(decrypted)

```
And after running the script you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img133.png)

**Flag :** crypto{squar3_r00t_i5_f4st3r_th4n_f4ct0r1ng!}

<br/>

# Manyprime (Primes Part 1)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img134.png)

As with the previous challenges, from output.txt we have N, ct and e. The challenges states that N has multiple prime factors (over 30!). So I know this is definitely not the best way to solve this challenge but I went back to the good old <a href="http://factordb.com/index.php?query=580642391898843192929563856870897799650883152718761762932292482252152591279871421569162037190419036435041797739880389529593674485555792234900969402019055601781662044515999210032698275981631376651117318677368742867687180140048715627160641771118040372573575479330830092989800730105573700557717146251860588802509310534792310748898504394966263819959963273509119791037525504422606634640173277598774814099540555569257179715908642917355365791447508751401889724095964924513196281345665480688029639999472649549163147599540142367575413885729653166517595719991872223011969856259344396899748662101941230745601719730556631637" target="_blank">website</a> which beautifully listed out all 32 prime factors (I am sure there is some module in Python which gets these prime factors in a much better way). I then manually :( input each prime into a prime factor list, and calculated the totient function as eulerTotient = (p1 - 1) (p2 -1 ) (p3 - 1) ..... (p32 - 1). After that, the rest was the same.

My code :

```python

from Crypto.Util.number import long_to_bytes
import math

n = 580642391898843192929563856870897799650883152718761762932292482252152591279871421569162037190419036435041797739880389529593674485555792234900969402019055601781662044515999210032698275981631376651117318677368742867687180140048715627160641771118040372573575479330830092989800730105573700557717146251860588802509310534792310748898504394966263819959963273509119791037525504422606634640173277598774814099540555569257179715908642917355365791447508751401889724095964924513196281345665480688029639999472649549163147599540142367575413885729653166517595719991872223011969856259344396899748662101941230745601719730556631637
e = 65537
ct = 320721490534624434149993723527322977960556510750628354856260732098109692581338409999983376131354918370047625150454728718467998870322344980985635149656977787964380651868131740312053755501594999166365821315043312308622388016666802478485476059625888033017198083472976011719998333985531756978678758897472845358167730221506573817798467100023754709109274265835201757369829744113233607359526441007577850111228850004361838028842815813724076511058179239339760639518034583306154826603816927757236549096339501503316601078891287408682099750164720032975016814187899399273719181407940397071512493967454225665490162619270814464

primeFactorList = [9282105380008121879, 9303850685953812323, 9389357739583927789, 10336650220878499841, 10638241655447339831, 11282698189561966721, 11328768673634243077, 11403460639036243901, 11473665579512371723, 11492065299277279799, 11530534813954192171, 11665347949879312361, 12132158321859677597, 12834461276877415051, 12955403765595949597, 12973972336777979701, 13099895578757581201, 13572286589428162097, 14100640260554622013, 14178869592193599187, 14278240802299816541, 14523070016044624039, 14963354250199553339, 15364597561881860737, 15669758663523555763, 15824122791679574573, 15998365463074268941, 16656402470578844539, 16898740504023346457, 17138336856793050757, 17174065872156629921, 17281246625998849649]

eulerTotient = 1

for i in range (len(primeFactorList)):
    eulerTotient = eulerTotient * (primeFactorList[i]-1)

d = pow(e, -1, eulerTotient)

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)

print(decrypted)

```

And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img135.png)

**Flag :** crypto{700_m4ny_5m4ll_f4c70r5}

<br/>

# Salty (Public Exponent)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img136.png)

Two files were given, salty.py and output.txt. This is the code for salty.py :

```python

#!/usr/bin/env python3

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

e = 1
d = -1

while d == -1:
    p = getPrime(512)
    q = getPrime(512)
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

n = p * q

flag = b"XXXXXXXXXXXXXXXXXXXXXXX"
pt = bytes_to_long(flag)
ct = pow(pt, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ct}")

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)
assert decrypted == flag

```

Output.txt had the usual exponent (this time it was 1), N and ct. So in RSA, ct = m^e MOD N (where m is the message). But since e = 1, this is ct = m MOD N. And we can get m by doing ct % N. So thats what I did :

```python

from Crypto.Util.number import long_to_bytes

n = 110581795715958566206600392161360212579669637391437097703685154237017351570464767725324182051199901920318211290404777259728923614917211291562555864753005179326101890427669819834642007924406862482343614488768256951616086287044725034412802176312273081322195866046098595306261781788276570920467840172004530873767                                                                  
e = 1
ct = 44981230718212183604274785925793145442655465025264554046028251311164494127485

m = long_to_bytes(ct % n)
print(m)

```

And when you run the program you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img137.png)

**Flag :** crypto{saltstack_fell_for_this!}

<br/>

# Modulus Inutilis (Public Exponent)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img138.png)

Two files were given, modulus_inutilis.py and output.txt. This is the code for modulus_inutilis.py :

```python

#!/usr/bin/env python3

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

e = 3
d = -1

while d == -1:
    p = getPrime(1024)
    q = getPrime(1024)
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

n = p * q

flag = b"XXXXXXXXXXXXXXXXXXXXXXX"
pt = bytes_to_long(flag)
ct = pow(pt, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ct}")

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)
assert decrypted == flag

```

Output.txt had the usual exponent (this time it was 3), N and ct. So in RSA, ct = m^e MOD N (where m is the message). But since e = 3, this is ct = m^3 MOD N. And so the message (plaintext) = the cube root of (ct % N). Since ct % N is a really large number, I found an algorithm from this <a href="https://stackoverflow.com/questions/356090/how-to-compute-the-nth-root-of-a-very-big-integer" target="_blank">thread</a>.

My code :

```python

from Crypto.Util.number import long_to_bytes
import math

n = 17258212916191948536348548470938004244269544560039009244721959293554822498047075403658429865201816363311805874117705688359853941515579440852166618074161313773416434156467811969628473425365608002907061241714688204565170146117869742910273064909154666642642308154422770994836108669814632309362483307560217924183202838588431342622551598499747369771295105890359290073146330677383341121242366368309126850094371525078749496850520075015636716490087482193603562501577348571256210991732071282478547626856068209192987351212490642903450263288650415552403935705444809043563866466823492258216747445926536608548665086042098252335883
e = 3
ct = 243251053617903760309941844835411292373350655973075480264001352919865180151222189820473358411037759381328642957324889519192337152355302808400638052620580409813222660643570085177957

mCubed = ct % n

def find_invpow(x,n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n <= x:
        high *= 2
    low = high//2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

m = find_invpow(mCubed, 3)

print(long_to_bytes(m))

```

And after running the script you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img139.png)

**Flag :** crypto{N33d_m04R_p4dd1ng}

<br/>

# Everything is Big (Public Exponent)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img140.png)

Two files were given, source.py and output.txt. This is the code for source.py :

```python

#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long, inverse
from random import getrandbits
from math import gcd

FLAG = b"crypto{?????????????????????????}"

m = bytes_to_long(FLAG)

def get_huge_RSA():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p*q
    phi = (p-1)*(q-1)
    while True:
        e = getrandbits(2048)
        if gcd(e,phi) == 1:
            break
    return N,e


N, e = get_huge_RSA()
c = pow(m, e, N)

print(f'N = {hex(N)}')
print(f'e = {hex(e)}')
print(f'c = {hex(c)}')

```

Output.txt had the usual exponent (this time it was very large), N and ciphertext. All of these were given in hex :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img141.png)

So I first converted all 3 to decimal. Then I used the awesome <a href="http://factordb.com/index.php?query=17882358060039339138898609438175411871477799918608830364502878294884428124352650304487222941488283375369504964489843886450079011111185462712713723967554860800590884830066000037099382469037854558513800884226033482024813889617119261578740186832726330482660558112299636890899520011220715934812750994601701551700102743698011384901217438912042452845551043076325218096704501728676598844462217580321136090473356372587847867144139594128211568185994035330415437804541731112709398826340193004240100025524738143760028319395043726883002837253849402330482885844810147036036336331435599614615503162626162367298458471506712461489989" target="_blank">wesbite once again</a> to get the two prime factors of N. Then after calculating the totient, I got the private key and then decrypted the ciphertext to get the flag. My code :

```python

from Crypto.Util.number import long_to_bytes

N = "8da7d2ec7bf9b322a539afb9962d4d2ebeb3e3d449d709b80a51dc680a14c87ffa863edfc7b5a2a542a0fa610febe2d967b58ae714c46a6eccb44cd5c90d1cf5e271224aa3367e5a13305f2744e2e56059b17bf520c95d521d34fdad3b0c12e7821a3169aa900c711e6923ca1a26c71fc5ac8a9ff8c878164e2434c724b68b508a030f86211c1307b6f90c0cd489a27fdc5e6190f6193447e0441a49edde165cf6074994ea260a21ea1fc7e2dfb038df437f02b9ddb7b5244a9620c8eca858865e83bab3413135e76a54ee718f4e431c29d3cb6e353a75d74f831bed2cc7bdce553f25b617b3bdd9ef901e249e43545c91b0cd8798b27804d61926e317a2b745"
e = "86d357db4e1b60a2e9f9f25e2db15204c820b6e8d8d04d29db168c890bc8a6c1e31b9316c9680174e128515a00256b775a1a8ccca9c6936f1b4c2298c03032cda4dd8eca1145828d31466bf56bfcf0c6a8b4a1b2fb27de7a57fae7430048d7590734b2f05b6443ad60d89606802409d2fa4c6767ad42bffae01a8ef1364418362e133fa7b2770af64a68ad50ad8d2bd5cebb99ceb13368fb31a6e7503e753f8638e21a96af1b6498c18578ba89b98d70fa482ad137d28fe701b4b77baa25d5e84c81b26ee9bddf8cbb51a071c60dd57714de379cd4bc14932809ba18524a0a18e4133665cfc46e2c4fcfbc28e0a0957e5513a7307c422b87a6182d0b6a074b4d"
c = "6a2f2e401a54eeb5dab1e6d5d80e92a6ca189049e22844c825012b8f0578f95b269b19644c7c8af3d544840d380ed75fdf86844aa8976622fa0501eaec0e5a1a5ab09d3d1037e55501c4e270060470c9f4019ced6c4e67673843daf2fd71c64f3dd8939ae322f2b79d283b3382052d076ebe9bb50b0042f1f7dd7beadf0f5686926ade9fc8370283ead781a21896e7a878d99e77c3bb1f470401062c0e0327fd85da1cf12901635f1df310e8f8c7d87aff5a01dbbecd739cd8f36462060d0eb237af8d613e2d9cebb67d612bcfc353ef2cd44b7ac85e471287eb04ae9b388b66ea8eb32429ae96dba5da8206894fa8c58a7440a127fceb5717a2eaa3c29f25f7"

N = int(N, 16)
e = int(e, 16)
c = int(c, 16)

p = 115507290436804681853972513785855229092334080356874717883434238235532664441400698329642751264652299576298636563034566154936812894976200811116395627642824129881201879664681775402664283913508399125714656956248098339209538838857780042711388040763913184276611985732635893909527514214876581238108724839614805837919

q = 154815838830735756266839897002132314538675909135249954852542100179590192055257100601759523401409380049463266265323780406554692248012224485469468355325698979825072726357567352976501667578692853621821116743497998613306224857520639271685772211046709014876104481766909036522349223506326852943709940047836080845531

eulerTotient = (p-1) * (q-1)

d = pow(e, -1, eulerTotient)

pt = pow(c, d, N)
decrypted = long_to_bytes(pt)

print(decrypted)

```

And after running the program, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img142.png)

**Flag :** crypto{s0m3th1ng5_c4n_b3_t00_b1g}

<br/>

# Crossed Wires (Public Exponent)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img143.png)

Two files were given, source.py and output.txt. This is the code for source.py :

```python

from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long, inverse
import math
from gmpy2 import next_prime

FLAG = b"crypto{????????????????????????????????????????????????}"

p = getPrime(1024)
q = getPrime(1024)
N = p*q
phi = (p-1)*(q-1)
e = 0x10001
d = inverse(e, phi)

my_key = (N, d)

friends = 5
friend_keys = [(N, getPrime(17)) for _ in range(friends)]

cipher = bytes_to_long(FLAG)

for key in friend_keys:
    cipher = pow(cipher, key[1], key[0])

print(f"My private key: {my_key}")
print(f"My Friend's public keys: {friend_keys}")
print(f"Encrypted flag: {cipher}")

```

Output.txt was different this time :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img144.png)

The private key and all 5 of the friend's public keys share the same modulus N. We also have the ciphertext which is the encrypted flag. The problem seems to be that instead of using the person's public key, each friend encrypted the message (flag) with their own public keys. So the original message (m) was encrypted with all 5 public keys. So first I found the prime factors of N using the good old website and got the totient function. After that, I looped through each of the 5 public keys and got the private key of each of the friend's public keys and used that to decrypt the ciphertext each time. So I decrypted the ciphertext 5 times (using each of the 5 private keys of the friends which I calculated). The final output was the flag.

My code :

```python

from Crypto.Util.number import long_to_bytes

N = 21711308225346315542706844618441565741046498277716979943478360598053144971379956916575370343448988601905854572029635846626259487297950305231661109855854947494209135205589258643517961521594924368498672064293208230802441077390193682958095111922082677813175804775628884377724377647428385841831277059274172982280545237765559969228707506857561215268491024097063920337721783673060530181637161577401589126558556182546896783307370517275046522704047385786111489447064794210010802761708615907245523492585896286374996088089317826162798278528296206977900274431829829206103227171839270887476436899494428371323874689055690729986771

p = 134460556242811604004061671529264401215233974442536870999694816691450423689575549530215841622090861571494882591368883283016107051686642467260643894947947473532769025695530343815260424314855023688439603651834585971233941772580950216838838690315383700689885536546289584980534945897919914730948196240662991266027

q = 161469718942256895682124261315253003309512855995894840701317251772156087404025170146631429756064534716206164807382734456438092732743677793224010769460318383691408352089793973150914149255603969984103815563896440419666191368964699279209687091969164697704779792586727943470780308857107052647197945528236341228473

eulerTotient = (p-1) * (q-1)

myPrivateKey = (N, 2734411677251148030723138005716109733838866545375527602018255159319631026653190783670493107936401603981429171880504360560494771017246468702902647370954220312452541342858747590576273775107870450853533717116684326976263006435733382045807971890762018747729574021057430331778033982359184838159747331236538501849965329264774927607570410347019418407451937875684373454982306923178403161216817237890962651214718831954215200637651103907209347900857824722653217179548148145687181377220544864521808230122730967452981435355334932104265488075777638608041325256776275200067541533022527964743478554948792578057708522350812154888097)

friendPublicKeyList = [(N, 106979), (N, 108533), (N, 69557), (N, 97117), (N, 103231)]

ct = 20304610279578186738172766224224793119885071262464464448863461184092225736054747976985179673905441502689126216282897704508745403799054734121583968853999791604281615154100736259131453424385364324630229671185343778172807262640709301838274824603101692485662726226902121105591137437331463201881264245562214012160875177167442010952439360623396658974413900469093836794752270399520074596329058725874834082188697377597949405779039139194196065364426213208345461407030771089787529200057105746584493554722790592530472869581310117300343461207750821737840042745530876391793484035024644475535353227851321505537398888106855012746117

pt = ""

for i in range(5):
    d = pow(friendPublicKeyList[i][1], -1, eulerTotient)
    ct = pow(ct, d, N)

decrypted = long_to_bytes(ct)
print(decrypted)

``` 

And after running the script, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img145.png)

**Flag :** crypto{3ncrypt_y0ur_s3cr3t_w1th_y0ur_fr1end5_publ1c_k3y}

<br/>

# Everything is Still Big (Public Exponent)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img146.png)

Two files were given, source.py and output.txt. This is the code for source.py :

```python

#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long, inverse
from random import getrandbits
from math import gcd

FLAG = b"crypto{?????????????????????????????????????}"

m = bytes_to_long(FLAG)

def get_huge_RSA():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p*q
    phi = (p-1)*(q-1)
    while True:
        e = getrandbits(2046)
        if gcd(e,phi) == 1:
            d = inverse(e, phi)
            if (3*d)**4 > N:
                break
    return N,e


N, e = get_huge_RSA()
c = pow(m, e, N)

print(f'N = {hex(N)}')
print(f'e = {hex(e)}')
print(f'c = {hex(c)}')

```

This was the exact same challenge as the challenge "Everything Is Big" 2 challenges back. Output.txt had the ciphertext, modulus and exponent in Hex :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img147.png)

I got the two prime factors, the totient, the private key and then decrypted the flag.

My script :

```python

from Crypto.Util.number import long_to_bytes

N = "665166804cd78e8197073f65f58bca14e019982245fcc7cad74535e948a4e0258b2e919bf3720968a00e5240c5e1d6b8831d8fec300d969fccec6cce11dde826d3fbe0837194f2dc64194c78379440671563c6c75267f0286d779e6d91d3e9037c642a860a894d8c45b7ed564d341501cedf260d3019234f2964ccc6c56b6de8a4f66667e9672a03f6c29d95100cdf5cb363d66f2131823a953621680300ab3a2eb51c12999b6d4249dde499055584925399f3a8c7a4a5a21f095878e80bbc772f785d2cbf70a87c6b854eb566e1e1beb7d4ac6eb46023b3dc7fdf34529a40f5fc5797f9c15c54ed4cb018c072168e9c30ca3602e00ea4047d2e5686c6eb37b9"

e = "2c998e57bc651fe4807443dbb3e794711ca22b473d7792a64b7a326538dc528a17c79c72e425bf29937e47b2d6f6330ee5c13bfd8564b50e49132d47befd0ee2e85f4bfe2c9452d62ef838d487c099b3d7c80f14e362b3d97ca4774f1e4e851d38a4a834b077ded3d40cd20ddc45d57581beaa7b4d299da9dec8a1f361c808637238fa368e07c7d08f5654c7b2f8a90d47857e9b9c0a81a46769f6307d5a4442707afb017959d9a681fa1dc8d97565e55f02df34b04a3d0a0bf98b7798d7084db4b3f6696fa139f83ada3dc70d0b4c57bf49f530dec938096071f9c4498fdef9641dfbfe516c985b27d1748cc6ce1a4beb1381fb165a3d14f61032e0f76f095d"

c = "503d5dd3bf3d76918b868c0789c81b4a384184ddadef81142eabdcb78656632e54c9cb22ac2c41178607aa41adebdf89cd24ec1876365994f54f2b8fc492636b59382eb5094c46b5818cf8d9b42aed7e8051d7ca1537202d20ef945876e94f502e048ad71c7ad89200341f8071dc73c2cc1c7688494cad0110fca4854ee6a1ba999005a650062a5d55063693e8b018b08c4591946a3fc961dae2ba0c046f0848fbe5206d56767aae8812d55ee9decc1587cf5905887846cd3ecc6fc069e40d36b29ee48229c0c79eceab9a95b11d15421b8585a2576a63b9f09c56a4ca1729680410da237ac5b05850604e2af1f4ede9cf3928cbb3193a159e64482928b585ac"

N = int(N, 16)
e = int(e, 16)
c = int(c, 16)

p = 98444549679044409506244239144443867459824227934526036052949278261505813439015297459200379108752444235232667213138464076415095486907288282630595622287237215801470940146886371515679909322090871473412384894540642399950010296214525469622505798526072170187467562765920044646574445427364231529083610955760228212701

q = 131205304707717699800023219057082007986286045823683571663112014612188606710079038751853416273709729039622908861933527111469616900188875912430487264576215232569029320804579614330240773622645122871884209068761138439268551367198798009790636662892148063583135747945604771740458352899202428704645256790931460695949

eulerTotient = (p-1) * (q-1)

d = pow(e, -1, eulerTotient)

pt = pow(c, d, N)
decrypted = long_to_bytes(pt)

print(decrypted)

```
And after running it, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img148.png)

**Flag :** crypto{bon3h5_4tt4ck_i5_sr0ng3r_th4n_w13n3r5}

<br/>

# Endless Emails (Public Exponent)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img149.png)

Two files were given, johan.py and output.txt. This is the code for johan.py :

```python

#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, getPrime
from secret import messages


def RSA_encrypt(message):
    m = bytes_to_long(message)
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    e = 3
    c = pow(m, e, N)
    return N, e, c


for m in messages:
    N, e, c = RSA_encrypt(m)
    print(f"n = {N}")
    print(f"e = {e}")
    print(f"c = {c}")

```

And this is what we got for output.txt :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img150.png)

So we have 7 different modulii corresponding to 7 ciphertexts and all of them have the same public exponent of 3. The challenge also states that "Poor Johan has been answering emails all day and the students are all asking the **same questions**" which indicates that at least some of the messages will be repeated. So if we know that at least 3 messages are repeated and the same public exponent is used and assuming that the modulii are relatively prime, we could use <a href="https://www.youtube.com/watch?v=aS57JCzJw_o" target="_blank">Håstad's broadcast attack</a> as explained by the video. Wikipedia also provides a useful <a href="https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H%C3%A5stad's_broadcast_attack" target="_blank">explanation</a> :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img151.png)

So as long as we have 3 different ciphertexts whose modulii are relatively prime for the corresponding public exponent (3 in this case) and the messages are the same, we can use the Chinese remainder theorem (CRT) to get the message cubed and cube rooting that will give us the message. So we could choose combinations of 3 ciphertexts and their correspoding modulii from the list of 7 and after finding the cube root of the message cubed (found via CRT), we will check if it is printable in ASCII. If it isn't, we will move on to the next one and stop only if a printable ASCII output is found. The reason I chose 3 is because I wasn't sure how many messages were the same.

The code that I wrote :

```python

from Crypto.Util.number import long_to_bytes
from sympy.ntheory.modular import crt
from sympy import cbrt
import itertools

messageList = [(14528915758150659907677315938876872514853653132820394367681510019000469589767908107293777996420037715293478868775354645306536953789897501630398061779084810058931494642860729799059325051840331449914529594113593835549493208246333437945551639983056810855435396444978249093419290651847764073607607794045076386643023306458718171574989185213684263628336385268818202054811378810216623440644076846464902798568705083282619513191855087399010760232112434412274701034094429954231366422968991322244343038458681255035356984900384509158858007713047428143658924970374944616430311056440919114824023838380098825914755712289724493770021, 3, 6965891612987861726975066977377253961837139691220763821370036576350605576485706330714192837336331493653283305241193883593410988132245791554283874785871849223291134571366093850082919285063130119121338290718389659761443563666214229749009468327825320914097376664888912663806925746474243439550004354390822079954583102082178617110721589392875875474288168921403550415531707419931040583019529612270482482718035497554779733578411057633524971870399893851589345476307695799567919550426417015815455141863703835142223300228230547255523815097431420381177861163863791690147876158039619438793849367921927840731088518955045807722225), (20463913454649855046677206889944639231694511458416906994298079596685813354570085475890888433776403011296145408951323816323011550738170573801417972453504044678801608709931200059967157605416809387753258251914788761202456830940944486915292626560515250805017229876565916349963923702612584484875113691057716315466239062005206014542088484387389725058070917118549621598629964819596412564094627030747720659155558690124005400257685883230881015636066183743516494701900125788836869358634031031172536767950943858472257519195392986989232477630794600444813136409000056443035171453870906346401936687214432176829528484662373633624123, 3, 5109363605089618816120178319361171115590171352048506021650539639521356666986308721062843132905170261025772850941702085683855336653472949146012700116070022531926476625467538166881085235022484711752960666438445574269179358850309578627747024264968893862296953506803423930414569834210215223172069261612934281834174103316403670168299182121939323001232617718327977313659290755318972603958579000300780685344728301503641583806648227416781898538367971983562236770576174308965929275267929379934367736694110684569576575266348020800723535121638175505282145714117112442582416208209171027273743686645470434557028336357172288865172), (19402640770593345339726386104915705450969517850985511418263141255686982818547710008822417349818201858549321868878490314025136645036980129976820137486252202687238348587398336652955435182090722844668488842986318211649569593089444781595159045372322540131250208258093613844753021272389255069398553523848975530563989367082896404719544411946864594527708058887475595056033713361893808330341623804367785721774271084389159493974946320359512776328984487126583015777989991635428744050868653379191842998345721260216953918203248167079072442948732000084754225272238189439501737066178901505257566388862947536332343196537495085729147, 3, 5603386396458228314230975500760833991383866638504216400766044200173576179323437058101562931430558738148852367292802918725271632845889728711316688681080762762324367273332764959495900563756768440309595248691744845766607436966468714038018108912467618638117493367675937079141350328486149333053000366933205635396038539236203203489974033629281145427277222568989469994178084357460160310598260365030056631222346691527861696116334946201074529417984624304973747653407317290664224507485684421999527164122395674469650155851869651072847303136621932989550786722041915603539800197077294166881952724017065404825258494318993054344153), (12005639978012754274325188681720834222130605634919280945697102906256738419912110187245315232437501890545637047506165123606573171374281507075652554737014979927883759915891863646221205835211640845714836927373844277878562666545230876640830141637371729405545509920889968046268135809999117856968692236742804637929866632908329522087977077849045608566911654234541526643235586433065170392920102840518192803854740398478305598092197183671292154743153130012885747243219372709669879863098708318993844005566984491622761795349455404952285937152423145150066181043576492305166964448141091092142224906843816547235826717179687198833961, 3, 1522280741383024774933280198410525846833410931417064479278161088248621390305797210285777845359812715909342595804742710152832168365433905718629465545306028275498667935929180318276445229415104842407145880223983428713335709038026249381363564625791656631137936935477777236936508600353416079028339774876425198789629900265348122040413865209592074731028757972968635601695468594123523892918747882221891834598896483393711851510479989203644477972694520237262271530260496342247355761992646827057846109181410462131875377404309983072358313960427035348425800940661373272947647516867525052504539561289941374722179778872627956360577), (17795451956221451086587651307408104001363221003775928432650752466563818944480119932209305765249625841644339021308118433529490162294175590972336954199870002456682453215153111182451526643055812311071588382409549045943806869173323058059908678022558101041630272658592291327387549001621625757585079662873501990182250368909302040015518454068699267914137675644695523752851229148887052774845777699287718342916530122031495267122700912518207571821367123013164125109174399486158717604851125244356586369921144640969262427220828940652994276084225196272504355264547588369516271460361233556643313911651916709471353368924621122725823, 3, 8752507806125480063647081749506966428026005464325535765874589376572431101816084498482064083887400646438977437273700004934257274516197148448425455243811009944321764771392044345410680448204581679548854193081394891841223548418812679441816502910830861271884276608891963388657558218620911858230760629700918375750796354647493524576614017731938584618983084762612414591830024113057983483156974095503392359946722756364412399187910604029583464521617256125933111786441852765229820406911991809039519015434793656710199153380699319611499255869045311421603167606551250174746275803467549814529124250122560661739949229005127507540805), (25252721057733555082592677470459355315816761410478159901637469821096129654501579313856822193168570733800370301193041607236223065376987811309968760580864569059669890823406084313841678888031103461972888346942160731039637326224716901940943571445217827960353637825523862324133203094843228068077462983941899571736153227764822122334838436875488289162659100652956252427378476004164698656662333892963348126931771536472674447932268282205545229907715893139346941832367885319597198474180888087658441880346681594927881517150425610145518942545293750127300041942766820911120196262215703079164895767115681864075574707999253396530263, 3, 23399624135645767243362438536844425089018405258626828336566973656156553220156563508607371562416462491581383453279478716239823054532476006642583363934314982675152824147243749715830794488268846671670287617324522740126594148159945137948643597981681529145611463534109482209520448640622103718682323158039797577387254265854218727476928164074249568031493984825273382959147078839665114417896463735635546290504843957780546550577300001452747760982468547756427137284830133305010038339400230477403836856663883956463830571934657200851598986174177386323915542033293658596818231793744261192870485152396793393026198817787033127061749), (19833203629283018227011925157509157967003736370320129764863076831617271290326613531892600790037451229326924414757856123643351635022817441101879725227161178559229328259469472961665857650693413215087493448372860837806619850188734619829580286541292997729705909899738951228555834773273676515143550091710004139734080727392121405772911510746025807070635102249154615454505080376920778703360178295901552323611120184737429513669167641846902598281621408629883487079110172218735807477275590367110861255756289520114719860000347219161944020067099398239199863252349401303744451903546571864062825485984573414652422054433066179558897, 3, 15239683995712538665992887055453717247160229941400011601942125542239446512492703769284448009141905335544729440961349343533346436084176947090230267995060908954209742736573986319254695570265339469489948102562072983996668361864286444602534666284339466797477805372109723178841788198177337648499899079471221924276590042183382182326518312979109378616306364363630519677884849945606288881683625944365927809405420540525867173639222696027472336981838588256771671910217553150588878434061862840893045763456457939944572192848992333115479951110622066173007227047527992906364658618631373790704267650950755276227747600169403361509144)]
moduluslist = []
cipherList = []

for i in range(7):
    moduluslist.append(messageList[i][0])
    cipherList.append(messageList[i][2])

iList = [0, 1, 2, 3, 4, 5, 6]
combinationsList = list(itertools.combinations(iList, 3))

for i in range (len(combinationsList)):
    chosenCombination = combinationsList[i]
    cc1, cc2, cc3 = chosenCombination[0], chosenCombination[1], chosenCombination[2]
    chosenModulusList = [moduluslist[cc1], moduluslist[cc2], moduluslist[cc3]]
    chosenCipherList = [cipherList[cc1], cipherList[cc2], cipherList[cc3]]
    messageCubed = crt(chosenModulusList, chosenCipherList)
    message = long_to_bytes(cbrt(messageCubed[0]))
    if (message.isascii()):
        print(message)
        break
        
```

And after running the script, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img152.png)

Out of curiosity, I wanted to know how many messages were the same. Previously I was selecting 3 ciphertexts at a time. When I increased this number to 4, the flag was still printed out but when I increased it to 5, nothing was printed out. This means that 4 messages were the same.

**Flag :** crypto{1f_y0u_d0nt_p4d_y0u_4r3_Vuln3rabl3}




