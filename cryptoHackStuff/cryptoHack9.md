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

<br/>

# Infinite Descent (Primes Part 2)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img153.png)

Two files were given, descent.py and output.txt. This is the code for descent.py :

```python

#!/usr/bin/env python3

import random
from Crypto.Util.number import bytes_to_long, isPrime

FLAG = b"crypto{???????????????????}"


def getPrimes(bitsize):
    r = random.getrandbits(bitsize)
    p, q = r, r
    while not isPrime(p):
        p += random.getrandbits(bitsize//4)
    while not isPrime(q):
        q += random.getrandbits(bitsize//8)
    return p, q


m = bytes_to_long(FLAG)
p, q = getPrimes(2048)
n = p * q
e = 0x10001
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")

```

The output.txt had the modulus N, exponent and ciphertext. Turns out factordb (our lord and saviour) had the prime factors for the modulus :D

Solve script (the usual) :

```python

import random
from Crypto.Util.number import long_to_bytes

n = 383347712330877040452238619329524841763392526146840572232926924642094891453979246383798913394114305368360426867021623649667024217266529000859703542590316063318592391925062014229671423777796679798747131250552455356061834719512365575593221216339005132464338847195248627639623487124025890693416305788160905762011825079336880567461033322240015771102929696350161937950387427696385850443727777996483584464610046380722736790790188061964311222153985614287276995741553706506834906746892708903948496564047090014307484054609862129530262108669567834726352078060081889712109412073731026030466300060341737504223822014714056413752165841749368159510588178604096191956750941078391415634472219765129561622344109769892244712668402761549412177892054051266761597330660545704317210567759828757156904778495608968785747998059857467440128156068391746919684258227682866083662345263659558066864109212457286114506228470930775092735385388316268663664139056183180238043386636254075940621543717531670995823417070666005930452836389812129462051771646048498397195157405386923446893886593048680984896989809135802276892911038588008701926729269812453226891776546037663583893625479252643042517196958990266376741676514631089466493864064316127648074609662749196545969926051                                                                  
e = 65537
ct = 98280456757136766244944891987028935843441533415613592591358482906016439563076150526116369842213103333480506705993633901994107281890187248495507270868621384652207697607019899166492132408348789252555196428608661320671877412710489782358282011364127799563335562917707783563681920786994453004763755404510541574502176243896756839917991848428091594919111448023948527766368304503100650379914153058191140072528095898576018893829830104362124927140555107994114143042266758709328068902664037870075742542194318059191313468675939426810988239079424823495317464035252325521917592045198152643533223015952702649249494753395100973534541766285551891859649320371178562200252228779395393974169736998523394598517174182142007480526603025578004665936854657294541338697513521007818552254811797566860763442604365744596444735991732790926343720102293453429936734206246109968817158815749927063561835274636195149702317415680401987150336994583752062565237605953153790371155918439941193401473271753038180560129784192800351649724465553733201451581525173536731674524145027931923204961274369826379325051601238308635192540223484055096203293400419816024111797903442864181965959247745006822690967920957905188441550106930799896292835287867403979631824085790047851383294389  

p = 19579267410474709598749314750954211170621862561006233612440352022286786882372619130071639824109783540564512429081674132336811972404563957025465034025781206466631730784516337210291334356396471732168742739790464109881039219452504456611589154349427303832789968502204300316585544080003423669120186095188478480761108168299370326928127888786819392372477069515318179751702985809024210164243409544692708684215042226932081052831028570060308963093217622183111643335692361019897449265402290540025790581589980867847884281862216603571536255382298035337865885153328169634178323279004749915197270120323340416965014136429743252761521
q = 19579267410474709598749314750954211170621862561006233612440352022286786882372619130071639824109783540564512429081674132336811972404563957025465034025781206466631730784516337210291334356396471732168742739790464109881039219452504456611589154349427303832789968502204300316585544080003423669120186095188478480761108168299370326928127888786819392372477069515318179751702985809024210164243409544692708684215042226932081052831028570060308963093217622183111643335692362635203582868526178838018946986792656819885261069890315500550802303622551029821058459163702751893798676443415681144429096989664473705850619792495553724950931


eulerTotient = (p - 1) * (q - 1)
d = pow(e, -1, eulerTotient)
pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)
print(decrypted)

```

After running it, we get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img154.png)

This was definitely not how you were expected to solve it..... Looking at other people's solutions, turns out you had to use Fermat factorization

**Flag :** crypto{f3rm47_w45_4_g3n1u5}

<br/>

# Marin's Secrets (Primes Part 2)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img155.png)

Two files were given, marin.py and output.txt. This is the code for marin.py :

```python

#!/usr/bin/env python3

import random
from Crypto.Util.number import bytes_to_long, inverse
from secret import secrets, flag


def get_prime(secret):
    prime = 1
    for _ in range(secret):
        prime = prime << 1
    return prime - 1


secrets = random.shuffle(secrets)

m = bytes_to_long(flag)
p = get_prime(secrets[0])
q = get_prime(secrets[1])
n = p * q
e = 0x10001
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")

```

Output.txt had the modulus, public exponent and ciphertext. Our lord and saviour had the prime factors for the modulus (once again definitely not the way to solve this) :

```python

from Crypto.Util.number import long_to_bytes

n = 658416274830184544125027519921443515789888264156074733099244040126213682497714032798116399288176502462829255784525977722903018714434309698108208388664768262754316426220651576623731617882923164117579624827261244506084274371250277849351631679441171018418018498039996472549893150577189302871520311715179730714312181456245097848491669795997289830612988058523968384808822828370900198489249243399165125219244753790779764466236965135793576516193213175061401667388622228362042717054014679032953441034021506856017081062617572351195418505899388715709795992029559042119783423597324707100694064675909238717573058764118893225111602703838080618565401139902143069901117174204252871948846864436771808616432457102844534843857198735242005309073939051433790946726672234643259349535186268571629077937597838801337973092285608744209951533199868228040004432132597073390363357892379997655878857696334892216345070227646749851381208554044940444182864026513709449823489593439017366358869648168238735087593808344484365136284219725233811605331815007424582890821887260682886632543613109252862114326372077785369292570900594814481097443781269562647303671428895764224084402259605109600363098950091998891375812839523613295667253813978434879172781217285652895469194181218343078754501694746598738215243769747956572555989594598180639098344891175879455994652382137038240166358066403475457

e = 65537

ct = 400280463088930432319280359115194977582517363610532464295210669530407870753439127455401384569705425621445943992963380983084917385428631223046908837804126399345875252917090184158440305503817193246288672986488987883177380307377025079266030262650932575205141853413302558460364242355531272967481409414783634558791175827816540767545944534238189079030192843288596934979693517964655661507346729751987928147021620165009965051933278913952899114253301044747587310830419190623282578931589587504555005361571572561916866063458812965314474160499067525067495140150092119620928363007467390920130717521169105167963364154636472055084012592138570354390246779276003156184676298710746583104700516466091034510765027167956117869051938116457370384737440965109619578227422049806566060571831017610877072484262724789571076529586427405780121096546942812322324807145137017942266863534989082115189065560011841150908380937354301243153206428896320576609904361937035263985348984794208198892615898907005955403529470847124269512316191753950203794578656029324506688293446571598506042198219080325747328636232040936761788558421528960279832802127562115852304946867628316502959562274485483867481731149338209009753229463924855930103271197831370982488703456463385914801246828662212622006947380115549529820197355738525329885232170215757585685484402344437894981555179129287164971002033759724456

p = pow(2, 2203) - 1
q = pow(2, 2281) - 1

eulerTotient = (p - 1) * (q - 1)
d = pow(e, -1, eulerTotient)
pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)
print(decrypted)

```

After running it we get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img156.png)

After looking at other people's solutions, turns out you had to check if the modulus was divisible by a Mersenne prime (2^n - 1).

**Flag :** crypto{Th3se_Pr1m3s_4r3_t00_r4r3}

<br/>

# Fast Primes (Primes Part 2)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img157.png)

Three files were given, fast_primes.py, ciphertext.txt and key.pem. This is the code for fast_primes.py :

```python

#!/usr/bin/env python3

import math
import random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, inverse
from gmpy2 import is_prime


FLAG = b"crypto{????????????}"

primes = []


def sieve(maximum=10000):
    # In general Sieve of Sundaram, produces primes smaller
    # than (2*x + 2) for a number given number x. Since
    # we want primes smaller than maximum, we reduce maximum to half
    # This array is used to separate numbers of the form
    # i+j+2ij from others where 1 <= i <= j
    marked = [False]*(int(maximum/2)+1)

    # Main logic of Sundaram. Mark all numbers which
    # do not generate prime number by doing 2*i+1
    for i in range(1, int((math.sqrt(maximum)-1)/2)+1):
        for j in range(((i*(i+1)) << 1), (int(maximum/2)+1), (2*i+1)):
            marked[j] = True

    # Since 2 is a prime number
    primes.append(2)

    # Print other primes. Remaining primes are of the
    # form 2*i + 1 such that marked[i] is false.
    for i in range(1, int(maximum/2)):
        if (marked[i] == False):
            primes.append(2*i + 1)


def get_primorial(n):
    result = 1
    for i in range(n):
        result = result * primes[i]
    return result


def get_fast_prime():
    M = get_primorial(40)
    while True:
        k = random.randint(2**28, 2**29-1)
        a = random.randint(2**20, 2**62-1)
        p = k * M + pow(e, a, M)

        if is_prime(p):
            return p


sieve()

e = 0x10001
m = bytes_to_long(FLAG)
p = get_fast_prime()
q = get_fast_prime()
n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

key = RSA.construct((n, e, d))
cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(FLAG)

assert cipher.decrypt(ciphertext) == FLAG

exported = key.publickey().export_key()
with open("key.pem", 'wb') as f:
    f.write(exported)

with open('ciphertext.txt', 'w') as f:
    f.write(ciphertext.hex())

```

Ciphertext.txt had the hex ciphertext and key.pem had the public key and exponent in a pem format. I first extracted the modulus N and public exponent from key.pem, factored it using factordb and then decrypted it using the private exponent. After reading the other solutions, it turns out the right way to do this way by using the <a href="https://en.wikipedia.org/wiki/ROCA_vulnerability" target="_blank">ROCA vulnerability</a>.

My solve script :

```python

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

key_encoded='''-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJATKIe3jfj1qY7zuX5Eg0JifAUOq6RUwLz
Ruiru4QKcvtW0Uh1KMp1GVt4MmKDiQksTok/pKbJsBFCZugFsS3AjQIDAQAB
-----END PUBLIC KEY-----'''

pubkey2 = serialization.load_pem_public_key(
    key_encoded.encode('ascii'),
    backend=default_backend()
)

n = pubkey2.public_numbers().n
e = pubkey2.public_numbers().e

ct = "249d72cd1d287b1a15a3881f2bff5788bc4bf62c789f2df44d88aae805b54c9a94b8944c0ba798f70062b66160fee312b98879f1dd5d17b33095feb3c5830d28"

p = 51894141255108267693828471848483688186015845988173648228318286999011443419469
q = 77342270837753916396402614215980760127245056504361515489809293852222206596161

eulerTotient = (p - 1) * (q - 1)
d = pow(e, -1, eulerTotient)

key = RSA.construct((n, e, d))
cipher = PKCS1_OAEP.new(key)
pv_key_string = key.exportKey()
with open ("private.pem", "w") as prv_file:
    print("{}".format(pv_key_string.decode()), file=prv_file)

key = RSA.importKey(open('private.pem').read())
cipher = PKCS1_OAEP.new(key)
message = cipher.decrypt(bytes.fromhex(ct))
print(message)

```

After running it we get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img158.png)

**Flag :** crypto{p00R_3570n14}

The flag "poor Estonia" is a reference to the ROCA vulnerability found <a href="https://www.usenix.org/system/files/sec20summer_parsovs_prepub.pdf
" target="_blank">previously</a> in Estonia's smart cards.

<br/>

# Ron was Wrong, Whit is Right (Primes Part 2)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img159.png)

A zip file was given which when unzipped revealed a set of 50 ciphertexts and public keys. The public keys had different exponents (65537, 17, 3) and different modulus lengths (some 2048 bit and some even 8192 bit!!!!). Another file was given, `excerpt.py` which is shown below :

```python

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


msg = "???"

with open('21.key') as f:
    key = RSA.importKey(f.read())

cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(msg)

with open('21.ciphertext', 'w') as f:
    f.write(ciphertext.hex())

```

So the challenge title refers to <a href="https://eprint.iacr.org/2012/064.pdf" target="_blank">this paper</a> which revealed that after going through millions of public keys, the researchers found that a small fraction of them contained a shared factor which would completely jeopardise the fundamental basis of RSA's security. Say you have two modulii, n1 and n2. Ideally since they are semi-prime, they should not have any factors, i.e. their GCD should be 1. But in the off chance that their GCD is not one, by computing their GCD, you could get their shared prime factor. From there everything else can also be computed to decrypt the ciphertext. So I did the same thing, my solve script involved finding the set of modulii which had a GCD which was not 1.

My solve script :

```python

from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.Util.number import long_to_bytes, inverse
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from sympy import *

def decryptText(p, q, e, n, ct):
    eulerTotient = (p - 1) * (q - 1)
    d = inverse(e, eulerTotient)
    key = RSA.construct((n, e, d))
    cipher1 = PKCS1_OAEP.new(key)
    m1 = cipher1.decrypt(bytes.fromhex(ct))
    print(m1)

ciphertextList = []
modulusList = []
publicExponentList = []

for i in range(1, 51):
    ct = open('keys_and_messages/' + str(i) + ".ciphertext",'r')
    ciphertextList.append(ct.read())
    f = open('keys_and_messages/' + str(i) + ".pem",'r')
    key = RSA.import_key(f.read())
    modulusList.append(key.n)
    publicExponentList.append(key.e)

for i in range(50):
    check = modulusList[i]
    for j in range(50):
        if (i == j):
            continue
        commonFactor = igcd(modulusList[i], modulusList[j])
        if (commonFactor != 1):
            #Getting First Block Message
            decryptText(commonFactor, (modulusList[i] // commonFactor), publicExponentList[i], modulusList[i], ciphertextList[i])
            #Getting Second Block Message
            decryptText(commonFactor, (modulusList[j] // commonFactor), publicExponentList[j], modulusList[j], ciphertextList[j])
            exit(0)

```

And after running it, you get the two plaintexts, one of which was the flag (the link is the same as the paper linked above) :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img160.png)

<p> <b>Flag :</b> crypto{3ucl1d_w0uld_b3_pr0ud} </p>

<br/>

# RSA Backdoor Viability (Primes Part 2)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img161.png)

Two files were given, the output.txt file which contained the modulus, public exponent and ciphertext as well as the source code for the prime generation :

```python

#!/usr/bin/env python3

import random
from Crypto.Util.number import bytes_to_long, getPrime, isPrime

FLAG = b"crypto{????????????????????????????????}"

def get_complex_prime():
    D = 427
    while True:
        s = random.randint(2 ** 1020, 2 ** 1021 - 1)
        tmp = D * s ** 2 + 1
        if tmp % 4 == 0 and isPrime((tmp // 4)):
            return tmp // 4


m = bytes_to_long(FLAG)
p = get_complex_prime()
q = getPrime(2048)
n = p * q
e = 0x10001
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")

```

I had no clue how to solve this the proper way so I just used factordb :D

Solve script :

```python

from Crypto.Util.number import long_to_bytes

n = 709872443186761582125747585668724501268558458558798673014673483766300964836479167241315660053878650421761726639872089885502004902487471946410918420927682586362111137364814638033425428214041019139158018673749256694555341525164012369589067354955298579131735466795918522816127398340465761406719060284098094643289390016311668316687808837563589124091867773655044913003668590954899705366787080923717270827184222673706856184434629431186284270269532605221507485774898673802583974291853116198037970076073697225047098901414637433392658500670740996008799860530032515716031449787089371403485205810795880416920642186451022374989891611943906891139047764042051071647203057520104267427832746020858026150611650447823314079076243582616371718150121483335889885277291312834083234087660399534665835291621232056473843224515909023120834377664505788329527517932160909013410933312572810208043849529655209420055180680775718614088521014772491776654380478948591063486615023605584483338460667397264724871221133652955371027085804223956104532604113969119716485142424996255737376464834315527822566017923598626634438066724763559943441023574575168924010274261376863202598353430010875182947485101076308406061724505065886990350185188453776162319552566614214624361251463
e = 65537
c = 608484617316138126443275660524263025508135383745665175433229598517433030003704261658172582370543758277685547533834085899541036156595489206369279739210904154716464595657421948607569920498815631503197235702333017824993576326860166652845334617579798536442066184953550975487031721085105757667800838172225947001224495126390587950346822978519677673568121595427827980195332464747031577431925937314209391433407684845797171187006586455012364702160988147108989822392986966689057906884691499234298351003666019957528738094330389775054485731448274595330322976886875528525229337512909952391041280006426003300720547721072725168500104651961970292771382390647751450445892361311332074663895375544959193148114635476827855327421812307562742481487812965210406231507524830889375419045542057858679609265389869332331811218601440373121797461318931976890674336807528107115423915152709265237590358348348716543683900084640921475797266390455366908727400038393697480363793285799860812451995497444221674390372255599514578194487523882038234487872223540513004734039135243849551315065297737535112525440094171393039622992561519170849962891645196111307537341194621689797282496281302297026025131743423205544193536699103338587843100187637572006174858230467771942700918388

p = 20365029276121374486239093637518056591173153560816088704974934225137631026021006278728172263067093375127799517021642683026453941892085549596415559632837140072587743305574479218628388191587060262263170430315761890303990233871576860551166162110565575088243122411840875491614571931769789173216896527668318434571140231043841883246745997474500176671926153616168779152400306313362477888262997093036136582318881633235376026276416829652885223234411339116362732590314731391770942433625992710475394021675572575027445852371400736509772725581130537614203735350104770971283827769016324589620678432160581245381480093375303381611323

q = 34857423162121791604235470898471761566115159084585269586007822559458774716277164882510358869476293939176287610274899509786736824461740603618598549945273029479825290459062370424657446151623905653632181678065975472968242822859926902463043730644958467921837687772906975274812905594211460094944271575698004920372905721798856429806040099698831471709774099003441111568843449452407542799327467944685630258748028875103444760152587493543799185646692684032460858150960790495575921455423185709811342689185127936111993248778962219413451258545863084403721135633428491046474540472029592613134125767864006495572504245538373207974181

eulerTotient = (p - 1) * (q - 1)
d = pow(e, -1, eulerTotient)
pt = pow(c, d, n)
decrypted = long_to_bytes(pt)
print(decrypted)

```

<p> <b>Flag :</b> crypto{I_want_to_Break_Square-free_4p-1} </p>

<br/>

# Bespoke Padding (Padding)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img168.png)

Source code for what was running on the server :

```python

#!/usr/bin/env python3

from utils import listener
from Crypto.Util.number import bytes_to_long, getPrime
import random

FLAG = b'crypto{???????????????????????????}'


class Challenge():
    def __init__(self):
        self.before_input = "Come back as much as you want! You'll never get my flag.\n"
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.N = self.p * self.q
        self.e = 11

    def pad(self, flag):
        m = bytes_to_long(flag)
        a = random.randint(2, self.N)
        b = random.randint(2, self.N)
        return (a, b), a*m+b

    def encrypt(self, flag):
        pad_var, pad_msg = self.pad(flag)
        encrypted = (pow(pad_msg, self.e, self.N), self.N)
        return pad_var, encrypted

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_flag':
            pad_var, encrypted = self.encrypt(FLAG)
            return {"encrypted_flag": encrypted[0], "modulus": encrypted[1], "padding": pad_var}

        else:
            return {"error": "Invalid option"}


"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=13386)

```

So when we connect to the server, after a random 2048 bit modulus is generated, we can request the server to provide an encrypted flag. This flag has been padded in the form `a*m + b` with `m` being the flag (in decimal) and `a, b` being two random numbers generated between 2 and the modulus `n`. So if we ask for the same encrypted flag two different times (during the same connection - this is important as with the same connection, the modulus would remain constant), we could get two different forms of the encrypted flag (a1*m + b1) and (a2*m + b2) where there is a relation between the two encrypted messages. This can be exploited via the <a href="https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin-Reiter_related-message_attack" target="_blank">Franklin-Reiter related-message attack</a> which was first explained in <a href="https://link.springer.com/content/pdf/10.1007/3-540-68339-9_1.pdf" target="_blank">this</a> paper. 

I also found <a href="https://crypto.stackexchange.com/questions/30884/help-understanding-basic-franklin-reiter-related-message-attack" target="_blank">this</a> thread to be particularly useful in the implementation of this attack as I had not used <a href="https://www.sagemath.org/" target="_blank">Sagemath</a> previously (first time trying out Sage which was needed since we were dealing with polynomials and roots).

This was my Sage solve script :

```python

from Crypto.Util.number import *
from pwn import *
import json

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

r = remote('socket.cryptohack.org', 13386)
modulusList = []
cipherList = []
aList = []
bList = []

for i in range(2):
    to_send = {
        "option": "get_flag"
    }
    json_send(to_send)
    r.recvline()
    received = json_recv()
    encryptedFlag = received["encrypted_flag"]
    cipherList.append(encryptedFlag)
    modulus = received["modulus"]
    modulusList.append(modulus)
    a = received['padding'][0]
    aList.append(a)
    b = received['padding'][1]
    bList.append(b)
    to_send = {
        "option": "get_flag"
    }
    json_send(to_send)

n = modulusList[0]
c1 = cipherList[0]
c2 = cipherList[1]
a1 = aList[0]
a2 = aList[1]
b1 = bList[0]
b2 = bList[1]
e = 11

R.<X> = Zmod(n)[]
f1 = (a1*X + b1)^e - c1
f2 = (a2*X + b2)^e - c2

def my_gcd(a, b): 
    return a.monic() if b == 0 else my_gcd(b, a % b)

print(long_to_bytes(- my_gcd(f1, f2).coefficients()[0]))

```

After running the script, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img169.png)

<p> <b>Flag :</b> crypto{linear_padding_isnt_padding} </p>

<br/>

# Signing Server (Signatures Part 1)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img163.png)

The source code file for the server was given :

```python

#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener



class Challenge():
    def __init__(self):
        self.before_input = "Welcome to my signing server. You can get_pubkey, get_secret, or sign.\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_pubkey':
            return {"N": hex(N), "e": hex(E) }

        elif your_input['option'] == 'get_secret':
            secret = bytes_to_long(SECRET_MESSAGE)
            return {"secret": hex(pow(secret, E, N)) }

        elif your_input['option'] == 'sign':
            msg = int(your_input['msg'], 16)
            return {"signature": hex(pow(msg, D, N)) }

        else:
            return {"error": "Invalid option"}


listener.start_server(port=13374)

```

So we have the ciphertext (secret message) and if you look at the signature generation algorithm, it will decrypt the ciphertext we send in.

Solve script :

```python

from pwn import *
import json
from Crypto.Util.number import long_to_bytes
from sympy import *

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

r = remote('socket.cryptohack.org', 13374)

def getInfo(option, output):
    to_send = {
        "option": option
    }
    json_send(to_send)
    r.recvline()
    received = json_recv()
    print(received[output])
    #print(int(received[output], 16))
    return int(received[output], 16)

#getInfo("get_pubkey", "N")
#getInfo("get_pubkey", "e")
#getInfo("get_secret", "secret")

n = 21771160289113920553146972142465234995814683559987226633675956294378135480885229083009774904629081083141904450599508033322688481167808425165020937163525671384103583167017252878303912244887261813946359532885102091257459085278683596894806698020257323990714768068711297218245422189544960869827261332526441491471751162788329542057106383192814119306090004174075547937096424776761861668156205190519821991920936089342819224776732355372197434012258887575647042307327885415171823790360018503205424910177750570755835173227132799934822949737036115013030518941036525338834446761476517640426656296554000566423790166016274458096007

e = 65537

secret = 6864915043463177492377282469996800343164301482077361279765373665532822727226792788421584831532773481708470052601056979219534433914341042945948694475101504654382578759158658652646903392036853930547737058782205064076746367015273868326718448915159758110555071844072823078536592603986995785967539448412694112073817158206385870487054537421191186729622427405285746510429363025501309326149675274595298353953707870615630811332766591701541520978776254085851339937072275417998774926884882892041726441555354227610509977945960881754602358326328488943443418609342491306813568508364497354114656469400142223866284826425003316711109

def getSignature(msg):
    to_send = {
        "option": "sign",
        "msg": msg
    }
    json_send(to_send)
    r.recvline()
    received = json_recv()
    #print(int(received["signature"], 16))
    return int(received["signature"], 16)

flagLong = getSignature("0x36616f25259cd2f073ce920144b1054d891fcd20cf243c4fc0bac556b5d7240fe92d8a19db7cfcee183c64f29585226521189b3d1c8be02d79ee754856cf1efae8a136cb02e045edd3f44b704a759f756574db89571b4b2fc3e52258ff15224e93072360afd7cea95d81029bc59f400dc1492597b958b8183c87a07a909b7ab407d44e5f65875e8b94585bbc60662a022e0c5edb18a28746ead4b8f8247cb80012d53a04ffa720cb10de0927f21a1334a49f5dae246d659672f8ff27703a52412dc9291f4ea50edd0d53a61cd8032336b3e416496bf2c424154018d2793c2d778c83fc245d8fabad2053d3e77767ba0feb3c094887e5424efbf5c5f02f618ec5")

print(long_to_bytes(flagLong))

```

And after running the script you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img164.png)

<p> <b>Flag :</b> crypto{d0n7_516n_ju57_4ny7h1n6} </p>

<br/>

# Blinding Light (Signatures Part 1)

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img165.png)

The source code file for the server was given :

```python

#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener

FLAG = "crypto{?????????????????????????????}"
ADMIN_TOKEN = b"admin=True"


class Challenge():
    def __init__(self):
        self.before_input = "Watch out for the Blinding Light\n"

    def challenge(self, your_input):
        if 'option' not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_pubkey':
            return {"N": hex(N), "e": hex(E) }

        elif your_input['option'] == 'sign':
            msg_b = bytes.fromhex(your_input['msg'])
            if ADMIN_TOKEN in msg_b:
                return {"error": "You cannot sign an admin token"}

            msg_i = bytes_to_long(msg_b)
            return {"msg": your_input['msg'], "signature": hex(pow(msg_i, D, N)) }

        elif your_input['option'] == 'verify':
            msg_b = bytes.fromhex(your_input['msg'])
            msg_i = bytes_to_long(msg_b)
            signature = int(your_input['signature'], 16)

            if msg_i < 0 or msg_i > N:
                # prevent attack where user submits admin token plus or minus N
                return {"error": "Invalid msg"}

            verified = pow(signature, E, N)
            if msg_i == verified:
                if long_to_bytes(msg_i) == ADMIN_TOKEN:
                    return {"response": FLAG}
                else:
                    return {"response": "Valid signature"}
            else:
                return {"response": "Invalid signature"}

        else:
            return {"error": "Invalid option"}


listener.start_server(port=13376)

```

The challenge name "Blinding Light" refers to a blind RSA signature attack where the signature of even a blacklisted string (in our case it is "admin=true") can be calculated. The basis of this attack can be learnt from <a href="http://the2702.com/2015/09/07/RSA-Blinding-Attack.html" target="_blank">this</a> link. 

The important part of the resource is shown below :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img166.png)

My solve script :

```python

from pwn import *
import json

from pwnlib.util.splash import splash
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sympy import *

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

r = remote('socket.cryptohack.org', 13376)

def getInfo(option, output):
    to_send = {
        "option": option
    }
    json_send(to_send)
    r.recvline()
    received = json_recv()
    return int(received[output], 16)

n = getInfo("get_pubkey", "N")
r.close()

r = remote('socket.cryptohack.org', 13376)
e = getInfo("get_pubkey", "e")
r.close()

ADMIN_TOKEN = b"admin=True"
k = 2
blindedMessage = (bytes_to_long(ADMIN_TOKEN) * pow(k, e)) % n

def getSignature(msg):
    to_send = {
        "option": "sign",
        "msg": msg
    }
    json_send(to_send)
    r.recvline()
    received = json_recv()
    return int(received["signature"], 16)

r = remote('socket.cryptohack.org', 13376)
sPrime = getSignature('{:x}'.format(blindedMessage)) 
r.close()
unblindedSignature = (sPrime // k) % n

r = remote('socket.cryptohack.org', 13376)

def verifyAndGetFlag(msg, signature):
    to_send = {
        "option": "verify",
        "msg": msg,
        "signature": signature
    }
    json_send(to_send)
    r.recvline()
    received = json_recv()
    print(received["response"])

verifyAndGetFlag(ADMIN_TOKEN.hex(), hex(unblindedSignature))

```

One thing I didn't understand was why the random number (`k`) = 3 or 7 did not work as both numbers are co-prime to the modulus `n`. I noticed that when `k` equalled 2, `sPrime % k = 0` but it was non-zero for when `k = 3 or 7`. Still many texts said that as long as k was co-prime to n, you could use it.

After running the script, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img167.png)

<p> <b>Flag :</b> crypto{m4ll34b1l17y_c4n_b3_d4n63r0u5} </p>

<br/>






