---
layout: page
title: RSA - Primes Part 2 / Padding / Signatures Parts 1 & 2
---
<hr/>

The RSA section consists of 29 challenges. The challenges are subdivided into 7 different stages : Starter, Primes Part 1, Public Exponent, Primes Part 2, Padding, Signatures Part 1 and Signatures Part 2. Below are the writeups for the ones I managed to complete for the Primes Part 2, Padding, Signatures Part 1 and Signatures Part 2 sections :

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

After runnign the script, you get the flag :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img167.png)

<p> <b>Flag :</b> crypto{m4ll34b1l17y_c4n_b3_d4n63r0u5} </p>

