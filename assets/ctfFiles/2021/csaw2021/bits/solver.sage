from pwn import *
from Crypto.Util.number import *
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

local = False
debug = False

r = remote("crypto.chal.csaw.io", 5010, level = 'debug') if debug else remote("crypto.chal.csaw.io", 5010)

r.recvuntil(b'N = ')
N = int(r.recvline())
r.recvuntil(b'G = ')
G = mod(int(r.recvline()), N)
r.recvuntil(b'publ = ')
publ = mod(int(r.recvline()), N)
r.recvuntil(b'alice = ')
alice = mod(int(r.recvline()), N)
r.recvuntil(b'nbits = ')
nbits = int(r.recvline())
r.recvuntil(b'FLAG = ')
encryptedFlag = int(r.recvline(), 16)

print(N, G, publ, alice, nbits, encryptedFlag)

#Parameters gotten from the server, note that N and G are always constant :
#N = 1264774171500162520522740123707654912813731191511600716918716574718457223687306654609462735310087859826053230623347849924104479609383350278302774436797213741150063894250655073009487778309401701437562813695437500274843520937515731255706515213415007999907839388181535469916350256765596422669114523648082369
#G = 2
#publ = 424861199968523540408732228099069099948534585512367990869892707674935963900611709427300784616702426814860058729683119622339265528985124052411245179500989114843289071582895607761396828751227690992178572360085027227641972904834296869178989065933598523185690739008294641069176079066328291953808609712486835
#alice = 90569259784101573278544411031411338956193931979912490005184431615233345083120574080916887715932712435195886713763094029537271814590327498828215826994733997547107069622547025263947630030135183039092919240982751438698555258106885502101729360110142535723102744463203618827942784702735872004159590264071557
#encryptedFlag = 6829009975510909842168391069944851160579087967996828690875096804086661197441010759982776605024378472510625940228975023


def oracle(h):
    r.sendline(str(h).encode())
    bit = int(r.recvline(keepends=False).decode())
    return bit

def right_reduction(n, g, h, i):
    R = 0
    for j in range(883, i, -1):
        h *= g^(2^(j-1))
    for j in range(i, 0, -1):
        bit = oracle(h)
        print(f"{j}: {bit}")
        if bit == 1:
            R += 1 << j
            h *= g^-(2^j)
        else:
            pass
        h *= g^(2^(j-1))
    return R


S = right_reduction(N, G, pow(G, N), 510)

if pow(G, S) == pow(G, N):
    print(f"Found {s = }")
elif pow(G, S + 1) == pow(G, N):
    s += 1
    print(f"Found {s = }")


#S = 74059460877869774991785377055039730589891937956359353408293798308304935074434675003466766367942215310608899807698868040431917374002812012518769752694125

var ("P, Q")

eq1 = (S == P + Q - 1) 
eq2 = (N == P * Q)

p = solve([eq1, eq2], [P, Q], solution_dict=True)[0][P]

assert int(N) % int(p) == 0

q = int(N)//int(p)

assert N == p*q


# https://crypto.stackexchange.com/questions/21097/discrete-logarithm-modulo-a-smooth-number

publP = mod(int(publ), p)
publQ = mod(int(publ), q)

y = publP.log(2)
z = publQ.log(2)

d = crt([y, z], [int(p)-1, int(q)-1])

print(f"Found secret integer {d}")
#d = 141969641146171053059785808427582284971104153488378362924480259081962678744549404450587633366558816974500827027761816935772997097895735046172610940767615536538049730214150219410292879721185412328366167886674156648859872376872077587848758737883594528833282986475887300302707668758209237572591894346219310

key = pow(alice, d, N)
print(key)
#key = 594807822095334741057051620171396964019351564890894203928169190126461806308549435025248323868458092982166978694503647098000456023924393502691705391685441611869539041261186566093550374349863029469388639761010988841288179860043880441953525279127769332238007038702727402475636786533812164271387985856187587