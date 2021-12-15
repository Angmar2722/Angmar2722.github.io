from sage.all import *
from math import gcd
import sys
from Crypto.Util.number import *
from tqdm import tqdm

sys.setrecursionlimit(100000)

def polynomial_xgcd(a, b):
    """
    Computes the extended GCD of two polynomials using Euclid's algorithm.
    :param a: the first polynomial
    :param b: the second polynomial
    :return: a tuple containing r, s, and t
    """
    assert a.base_ring() == b.base_ring()

    r_prev, r = a, b
    s_prev, s = 1, 0
    t_prev, t = 0, 1

    while r:
        try:
            q = r_prev // r
            r_prev, r = r, r_prev - q * r
            s_prev, s = s, s_prev - q * s
            t_prev, t = t, t_prev - q * t
        except RuntimeError:
            raise ArithmeticError("r is not invertible", r)

    return r_prev, s_prev, t_prev

def polynomial_inverse(p, m):
    """
    Computes the inverse of a polynomial modulo a polynomial using the extended GCD.
    :param p: the polynomial
    :param m: the polynomial modulus
    :return: the inverse of p modulo m
    """
    g, s, t = polynomial_xgcd(p, m)
    return s * g.lc() ** -1

def factorize(N, D):
    """
    Recovers the prime factors from a modulus using Cheng's elliptic curve complex multiplication method.
    More information: Sedlacek V. et al., "I want to break square-free: The 4p - 1 factorization method and its RSA backdoor viability"
    :param N: the modulus
    :param D: the discriminant to use to generate the Hilbert polynomial
    :return: a tuple containing the prime factors
    """
    assert D % 8 == 3, "D should be square-free"

    zmodn = Zmod(N)
    pr = zmodn["x"]

    H = pr(hilbert_class_polynomial(-D))
    Q = pr.quotient(H)
    j = Q.gen()

    try:
        k = j * polynomial_inverse((1728 - j).lift(), H)
    except ArithmeticError as err:
        # If some polynomial was not invertible during XGCD calculation, we can factor n.
        p = gcd(int(err.args[1].lc()), N)
        return int(p), int(N // p)

    E = EllipticCurve(Q, [3 * k, 2 * k])
    while True:
        x = zmodn.random_element()

        #print(f"Calculating division polynomial of Q{x}...")
        z = E.division_polynomial(N, x=Q(x))

        try:
            d, _, _ = polynomial_xgcd(z.lift(), H)
        except ArithmeticError as err:
            # If some polynomial was not invertible during XGCD calculation, we can factor n.
            p = gcd(int(err.args[1].lc()), N)
            return int(p), int(N // p)

        p = gcd(int(d), N)
        if 1 < p < N:
            return int(p), int(N // p)

n = 1107089530865291005792928480548189885479977703442107533313356742591951667125087535826010797157037462511849114045516095117408586807231706532861043400760247491545435256670371588020835746662537074526723641129179212527096161455117334264697975671817050553066298766943783138197527420889207777538892682506714149210612017224796083819420558023833783052917520724666512823601961316820680461331809092698744718706733677296285030329390980535993866209005527261307419128592439300515586162373258781346476786339580690681056167085317745381659204404735103663112312693895151699459534695810700103198736323229849182269856798173444808702578924983265251814786149856862410628895786620259450924651662102926294106305830166586486290823127164862167085238586221495862582249250498351063486438791642573599997108715545357001141390463446119948917429169048381714872075664706511363903028841832059662969788526342879432038294204060254076089346916015904423832151508649589004393115281760187305175538986217342069866841444503926477979016789070563231454129660241269241703644048193901022392096029852555194381071481792694321652042639278577632914177886450520371875549477493674646527815335341293227066407822982856815277497965140254717599437693337147736442753971955722420621907486011
e = 6551
c = 1058973149865164549817155137780815812623456388672543624635614085499244505987561039674767711743995552767627702752408380616883846211075499731545623651849875151404363710832001498313789374024771997636035858261588415813326816005995068929381352608925142940988357078368871961040798086164564448858106053108740194519944625550651430368864502736439474454098320996590422347650921528404245531928248700516748854749201075928521539792773428322450795957658901093109369813686410937987553062385702498313602204488073904351501964183374202465473380985602391885101503608627656341003137115517005592591746184951205036757837506166599417314523057848473058411480339477693062957272869601856015496182168433136199994935250109784152100245527161736252507193119985157036229139371883973535111593404077185046749750799222687057579590699112612517984739574870394435873979331373499970168615775526148858445852147161884965435806142797327740412603655959161046424598064190354357612721920648035385092037901968197029138094288551013982417040611621259974923351358663093743109476722870043782424356300204605852351738436494837101112320000689343206094235482366575795725469918145189121430260345459865260920783660140849521053205162497433393126952425091234633490186637000777737106192645410
D = 987

p, q = factorize(n, D)

assert p*q == n

def roots_of_unity(e, phi, n, rounds=250):
    # Divide common factors of `phi` and `e` until they're coprime.
    phi_coprime = phi
    while gcd(phi_coprime, e) != 1:
        phi_coprime //= gcd(phi_coprime, e)

    # Don't know how many roots of unity there are, so just try and collect a bunch
    roots = set(pow(i, phi_coprime, n) for i in range(1, rounds))

    assert all(pow(root, e, n) == 1 for root in roots)
    return roots, phi_coprime

# n is prime
# Problem: e and phi are not coprime - d does not exist
phi = (p - 1) * (q-1)

# Find e'th roots of unity modulo n
roots, phi_coprime = roots_of_unity(e, phi, n)

# Use our `phi_coprime` to get one possible plaintext
d = inverse_mod(e, phi_coprime)
pt = pow(c, d, n)
assert pow(pt, e, n) == c

# Use the roots of unity to get all other possible plaintexts
pts = [(pt * root) % n for root in roots]
pts = [long_to_bytes(pt) for pt in pts]

for pt in pts:
    if b'idek' in pt: 
        print(pt)

#b'idek{A_mashup_of_2_interesting_papers?_4p-1_and_coprime_e-phi}'