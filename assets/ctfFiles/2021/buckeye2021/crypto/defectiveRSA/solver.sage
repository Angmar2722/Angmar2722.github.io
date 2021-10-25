from Crypto.Util.number import *

e = 1440
p = 108625855303776649594296217762606721187040584561417095690198042179830062402629658962879350820293908057921799564638749647771368411506723288839177992685299661714871016652680397728777113391224594324895682408827010145323030026082761062500181476560183634668138131801648343275565223565977246710777427583719180083291
q = 124798714298572197477112002336936373035171283115049515725599555617056486296944840825233421484520319540831045007911288562132502591989600480131168074514155585416785836380683166987568696042676261271645077182221098718286132972014887153999243085898461063988679608552066508889401992413931814407841256822078696283307
n = p * q
ct = 4293606144359418817736495518573956045055950439046955515371898146152322502185230451389572608386931924257325505819171116011649046442643872945953560994241654388422410626170474919026755694736722826526735721078136605822710062385234124626978157043892554030381907741335072033672799019807449664770833149118405216955508166023135740085638364296590030244412603570120626455502803633568769117033633691251863952272305904666711949672819104143350385792786745943339525077987002410804383449669449479498326161988207955152893663022347871373738691699497135077946326510254675142300512375907387958624047470418647049735737979399600182827754

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
phi = (p - 1) * (q - 1)

# Find e'th roots of unity modulo n
roots, phi_coprime = roots_of_unity(e, phi, n)

# Use our `phi_coprime` to get one possible plaintext
d = inverse_mod(e, phi_coprime)
pt = pow(ct, d, n)
assert pow(pt, e, n) == ct

# Use the roots of unity to get all other possible plaintexts
pts = [(pt * root) % n for root in roots]
pts = [long_to_bytes(pt) for pt in pts]

for possibleFlag in pts:
    if b'buckeye{' in possibleFlag:
        print(possibleFlag)
        exit()

#b'buckeye{r0ots_0f_uN1Ty_w0rk_f0r_th1s???}'