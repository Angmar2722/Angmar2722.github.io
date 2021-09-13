from pwn import *
from Crypto.Util.number import *
from math import gcd
from math import lcm

debug = True

r = remote("crypto.chal.csaw.io", 5002, level = 'debug') if debug else remote("crypto.chal.csaw.io", 5002)


#==================Helper Function For Levels One and Two==================

def getParameters():
    r.recvuntil('p = ')
    p = int(r.recvline())
    assert is_prime(p)
    r.recvuntil('a = ')
    a = int(r.recvline())
    r.recvuntil('b = ')
    b = int(r.recvline())

    r.recvuntil("P1: ")
    G = r.recvline().decode()
    r.recvuntil("P2: ")
    Q = r.recvline().decode()

    E = EllipticCurve(GF(p), [a,b])

    G = G.replace(" :", ",").replace(", 1", "").replace(")", "").replace("(", "").partition(",")
    print(G, type(G))
    print(G[0], G[-1])
    G = E(int(G[0]), int(G[-1]))

    Q = Q.replace(" :", ",").replace(", 1", "").replace(")", "").replace("(", "").partition(",")
    print(Q, type(Q))
    print(Q[0], Q[-1])
    Q = E(int(Q[0]), int(Q[-1]))

    return p, a, b, G, Q, E


#==================Part One==================

p, a, b, G, Q, E = getParameters()
#print(p, a, b, G, Q, E)

#Since E.order() == p, the curve is of trace one (an anomalous elliptic curve)

# Lifts a point to the p-adic numbers.
def _lift(curve, point, gf):
    x, y = map(ZZ, point.xy())
    for point_ in curve.lift_x(x, all=True):
        x_, y_ = map(gf, point_.xy())
        if y == y_:
            return point_


def attack(base, multiplication_result):
    """
    Solves the discrete logarithm problem using Smart's attack.
    More information: Smart N. P., "The discrete logarithm problem on elliptic curves of trace one"
    :param base: the base point
    :param multiplication_result: the point multiplication result
    :return: l such that l * base == multiplication_result
    """
    curve = base.curve()
    gf = curve.base_ring()
    p = gf.order()
    assert curve.trace_of_frobenius() == 1, f"Curve should have trace of Frobenius = 1."

    lift_curve = EllipticCurve(Qp(p), list(map(lambda a: int(a) + p * ZZ.random_element(1, p), curve.a_invariants())))
    lifted_base = p * _lift(lift_curve, base, gf)
    lifted_multiplication_result = p * _lift(lift_curve, multiplication_result, gf)
    lb_x, lb_y = lifted_base.xy()
    lmr_x, lmr_y = lifted_multiplication_result.xy()
    return int(gf((lmr_x / lmr_y) / (lb_x / lb_y)))


d = attack(G, Q)
print(f"Found secret {d}")
r.recvuntil(b"What is the value of 'secret'?: \r\n")
r.sendline(str(d))


#==================Part Two==================

p, a, b, G, Q, E = getParameters()
#print(p, a, b, G, Q, E)


def attack(base, multiplication_result):
    """
    Solves the discrete logarithm problem using the MOV attack.
    :param base: the base point
    :param multiplication_result: the point multiplication result
    :return: l such that l * base == multiplication_result
    """
    curve = base.curve()
    p = curve.base_ring().order()
    n = base.order()

    assert gcd(n, p) == 1, "GCD of curve base ring order and generator order should be 1."

    print("Calculating embedding degree...")

    # Embedding degree k.
    k = 1
    while (p ** k - 1) % n != 0:
        k += 1

    print(f"Found embedding degree {k}, computing discrete logarithm...")

    pairing_curve = curve.base_extend(GF(p ** k))
    pairing_base = pairing_curve(base)
    pairing_multiplication_result = pairing_curve(multiplication_result)

    ls = []
    ds = []
    while lcm(*ds) != n:
        rand = pairing_curve.random_point()
        o = rand.order()
        d = gcd(o, n)
        rand = (o // d) * rand
        assert rand.order() == d

        u = pairing_base.weil_pairing(rand, n)
        v = pairing_multiplication_result.weil_pairing(rand, n)
        print(f"Calculating ({v}).log({u}) modulo {d}")
        l = v.log(u)
        print(f"Found discrete log {l} modulo {d}")
        ls.append(int(l))
        ds.append(int(d))

    return ls[0] if len(ls) == 1 else int(crt(ls, ds))

d = attack(G, Q)
print(f"Found secret {d}")
r.recvuntil(b"What is the value of 'secret'?: \r\n")
r.sendline(str(d))


#==================Part Three==================

r.recvuntil('p = ')
p = int(r.recvline())
assert is_prime(p)

r.recvuntil("P1: ")
G = r.recvline().decode()
r.recvuntil("P2: ")
Q = r.recvline().decode()

G = G.replace(" :", ",").replace(", 1", "").replace(")", "").replace("(", "").partition(",")
G = (int(G[0]), int(G[-1]))

Q = Q.replace(" :", ",").replace(", 1", "").replace(")", "").replace("(", "").partition(",")
Q = (int(Q[0]), int(Q[-1]))

gx, gy = int(G[0]), int(G[1])
px, py = int(Q[0]), int(Q[1])

F = GF(p)
M = Matrix(F, [[gx,1],[px,1]])
a,b = M.solve_right(vector([gy^2-gx^3,py^2-px^3]))

assert 4*a^3 + 27*b^2 == 0

print(f"Found a : {a} and found b : {b}")

K.<x> = F[]
f = x^3 + a*x + b
roots = f.roots()
if roots[0][1] == 1:
    beta, alpha = roots[0][0], roots[1][0]
else:
    alpha, beta = roots[0][0], roots[1][0]

slope = (alpha - beta).sqrt()
u = (gy + slope*(gx-alpha))/(gy - slope*(gx-alpha))
v = (py + slope*(px-alpha))/(py - slope*(px-alpha))

d = discrete_log(v, u)

print(f"Found secret {d}")
r.recvuntil(b"What is the value of 'secret'?: \r\n")
r.sendline(str(d))

print(r.recvall())

"b'Success!\r\n\r\nCongrats on passing the ECC Pop Quiz! Here is your flag: flag{4Ll_0f_tH353_4tT4cK5_R3lY_0N_51mPl1FY1n9_th3_D15cr3t3_l09_pr08l3m}\r\n\r\n'"
