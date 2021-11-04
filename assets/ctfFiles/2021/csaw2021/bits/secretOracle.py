from math import ceil, sqrt, gcd, lcm
import random
import time
from gmpy2 import mpz

def bsgs(g, h, p, upper_bound=None):
    if upper_bound:
        m = ceil(sqrt(upper_bound))
    else:
        m = ceil(sqrt(p-1))

    if not hasattr(bsgs, 'baby_steps'):
        bsgs.baby_steps = dict()
        gi = mpz(1)
        for i in range(m):
            bsgs.baby_steps[gi] = i
            gi = (gi * g) % p

    c = pow(g, m * (p - 2), p)
    hi = h
    # giant steps
    for j in range(m):
        if hi in bsgs.baby_steps:
            return j * m + bsgs.baby_steps[hi]
        hi = (hi * c) % p
    # No solution
    return None

def crt(xs, ns_fac, n):
    x = 0
    ns = [p**e for p,e in ns_fac]
    common = gcd(*ns)
    ns = [n // common for n in ns]

    for xi, ni in zip(xs, ns):
        yi = n // ni
        zi = pow(yi, -1, ni)
        x += xi * yi * zi
    return x % n

def pohlig_hellman(g,h,p,n,n_factors):
    dlogs = []
    for pi, ei in n_factors:
        # Set up for each step
        ni = pi**ei
        gi = pow(g, n // ni, p)
        hi = pow(h, n // ni, p)

        # Groups of prime-power order
        xi = 0
        hk_exp = ni // pi
        gamma = pow(gi, hk_exp, p)

        for k in range(ei):
            # Create hk in <γ>
            gk = pow(gi, -xi, p)
            hk = pow(gk*hi, hk_exp, p)
            # make call to rust
            dk = bsgs(gamma, hk, p, upper_bound=pi)
            # increment the secret
            xi += dk*(pi**k)
            # Reduce the exponent
            hk_exp = hk_exp // pi
        
        del bsgs.baby_steps
        dlogs.append(xi)
    return crt(dlogs, n_factors, n)

def dlog_backdoor(g,h,N,p,q):
    np_factors = [(2, 1), (785685301, 16), (633462701, 1)]
    np = p-1

    nq_factors = [(2, 1), (794309437, 16), (942797321, 1)]
    nq = q-1

    xp = pohlig_hellman(g,h,p,np,np_factors)
    assert pow(g,xp,p) == pow(h,1,p)

    xq = pohlig_hellman(g,h,q,nq,nq_factors)
    assert pow(g,xq,q) == pow(h,1,q)

    x = crt([xp, xq], [(np, 1), (nq, 1)], np*nq)
    return x % order

p = mpz(26713395582018967511973684657814004241261156269415358729692119332394978760010789226380713422950849602617267772456438810738143011486768190080495256375003)
q = mpz(47346065295850807479811692397225726348630781686943994678601678975909956314423885777086052944991365707991632035242429229693774362516043822438274496319123)
np = p-1
nq = q-1

N = p*q
order = lcm(np,nq)

g = mpz(2)
x = mpz(random.randint(2,order))
h = pow(g,x,N)

print(f'x = {x}')

t = time.time()
x_guess = dlog_backdoor(g,h,N,p,q)

print(f'x_guess = {x_guess}')
print(f'Time taken: {time.time() - t}')
print(f'Solution found: {x == x_guess}')
print(f'Solution found: {pow(g,x_guess,N) == h}')
