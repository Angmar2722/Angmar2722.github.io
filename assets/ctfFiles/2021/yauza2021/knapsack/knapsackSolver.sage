from math import ceil
from math import log2
from math import sqrt
from sage.all import matrix
from sage.all import QQ
from Crypto.Util.number import long_to_bytes

def attack(a, s):
    """
    Tries to find e_i values such that sum(e_i * a_i) = s.
    This attack only works if the density of the a_i values is < 0.9048.
    More information: Coster M. J. et al., "Improved low-density subset sum algorithms"
    :param a: the a_i values
    :param s: the s value
    :return: the e_i values, or None if the e_i values were not found
    """
    n = len(a)
    d = n / log2(max(a))
    N = ceil(sqrt(1 / 2 * n))
    assert d < 0.9408, f"Density should be less than 0.9408 but was {d}."

    M = matrix(QQ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = 1
        M[i, n] = N * a[i]

    M[n] = [1 / 2] * n + [N * s]

    L = M.LLL()

    for row in L.rows():
        s_ = 0
        e = []
        for i in range(n):
            ei = 1 - (row[i] + 1 / 2)
            if ei != 0 and ei != 1:
                break

            ei = int(ei)
            s_ += ei * a[i]
            e.append((str(ei)))

        if s_ == s:
            #print(e)
            return e


pubkey = [2948549611747, 2043155587142, 361533419625, 1001380428657, 2438250374319, 1059738568330, 115120002311, 198226659880, 2343897184958, 2592576935132, 2327834076450, 237536244289, 309228208827, 3327276767693, 462372704541, 2176574227058]
flag = [12777998288638, 10593582832873, 7834439533378, 10486500991495, 14714582460036, 7568907598905, 12800035735033, 14724457772647, 11910445040159, 11202963622894, 10291238568620, 15103559399914, 13156142631772, 16988824411176]

actualFlag = ""
for i in flag:
    actualFlag += ''.join(attack(pubkey, i))

print(long_to_bytes(int(actualFlag, 2)))
