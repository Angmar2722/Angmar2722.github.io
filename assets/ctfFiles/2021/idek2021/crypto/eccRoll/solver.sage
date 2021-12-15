from tqdm import tqdm
from Crypto.Util.number import long_to_bytes

p_list = []
G_list = []
g_list = []
enc_list = []

with open('output.txt', 'r') as f:
    lines = f.readlines()
    for i, line in enumerate(lines):
        #p
        if i % 4 == 0:
            p_list.append(Integer(line.strip().split(" = ")[1]))
        #G
        if i % 4 == 1:
            F = EllipticCurve(GF(p_list[-1]), [9487, 0])
            comps = line.strip().split(" = ")[1].split(" : ")
            comps = [x.replace("(", "").replace(")", "") for x in comps]
            G_list.append(F(Integer(comps[0]), Integer(comps[1])))
        #g
        if i % 4 == 2:
            g_list.append(Integer(line.strip().split(" = ")[1]))
        #enc
        if i % 4 == 3:
            str_list = line.strip().split(" = ")[1][1:-1].split(", ")
            enc_list.append([Integer(x) for x in str_list])

def guessBit(p, x):
    return str(int(kronecker(x, p) == -1))

guesses = []

for guess in guesses:
    print(''.join(guess))

for p, G, g, enc in list(zip(p_list, G_list, g_list, enc_list)):
    E = EllipticCurve(GF(p), [9487, 0])
    guesses.append([])
    for bit in enc:
        guess = guessBit(p, bit)
        guesses[-1].append(guess)

to_remove = []
for i, guess in enumerate(guesses):
    if '1' not in guess:
        to_remove.append(i)

for i, ind in enumerate(to_remove):
    del guesses[ind - i]

compounded = []
for i in range(len(guesses[0])):
    for guess in guesses:
        if guess[i] == '1':
            compounded.append('1')
            break
    else:
        compounded.append('0')

print(long_to_bytes(int(''.join(compounded), 2)))

#b'idek{Wh3n_b=0_X_C00rd1n4t3s_of_p01nts_w1th_0dd_0rd3rs_4r3_qu4dr4t1c_r3s1du3s!!!}'