import ast 
from tqdm import tqdm 

with open("output.txt", "r") as f:
    temp = f.readlines()

def xor(a, b):
    return [x ^^ y for x, y in zip(a, b)]

def bytes_to_bits(inp):
    res = []
    for v in inp:
        res.extend(list(map(int, format(v, '08b'))))
    return res

def bits_to_bytes(inp):
    res = []
    for i in range(0, len(inp), 8):
        res.append(int(''.join(map(str, inp[i:i+8])), 2))
    return bytes(res)

enc = bytes_to_bits(bytes.fromhex("792137ecd08d478208e850a60680ccb7e937778222b1ceb8a1ac89046f421706930d240300cdf3ed07691c14a5ed60b226841238fee420feda73174021a557f552b5181dfb717aee329c44b90a"))
public = ast.literal_eval(temp[1])


#enc = bytes_to_bits(bytes.fromhex("f1558b8a3b"))
#public = [[0, 1071488838234], [65204354650, 1021669646129], [57666690108, 711988189457], [552902666172, 573828359780], [0, 213492007909], [961253271207, 727103715548], [385906222855, 943229752996], [16610212448, 48587962307], [499126049781, 0], [139307930864, 0], [29296352379, 377265293573], [683961828786, 814349401820], [536270470756, 0], [422540082809, 591630079875], [707791955581, 894791470441], [753162308727, 300617045692], [325979509102, 213740380088], [196990823610, 1011199229148], [1088167842249, 1074057466982], [85729246474, 751316447276], [1071251091857, 0], [961701127210, 732048561777], [927365395478, 614368622730], [716610958274, 0], [433179696788, 293615215737], [925315086770, 317181845965], [0, 928242444496], [722653918199, 717251183911], [0, 446349369016], [39814622639, 0], [908503739383, 0], [41753962425, 996494081092], [1067021348692, 597325539631], [749045473382, 344345566050], [820380477164, 19121820088], [293108235585, 35969873245], [337685520602, 0], [0, 169031717508], [294197399814, 205188886661], [305394740869, 769041635555]]

for i in range (len(public)):
    public[i][0] = Integer(public[i][0])
    public[i][1] = Integer(public[i][1])

BITLENGTH = len(public)
B = Integers(2)^BITLENGTH

def are_dependent(vecs):
    veclist = [B(v.bits() + [0]*(BITLENGTH - len(v.bits()))) for v in vecs]
    return B.are_linearly_dependent(veclist)

with_zeros = list(filter(lambda p: 0 in p, public))
the_rest = list(filter(lambda p: 0 not in p, public))
print(len(with_zeros), len(the_rest))
key = [p[0] if p[1] == 0 else p[1] for p in with_zeros]

for i in range(len(the_rest)):
    print(i)
    for p in tqdm(the_rest):
        print(".", end="")
        if are_dependent(key + [p[0]]):
            key += [p[1]]
            the_rest.remove(p)
            break
        elif are_dependent(key + [p[1]]):
            key += [p[0]]
            the_rest.remove(p)
            break
    print()

keystream = [1 if pair[1] in key else 0 for pair in public]
print(bits_to_bytes(xor(enc, keystream)))

#pbctf{I_hope_you_enjoyed_this_challenge_now_how_about_playing_Metroid_Dread?}