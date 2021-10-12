import ast 

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

with open("output.txt", "r") as f:
    temp = f.readlines()

enc = bytes_to_bits(bytes.fromhex("cd4c1a7edd7a421dcea72ae8bf47946d74f6cdba763a6a052a3f2955333dc6fa267f5297c405bf807e922380ebf9628194bf319e8ae4074dc5476de1d81a52d72c29f0e8b590ac8f6a78bb"))
public = ast.literal_eval(temp[1])

for i in range (len(public)):
    public[i][0] = Integer(public[i][0])
    public[i][1] = Integer(public[i][1])


def get_pair(n):
    ind = flatten(public).index(n) // 2
    pair = public[ind]
    if 0 in pair and n != 0: 
        pair = public[ind+1:][flatten(public[ind+1:]).index(n) // 2]
    return pair

pair = get_pair(0)
key = [pair[0] if pair[1] == 0 else pair[1]]

#print(len(public))
for _ in range(len(public) - 1):
    #print(_, pair)
    to_find = reduce(lambda a, b: a ^^ b, key[:len(public)//3])
    pair = get_pair(to_find)
    key = [pair[0] if pair[1] == to_find else pair[1]] + key

#print(key)
keystream = [1 if pair[1] in key else 0 for pair in public]
print(bits_to_bytes(xor(enc, keystream)))

#b'pbctf{super_duper_easy_brute_forcing_actually_this_one_waq_made_by_mistake}'

#Flag should be (the q in 'waq' should be 'was'):
#pbctf{super_duper_easy_brute_forcing_actually_this_one_was_made_by_mistake}