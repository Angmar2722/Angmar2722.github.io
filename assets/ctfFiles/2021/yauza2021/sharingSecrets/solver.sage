shadows = [7832917, 8395798, 4599919, 154544, 3430534, 4694683, 123690, 5911445, 7380167, 10597668]
primes = [8412883, 8889941, 9251479, 9471269, 9503671, 9723401, 10092149, 10389901, 10551241, 10665527, 11099951]

def mul(x):
    m = 1
    for i in x:
        m *= i
    return m

lcm = mul(primes[1:])
flag = CRT_list(shadows, primes[1:])
for i in range(primes[0]):
    flag += lcm
    flag_bytes = int(flag).to_bytes(40, "big")

    if b"Yauza" in flag_bytes: 
        print(flag_bytes)
        exit()