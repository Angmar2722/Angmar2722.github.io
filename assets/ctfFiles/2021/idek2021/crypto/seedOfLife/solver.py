import random
from tqdm import tqdm
from Crypto.Util.number import *

for seed in tqdm(range(10000000)):

    random.seed(seed)
    toBreak = False

    for i in range(19):
        random.seed(random.random())

    seedtosave = random.random()

    for add in range(0, 1000):
        random.seed(seedtosave+add)
        for i in range(0, 100):
            temp = random.random()
            if add == 0 and i == 0 and temp != 0.5327486342598738:
                toBreak = True
                break

        if toBreak:
            break

    if toBreak:
        continue

    for add in range(0, 1000):
        random.seed(seedtosave-add)
        for i in range(0, 1000):
            random.random()

    random.seed(seedtosave)
    for i in range(0, 100):
        t = random.random()*100

    if t == 83.74981977975804:
        print("idek{", seed, "}", sep="")
        exit()

#idek{103123}