---
layout: page
title: TJCTF 2023 Writeup
---
<hr/>

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img1.png)

I participated in Thomas Jefferson High School for Science and Technology's <a href="[https://ctftime.org/event/1656](https://ctftime.org/event/1865)" target="_blank">TJCTF 2023</a> event (Fri, 26 May 2023, 08:00 SGT — Sun, 28 May 2023, 08:00 SGT), playing solo. In the end, I ranked 19<sup>th</sup> out of 1047 scoring teams. All the attached files can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/tree/master/assets/ctfFiles/2023/tjctf2023" target="_blank">here</a>. Managed to sweep all crypto challenges.

Below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[Drm 1](#drm-1) | Crypto | 216 | 16 | 
|[Save Trees](#save-trees) | Rev | 207 | 17 | 
|[Aluminium Isopropoxide](#aluminium-isopropoxide) | Crypto | 168 | 22 | 
|[Keysmith](#keysmith) | Crypto | 128 | 30 | 
|[Merky Hell](#merky-hell) | Crypto | 72 | 54 | 
|[E](#e) | Crypto | 60 | 64 | 
|[Squishy](#squishy) | Crypto | 42 | 90 | 
|[Div3rev](#div3rev) | Rev | 36 | 102 | 
|[IHeartRSA](#iheartrsa) | Crypto | 35 | 106 | 
|[Scramble](#scramble) | Rev | 23 | 153 | 
|[Ezdlp](#ezdlp) | Crypto | 18 | 188 | 
|[Beep Boop Robot](#beep-boop-robot) | Forensics | 6 | 558 | 
|[Baby RSA](#baby-rsa) | Crypto | 6 | 576 | 
|[Hi](#hi) | Web | 4 | 840 | 
|[Survey](#survey) | Misc | 1 | 298 | 
|[Discord](#discord) | Misc | 1 | 704 | 

<br/>

<br/>

## Drm 1

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img2.png)

Source code :

```py

from flask import Flask
import time
from Crypto.Hash import SHA256

app = Flask(__name__)

hash_key = open("hash_key", "rb").read()[:32]
flag = open("flag.txt", "r").read().strip()


@app.route('/buy/<user>')
def buy(user):
    return "No"


@app.route('/song/<user>')
def song(user):
    return open("user/"+user+".drmsong", "rb").read().hex()


@app.route('/unlock/<meta>/<hmac>')
def unlock(meta, hmac):
    meta = bytes.fromhex(meta)

    user = None
    t = None
    for word in meta.split(b","):
        if b"user" in word:
            user = str(word[word.index(b":")+1:])[2:-1]
        if b"made" in word:
            t = float(str(word[word.index(b":")+1:])[2:-1])

    h = SHA256.new()
    h.update(hash_key)
    h.update(meta)
    if h.hexdigest() == hmac:
        if time.time() - t < 1000:
            drm_key = open("user/"+user+".drmkey", "rb").read().hex()
            drm_n = open("user/"+user+".drmnonce", "rb").read().hex()
            return drm_key + " " + drm_n + " " + flag
        else:
            return "Expired :(... pay us again"
    else:
        return "Bad Hash"


if __name__ == '__main__':
    app.run()

```

Solve script :

```py

import requests
import hlextend
import time

sha = hlextend.new('sha256')
appended = b',made:' + f'{int(time.time())}'.encode() + b',user:daniel-kpdfgo'
meta = sha.extend(appended, b'made:0,user:daniel-kpdfgo', 32, 'da1e3623a12b16e0a36c3d966c6d560f81e988ecf9040f99f1ac717ae444d417').hex()
hmac = sha.hexdigest()

url='https://drm.tjc.tf'
get_data_url = f"{url}/unlock/{meta}/{hmac}"
result = requests.get(get_data_url).text
print(f"{result=}")

#result='7031722c0feeb22a568fe3ea49f6a9e43978b9a0cfad3ce074c0a1562ced0b53 8bf202be03aca01e tjctf{wh0_n33ds_sp0t1fy_a7dfd3e5}'

```

<p> <b>Flag :</b> tjctf{wh0_n33ds_sp0t1fy_a7dfd3e5} </p>

<br/>

## Save Trees

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img3.png)

Source code :

```py

#!/usr/local/bin/python3.10 -u

import ast
import sys

import select
from Crypto.Util.number import bytes_to_long
import hashlib
import random


def set_globals():
    global edge_lst, cnt, threshold, vals, key, lvs
    edge_lst = []
    cnt, threshold = 0, 128
    vals = [0 for _ in range(threshold*16)]
    key = (bytes_to_long(bytes('save thr trees!!', 'utf-8'))
           << 16) + random.randint((1 << 15), (1 << 16))
    lvs = []


with open('flag.txt', 'r') as f:
    flag = f.readline()


def ear3mt3sdk(nd):
    global cnt, threshold, edge_lst, lvs, key
    if nd > threshold:
        lvs.append(nd)
        return
    if nd > threshold // 2:
        if random.randint(1, 4) == 1:
            lvs.append(nd)
            return
    edge_lst.append((nd, cnt+1))
    edge_lst.append((nd, cnt+2))
    old_cnt = cnt
    vals[cnt+1] = (vals[nd] >> 16) ^ key
    vals[cnt+2] = (vals[nd] & ((1 << 16) - 1)) ^ key
    cnt += 2
    ear3mt3sdk(old_cnt+1)
    ear3mt3sdk(old_cnt+2)


set_globals()
hsh = int('0x10000000' + str(hashlib.sha256(flag.encode('utf-8')).hexdigest()), 16)
vals[0] = hsh
ear3mt3sdk(0)

print('you have 5s to help treeelon musk save the trees!!')
print(edge_lst)
print([(nd, vals[nd]) for nd in lvs])


def input_with_timeout(prompt, timeout):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().rstrip('\n')
    raise Exception


try:
    answer = input_with_timeout('', 5)
except:
    print("\nyou let treeelon down :((")
    exit(0)

try:
    answer = ast.literal_eval(answer)
except:
    print("treeelon is very upset")
    exit(0)

if hsh == answer:
    print('good job treeelon is proud of you <3<3')
    print(flag)
else:
    print("treeelon is upset")

```

Solve script :

```py

from Crypto.Util.number import bytes_to_long
from tqdm import tqdm
from functools import reduce
import operator
import ast

#Reduce search space for key by half. If hsh isn't found, just run the solver again a few times
kl = []
constPart = bytes_to_long(bytes('save thr trees!!', 'utf-8')) << 16
for i in range(((1 << 15) + (1 << 16) + 1) // 2, (1 << 16) + 1):
    kl.append(constPart + i)

from pwn import *

debug = True
r = remote("tjc.tf", 31519, level = 'debug' if debug else None)

r.recvline()
el = ast.literal_eval(r.recvline().decode())
lvParentVals = ast.literal_eval(r.recvline().decode())

class Node:

    child1 = None
    child2 = None
    parent = None
    isLeaf = False
    parentVal = None
    val1 = None
    val2 = None

    def __init__(self, ID):
        self.ID = ID

    def addChild(self, child):
        if self.child1 is None:
            self.child1 = child
        else:
            self.child2 = child

    def addParent(self, parent):
        self.parent = parent

    def addVal(self, val, ID, key):
        if ID % 2: #Odd ID
            self.val1 = val
        else:
            self.val2 = val
            if len(str(self.val2)) not in [44, 4]: #val2 is always 4 or 44 long
                return "badKey"
        self.setParentVal(key)

    def setParentVal(self, key):
        if self.val1 is not None and self.val2 is not None and (self.parent is not None or self.ID == 0):
            self.parentVal = int((bin(self.val1 ^ key)[2:] + '{0:016b}'.format(self.val2 ^ key)), 2)

for key in tqdm(kl):

    nodeList = [Node(i) for i in range(max(reduce(operator.concat, el)) + 1)]

    for e in el:
        parent, child = e[0], e[1]
        nodeList[parent].addChild(nodeList[child])
        nodeList[child].addParent(nodeList[parent])

    for leaf in lvParentVals:
        leafID = leaf[0]
        leafVal = leaf[1]
        nodeList[leafID].isLeaf = True
        nodeList[leafID].parent.addVal(leafVal, leafID, key)

    wrongKey = False

    for node in nodeList[::-1][:-1]:
        if node.isLeaf: #Skip leafs as they have already added their vals to parent
            continue
        check = nodeList[node.ID].parent.addVal(node.parentVal, node.ID, key)
        if check == "badKey":
            break

    if wrongKey:
        continue

    hsh = nodeList[0].parentVal

    #Only the answer hsh is 86 long
    if len(str(hsh)) == 86:
        print(f"Found hsh, it is {hsh=}")
        break

r.sendline(str(hsh))
print(r.recvall())
#b'tjctf{tR33s_g1v3_0xYg3ndx0x<3}\n'

```

<p> <b>Flag :</b> tjctf{tR33s_g1v3_0xYg3ndx0x<3} </p>

<br/>

## Aluminium Isopropoxide

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img4.png)

Source code :

```cpp
  
#include <iostream>
#include <cinttypes>
#include <string>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <vector>
#include <cstring>
using namespace std;
using namespace std::filesystem;

typedef uint8_t Byte;

void make_key(Byte *S, const std::string &key)
{
	for (int i = 0; i < 255; i++)
		S[i] = i;

	Byte j = 0;
	for (int i = 0; i < 255; i++)
	{
		j = (j ^ S[i] ^ key[i % key.length()]) % 256;
		std::swap(S[i], S[j]);
	}
}

Byte S_box[256] = {24, 250, 101, 19, 98, 246, 141, 58, 129, 74, 227, 160, 55, 167, 62, 57, 237, 156, 32, 46, 90, 67, 22, 3, 149, 212, 36, 210, 27, 99, 168, 109, 125, 52, 173, 184, 214, 86, 112, 70, 5, 252, 6, 170, 30, 251, 103, 43, 244, 213, 211, 198, 16, 242, 65, 118, 68, 233, 148, 18, 61, 17, 48, 80, 187, 206, 72, 171, 234, 140, 116, 35, 107, 130, 113, 199, 51, 114, 232, 134, 215, 197, 31, 150, 247, 79, 26, 110, 142, 29, 9, 117, 248, 186, 105, 120, 15, 179, 207, 128, 10, 254, 83, 222, 178, 123, 100, 39, 228, 84, 93, 97, 60, 94, 180, 146, 185, 38, 203, 235, 249, 89, 226, 1, 106, 12, 216, 221, 8, 45, 13, 2, 14, 75, 49, 33, 127, 163, 111, 85, 255, 253, 166, 151, 40, 23, 194, 34, 139, 95, 145, 193, 159, 133, 69, 245, 196, 102, 91, 11, 157, 96, 47, 152, 154, 59, 181, 28, 126, 200, 158, 88, 224, 231, 41, 190, 240, 191, 188, 143, 164, 189, 217, 54, 66, 241, 209, 104, 78, 87, 82, 230, 182, 220, 53, 147, 21, 136, 76, 0, 115, 169, 71, 44, 223, 175, 92, 25, 177, 64, 201, 77, 138, 144, 204, 229, 81, 20, 183, 205, 124, 243, 4, 172, 174, 108, 132, 176, 135, 161, 162, 7, 236, 195, 238, 56, 42, 131, 218, 155, 121, 153, 239, 50, 219, 225, 37, 202, 63, 137, 192, 208, 119, 122, 165, 73};

void enc(Byte *S, Byte *out, int amount)
{
	Byte i = 0;
	Byte j = 0;
	int ctr = 0;
	while (ctr < amount)
	{
		i = (i * j) % 256;
		j = (i + S[j]) % 256;
		// std::swap(S[i],S[j]);
		Byte K = (S[i] & S[j]);
		out[ctr] ^= S_box[K];
		ctr++;
	}
}

Byte key[256];
int main()
{

	std::string path = current_path();

	std::vector<std::string> files;
	for (const auto &file : directory_iterator(path))
		files.push_back(std::string(file.path()));

	for (const auto &file : files)
	{
		std::cout << file << "\n";
		struct stat results;
		std::ifstream in(file);
		std::ofstream out(file + ".enc", std::ofstream::binary);
		if (stat(file.c_str(), &results) == 0)
		{
			uint8_t *buffer = new uint8_t[results.st_size];
			in.read((char *)buffer, results.st_size);

			make_key(key, std::to_string(rand()));
			enc(key, buffer, results.st_size);

			out.write((char *)buffer, results.st_size);
			delete[] buffer;
		}
		in.close();
		out.close();
	}

	return 0;
}

```

Solve scripts : 
  
```cpp

#include <iostream>
#include <cinttypes>
#include <string>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>

typedef uint8_t Byte;

Byte S_box[256] = {24, 250, 101, 19, 98, 246, 141, 58, 129, 74, 227, 160, 55, 167, 62, 57, 237, 156, 32, 46, 90, 67, 22, 3, 149, 212, 36, 210, 27, 99, 168, 109, 125, 52, 173, 184, 214, 86, 112, 70, 5, 252, 6, 170, 30, 251, 103, 43, 244, 213, 211, 198, 16, 242, 65, 118, 68, 233, 148, 18, 61, 17, 48, 80, 187, 206, 72, 171, 234, 140, 116, 35, 107, 130, 113, 199, 51, 114, 232, 134, 215, 197, 31, 150, 247, 79, 26, 110, 142, 29, 9, 117, 248, 186, 105, 120, 15, 179, 207, 128, 10, 254, 83, 222, 178, 123, 100, 39, 228, 84, 93, 97, 60, 94, 180, 146, 185, 38, 203, 235, 249, 89, 226, 1, 106, 12, 216, 221, 8, 45, 13, 2, 14, 75, 49, 33, 127, 163, 111, 85, 255, 253, 166, 151, 40, 23, 194, 34, 139, 95, 145, 193, 159, 133, 69, 245, 196, 102, 91, 11, 157, 96, 47, 152, 154, 59, 181, 28, 126, 200, 158, 88, 224, 231, 41, 190, 240, 191, 188, 143, 164, 189, 217, 54, 66, 241, 209, 104, 78, 87, 82, 230, 182, 220, 53, 147, 21, 136, 76, 0, 115, 169, 71, 44, 223, 175, 92, 25, 177, 64, 201, 77, 138, 144, 204, 229, 81, 20, 183, 205, 124, 243, 4, 172, 174, 108, 132, 176, 135, 161, 162, 7, 236, 195, 238, 56, 42, 131, 218, 155, 121, 153, 239, 50, 219, 225, 37, 202, 63, 137, 192, 208, 119, 122, 165, 73};

void make_key(Byte *S, const std::string &key)
{
    for (int i = 0; i < 255; i++)
        S[i] = i;

    Byte j = 0;
    for (int i = 0; i < 255; i++)
    {
        j = (j ^ S[i] ^ key[i % key.length()]) % 256;
        std::swap(S[i], S[j]);
    }
}

void enc(Byte *S, Byte *out, int amount)
{
	Byte i = 0;
	Byte j = 0;
	int ctr = 0;
	while (ctr < amount)
	{
		i = (i * j) % 256;
		j = (i + S[j]) % 256;
		// std::swap(S[i],S[j]);
		Byte K = (S[i] & S[j]);
		out[ctr] ^= S_box[K];
		ctr++;
	}
}

bool checkCiphertextMatch(const std::vector<int>& encryptedList, const Byte* ciphertext, int size)
{
    if (encryptedList.size() != size)
        return false;

    for (int i = 0; i < size; ++i) {
        if (ciphertext[i] != static_cast<Byte>(encryptedList[i])) {
            return false;
        }
    }

    return true;
}

int main()
{

    std::vector<int> firstFive1;
    firstFive1.push_back(108);
    firstFive1.push_back(144);
    firstFive1.push_back(67);
    firstFive1.push_back(153);
    firstFive1.push_back(101);
    firstFive1.push_back(25);

    std::vector<int> firstFive2;
    firstFive2.push_back(142);
    firstFive2.push_back(156);
    firstFive2.push_back(1);
    firstFive2.push_back(22);
    firstFive2.push_back(144);
    firstFive2.push_back(141);

    std::vector<int> firstFive3;
    firstFive3.push_back(48);
    firstFive3.push_back(46);
    firstFive3.push_back(30);
    firstFive3.push_back(9);
    firstFive3.push_back(243);
    firstFive3.push_back(150);

    const int RAND_MAX_VALUE = 2147483647;

    for (int i = 1; i <= RAND_MAX_VALUE; ++i) {

        Byte S[256];
        std::string key = std::to_string(i);

        make_key(S, key);

        std::string plaintext = "tjctf{";
        int size = plaintext.length();
        Byte* ciphertext = new Byte[size];

        // Copy plaintext to ciphertext array
        std::memcpy(ciphertext, plaintext.c_str(), size);

        // Encrypt the ciphertext
        enc(S, ciphertext, size);

        bool isMatch1 = checkCiphertextMatch(firstFive1, ciphertext, size);
        bool isMatch2 = checkCiphertextMatch(firstFive2, ciphertext, size);
        bool isMatch3 = checkCiphertextMatch(firstFive3, ciphertext, size);

        if (isMatch1 || isMatch2 || isMatch3) {
            std::cout << "\nInputted key: " << key << "\n";
        }

    }

    return 0;

}

```

And (written in Sage) : 
						      
```py
						      
def make_key(key):

    S = [i for i in range(255)] + [0]

    j = 0
    for i in range(255):
        j = (j ^^ S[i] ^^ ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    return bytearray(S)

S_box = [24, 250, 101, 19, 98, 246, 141, 58, 129, 74, 227, 160, 55, 167, 62, 57, 237, 156, 32, 46, 90, 67, 22, 3, 149, 212, 36, 210, 27, 99, 168, 109, 125, 52, 173, 184, 214, 86, 112, 70, 5, 252, 6, 170, 30, 251, 103, 43, 244, 213, 211, 198, 16, 242, 65, 118, 68, 233, 148, 18, 61, 17, 48, 80, 187, 206, 72, 171, 234, 140, 116, 35, 107, 130, 113, 199, 51, 114, 232, 134, 215, 197, 31, 150, 247, 79, 26, 110, 142, 29, 9, 117, 248, 186, 105, 120, 15, 179, 207, 128, 10, 254, 83, 222, 178, 123, 100, 39, 228, 84, 93, 97, 60, 94, 180, 146, 185, 38, 203, 235, 249, 89, 226, 1, 106, 12, 216, 221, 8, 45, 13, 2, 14, 75, 49, 33, 127, 163, 111, 85, 255, 253, 166, 151, 40, 23, 194, 34, 139, 95, 145, 193, 159, 133, 69, 245, 196, 102, 91, 11, 157, 96, 47, 152, 154, 59, 181, 28, 126, 200, 158, 88, 224, 231, 41, 190, 240, 191, 188, 143, 164, 189, 217, 54, 66, 241, 209, 104, 78, 87, 82, 230, 182, 220, 53, 147, 21, 136, 76, 0, 115, 169, 71, 44, 223, 175, 92, 25, 177, 64, 201, 77, 138, 144, 204, 229, 81, 20, 183, 205, 124, 243, 4, 172, 174, 108, 132, 176, 135, 161, 162, 7, 236, 195, 238, 56, 42, 131, 218, 155, 121, 153, 239, 50, 219, 225, 37, 202, 63, 137, 192, 208, 119, 122, 165, 73]

def enc(S, out, amount):
    i = 0
    j = 0
    ctr = 0
    while ctr < amount:
        i = (i * j) % 256
        j = (i + S[j]) % 256
        K = (S[i] & S[j])
        out[ctr] ^^= S_box[K]
        ctr += 1
    return out

def dec(S, enc, amount):
    i = 0
    j = 0
    ctr = 0
    while ctr < amount:
        i = (i * j) % 256
        j = (i + S[j]) % 256
        K = (S[i] & S[j])
        enc[ctr] ^^= S_box[K]
        ctr += 1
    return enc

e1 = bytearray(b'l\x90C\x99e\x19\x03Br\x02\xd2\x98@\xf8\xe8deWOvv\x16[G}GA\\\xd2rv`\x16\x18')
e2 = bytearray(b'\x8e\x9c\x01\x16\x90\x8d\x90\x0e\x03\x91G\x17\x98\x92\x93\x88\xa5\x9b\r\x83\x98\x16\x97\x93\x0cGw\x04\xa9|\x17\x89l\x87')
e3 = bytearray(b'0.\x1e\t\xf3\x96\x8b\xf9\xe0\x7f\xdepk\x89\xf0\xf3G\xecwpk\x99\x8cl\xfb\xb2j\xf3\xca\x19\xe0\x9eqe')

from pwn import *

debug = False

r = process(["./bruteForce"], level='debug') if debug else process(["./bruteForce"])

kl = []
dctl = []

greaterThanTwoBillion = False
increment = 1

while not greaterThanTwoBillion:

    r.recvuntil('Inputted key: ')
    key = Integer(r.recvline())

    if key > 10000000*increment:
        print(f"On {float(key/1000000)} million")
        increment += 1

    if key > 2000000000:
        greaterThanTwoBillion = True

    tenc = enc(make_key(str(key)), bytearray(b'tjctf{'), 6)
    if tenc == e1[:len(b'tjctf{')]:
        decr = dec(make_key(str(key)), e1, len(e1))
        if decr.isascii():
            print(f"Found key for e1, it is {key}")
            kl.append(key)
            dctl.append(decr)
            print(decr)
    elif tenc == e2[:len(b'tjctf{')]:
        decr = dec(make_key(str(key)), e2, len(e2))
        if decr.isascii():
            print(f"Found key for e2, it is {key}")
            kl.append(key)
            dctl.append(decr)
            print(decr)
    elif tenc == e3[:len(b'tjctf{')]:
        decr = dec(make_key(str(key)), e3, len(e3))
        if decr.isascii():
            print(f"Found key for e3, it is {key}")
            kl.append(key)
            dctl.append(decr)
            print(decr)


print(f"{kl=}")
print(f"{dctl=}")

#Found key for e1, it is 719885386
#bytearray(b'tjctf{flag_under_mountain_of_dust}')
	
```

<p> <b>Flag :</b> tjctf{flag_under_mountain_of_dust} </p>

<br/>

## Keysmith

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img5.png)

Source code :                                                    
                                                      
```py
	
#!/usr/local/bin/python3.10 -u
from Crypto.Util.number import getPrime
flag = open("flag.txt", "r").read()

po = getPrime(512)
qo = getPrime(512)
no = po * qo
eo = 65537

msg = 762408622718930247757588326597223097891551978575999925580833
s = pow(msg,eo,no)

print(msg,"\n",s)

try:
    p = int(input("P:"))
    q = int(input("Q:"))
    e = int(input("E:"))
except:
    print("Sorry! That's incorrect!")
    exit(0)

n = p * q
d = pow(e, -1, (p-1)*(q-1))
enc = pow(msg, e, n)
dec = pow(s, d, n)
if enc == s and dec == msg:
    print(flag)
else:
    print("Not my keys :(")

```
	
Solve script :
	
```py
	
from Crypto.Util.number import *
from pwn import *
from tqdm import tqdm
import time

p,q = 2^188 * 5^360+1, 2 * 11^45 * 17^212+1
N = p*q

def get_e(s, c):
    sp = GF(p)(s)
    sq = GF(q)(s)
    dp = sp.log(c)
    dq = sq.log(c)
    d = crt([dp, dq], [p-1, q-1])
    return pow(int(d), -1, lcm(p-1, q-1)).lift(), d


for i in tqdm(range(100)):

    try:

        time.sleep(1)
        debug = False
        r = remote("tjc.tf", 31103, level = 'debug' if debug else None)

        r.recvline()
        s = Integer(r.recvline())
        msg = 762408622718930247757588326597223097891551978575999925580833

        e, d = get_e(msg, s)
        print("Found one pair!")
        print(f"{e=}, {d=}")
        assert pow(s, d, N) == msg

        r.sendlineafter('P:', str(p))
        r.sendlineafter('Q:', str(q))
        r.sendlineafter('E:', str(e))
        print(r.recvall())

        exit()

    except ValueError:
        continue
    except AssertionError:
        continue
    except ZeroDivisionError:
        continue

#b'tjctf{lock-smith_289378972359}\n'
	
```

<p> <b>Flag :</b> tjctf{lock-smith_289378972359} </p>

<br/>

## Merky Hell

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img6.png)

Source code :  

```py
	
from math import gcd
import secrets
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

n = 48

with open('flag.txt', 'rb') as f:
    flag = f.read()


def randint(a, b):
    return int(secrets.randbelow(int(b-a + 1)) + a)


def makeKey():
    W = []
    s = 0
    for i in range(n):
        curr = 0
        if i != 0:
            curr = randint((2**i - 1) * 2**n + 1, 2**(i+n))
        else:
            curr = randint(1, 2**n)
        assert s < curr
        s += curr
        W.append(curr)

    q = randint((1 << (2 * n + 1)) + 1, (1 << (2 * n + 2)) - 1)

    r = randint(2, q - 2)
    r //= gcd(r, q)

    B = []
    for w in W:
        B.append((r * w) % q)

    return B, (W, q, r)


def encrypt(public, m):
    return sum([public[i] * ((m >> (n - i - 1)) & 1) for i in range(n)])


pub, _ = makeKey()

sup_sec_num = secrets.randbits(n)

msg = encrypt(pub, sup_sec_num)

iv = secrets.token_bytes(16)

key = pad(long_to_bytes(sup_sec_num), 16)
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
ct = cipher.encrypt(pad(flag, 16))

print('B =', pub)
print('msg =', msg)
print('iv =', iv.hex())
print('ct =', ct.hex())

```
	
Solve script : 
	
```py
	
from math import ceil
from math import log2
from math import sqrt
from sage.all import QQ
from sage.all import matrix

def shortest_vectors(B):

    B = B.LLL()

    for row in B.rows():
        if not row.is_zero():
            yield row

def attack(a, s):

    n = len(a)
    d = n / log2(max(a))
    N = ceil(1 / 2 * sqrt(n))
    assert d < 0.9408, f"Density should be less than 0.9408 but was {d}."

    L = matrix(QQ, n + 1, n + 1)
    for i in range(n):
        L[i, i] = 1
        L[i, n] = N * a[i]

    L[n] = [1 / 2] * n + [N * s]

    for v in shortest_vectors(L):
        s_ = 0
        e = []
        for i in range(n):
            ei = 1 - (v[i] + 1 / 2)
            if ei != 0 and ei != 1:
                break

            ei = int(ei)
            s_ += ei * a[i]
            e.append(ei)

        if s_ == s:
            return e

B = [243873082678558120886143238109, 140121004360885317204645106697, 65971149179852778782856023084, 198367501585318217337192915461, 90780110766692265488675597096, 204457189038632581915443073067, 11843936715392553537334014601, 249714131767678082951811660354, 46864685536820768096162079781, 270615453249669076126135660113, 62422813932318315478542903448, 54340894478463039745320012710, 82166063070770734716784239617, 123360554027599432641005228613, 225930829813243714315757104718, 140931881774215407739681383827, 153511648985484571193029079380, 128333502017904902954574343976, 157971994970491620681977801348, 151995940102680832680366775791, 111930343189002833676566713355, 254629522353980890137482003596, 46122603870700121747541022366, 106621126674742413122499956117, 213619593425584289387962971025, 250029395347234943835276840576, 90157964719511330175905946756, 160955342950540531541477834386, 62686435507426271661129199824, 48684199759430660574537497320, 262348080860779266021957164776, 123406793114541556721282454859, 8323348282744522342656453505, 8204832183897468999773786370, 117068364683450498818799008726, 22742733514396961388718208907, 152588763365550382579175625426, 18880903696373297518512895359, 168999842801038138048571134864, 251946102324340921852977277387, 62739530425883979430660351271, 26189963743964979633698113800, 149052997409450695582768647188, 161035032125544665156226726161, 170005203789455944372862796495, 127446446141939678833034246067, 66890847724290458515749208331, 230355717600508139033028789245]
msg = 4096661050207034370558640511465

sup_sec_num = int(''.join(list(map(str, attack(B, msg)))), 2)
print(f"{sup_sec_num=}")

from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

iv = bytes.fromhex("c3599b694d81ca069cefdbd7c8f06812")
ct = bytes.fromhex("8e291e6ea5eb6f186949c8d25c5e6dc30c1869a7abf1078d26792dc846f2ffb9b5793fe92036fe55c9f8a6c61f4f516e")

key = pad(long_to_bytes(sup_sec_num), 16)
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), AES.block_size)
print(flag)

#b'tjctf{knaps4ck-rem0v4L0-CreEEws1278bh}'
	    
```
		      
<p> <b>Flag :</b> tjctf{knaps4ck-rem0v4L0-CreEEws1278bh} </p>

<br/>

## E

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img7.png)

Source code :  

```py
	
from Crypto.Util.number import bytes_to_long

p = random_prime(2 ^ 650)
q = random_prime(2 ^ 650)
N = p*q
e = 5
flag = open("flag.txt", "rb").read().strip()
m = bytes_to_long(b'the challenges flag is ' + flag)
c = m ^ e % N
print("N: ", N)
print("C: ", c)
print("e: ", e)

```
	
Solve script :
	
```py
	
from Crypto.Util.number import *
from tqdm import tqdm

N=  853008036761402960429244085500226305898326229049062709229066738337581395441559298620215547481097485360068401045559533084692445386310317304293873811639421668853703030998563380404046228010704173349786419154143323587451196441095743638783569173579503503557413613700490069592150975220823978641111437607374483116682547794651693986279540940965888470663234601045413512056249535670198419685119952947
C=  298700332507654723773580072855784292117810966958600234446114828082727445272393622869719877676272804981941548843479760604983256960593285221389548684954375981617049731866256547635842115184695147132731165168615990125469633018271766466825307769730709868985624843944432541800012321786587028293887532995722347604510229248766961319729482167555605707032678858635163105035385522888663577785577519392
e=  5

for unknownFlagLen in tqdm(range(1, 200)):

    P.<b> = PolynomialRing(Zmod(N), implementation='NTL')

    ts = b'the challenges flag is tjctf{'[::-1]
    ans = 0
    for i in range(unknownFlagLen, len(ts)+unknownFlagLen):
        ans += (ts[i-unknownFlagLen]*(256^i))

    a = ans + ord('}')

    #(a+b)^5
    #a is known flag bytes
    #b is unknown x
    pol = (a^5) + (5*a^4*b) + (10*a^3*b^2) + (10*a^2*b^3) + (5*a*b^4) + (b^5) - C
    sols = pol.small_roots(epsilon=1/30)

    for sol in sols:
        print(long_to_bytes(a + sol))
        exit()

#b'the challenges flag is tjctf{coppersword2}'

```
	
<p> <b>Flag :</b> tjctf{coppersword2} </p>

<br/>

## Squishy

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img8.png)

Source code :  

```py

#!/usr/local/bin/python3.10 -u

import sys
import select
from Crypto.Util.number import bytes_to_long, getPrime


def input_with_timeout(prompt, timeout=10):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.buffer.readline().rstrip(b'\n')
    raise Exception


def sign(a):
    return pow(bytes_to_long(a), d, n)


def check(a, s):
    return bytes_to_long(a) == pow(s, e, n)


e = 65537
users = {b"admin"}

p = getPrime(1000)
q = getPrime(1000)
n = p * q
d = pow(e, -1, (p - 1) * (q - 1))


print(n)

while True:
    cmd = input("Cmd: ")
    if cmd == "new":
        name = input_with_timeout("Name: ")
        if name not in users:
            users.add(name)
            print(name, sign(name))
        else:
            print("Name taken...")
    elif cmd == "login":
        name = input_with_timeout("Name: ")
        sig = int(input_with_timeout("Sign: ").decode())
        if check(name, sig) and name in users:
            if name == b"admin":
                print("Hey how'd that happen...")
                print(open("flag.txt", "r").read())
            else:
                print("No admin, no flag")
        else:
            print("Invalid login.")

    else:
        print("Command not recognized...")

```
	
Solve script : 
	
```py
	
from pwn import *
from Crypto.Util.number import *

debug = False
r = remote("tjc.tf", 31358, level = 'debug' if debug else None)

n = int(r.recvline())
e = 65537

r.sendlineafter("Cmd: ", "new")

name = long_to_bytes((pow(2, e, n) * bytes_to_long(b'admin')) % n)
r.sendlineafter("Name: ", name)

sig = int(r.recvline().split()[-1].decode())
realSig = (inverse(2, n) * sig) % n

r.sendlineafter("Cmd: ", "login")
r.sendlineafter("Name: ", "admin")
r.sendlineafter("Sign: ", str(realSig))
print(r.recvall())

#b"Hey how'd that happen...\ntjctf{sQuIsHy-SqUiShY-beansbeansbeans!!!!!!}\n\nCmd: "
	
```

<p> <b>Flag :</b> tjctf{sQuIsHy-SqUiShY-beansbeansbeans!!!!!!} </p>

<br/>

## Div3rev

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img9.png)

Source code :  

```py

def op1(b):
    for i in range(len(b)):
        b[i] += 8*(((b[i] % 10)*b[i]+75) & 1)
        cur = 1
        for j in range(420):
            cur *= (b[i]+j) % 420
    return b


def op2(b):
    for i in range(len(b)):
        for j in range(100):
            b[i] = b[i] ^ 69
        b[i] += 12
    return b


def op3(b):
    for i in range(len(b)):
        b[i] = ((b[i] % 2) << 7)+(b[i]//2)
    return b


def recur(b):
    if len(b) == 1:
        return b
    assert len(b) % 3 == 0
    a = len(b)
    return op1(recur(b[0:a//3]))+op2(recur(b[a//3:2*a//3]))+op3(recur(b[2*a//3:]))


flag = open("flag.txt", "r").read()
flag = flag[:-1]
b = bytearray()
b.extend(map(ord, flag))
res = recur(b)
if res == b'\x8c\x86\xb1\x90\x86\xc9=\xbe\x9b\x80\x87\xca\x86\x8dKJ\xc4e?\xbc\xdbC\xbe!Y \xaf':
    print("correct")
else:
    print("oopsies")

```
	
Solve script :
	
```py
	
res = bytearray(b'\x8c\x86\xb1\x90\x86\xc9=\xbe\x9b\x80\x87\xca\x86\x8dKJ\xc4e?\xbc\xdbC\xbe!Y \xaf')

def reversedOp1(b):
    for i in range(len(b)):
        if (b[i] % 2) == 0:
            b[i] -= 8
    return b

def reversedOp2(b):
    for i in range(len(b)):
        for j in range(100):
            b[i] = b[i] ^ 69
        b[i] -= 12
    return b

def reversedOp3(b):
    for i in range(len(b)):
        try:
            if (b[i] % 2):
                b[i] = (b[i] - 128)*2 + 1
            else:
                b[i] *= 2
        except ValueError:
            try:
                b[i] *= 2
            except ValueError:
                b[i] = (b[i] - 128)*2 + 1
                continue
            continue
    return b

def recur(b):
    if len(b) == 1:
        return b
    assert len(b) % 3 == 0
    a = len(b)
    return recur(reversedOp1(b[0:a//3]))+recur(reversedOp2(b[a//3:2*a//3]))+recur(reversedOp3(b[2*a//3:]))

flag = recur(res)
print(f"{flag=}")
#flag=bytearray(b'tjctf{randomfifteenmorelet}')
	
```
	
<p> <b>Flag :</b> tjctf{randomfifteenmorelet} </p>

<br/>

## IHeartRSA

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img10.png)

Source code :  

```py
	
#!/usr/local/bin/python3.10 -u

import ast
import sys

import select
from Crypto.Util import number
import hashlib

with open('flag.txt') as f:
    flag = f.readline()

raw_bin = str(
    bin(int('0x'+str(hashlib.sha256(flag.encode('utf-8')).hexdigest()), 16))[2:])
hsh = int('0b1' + '0' * (256 - len(raw_bin)) + raw_bin, 2)

p = number.getPrime(1024)
q = number.getPrime(1024)
n = p * q
e = 0

for i in range(0, 100):
    if pow(hsh, i) >= n:
        e = i
        break

m = pow(hsh, e, n)
print(f'm: {m}')
print(f'n: {n}')


def input_with_timeout(prompt, timeout):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().rstrip('\n')
    raise Exception


try:
    answer = input_with_timeout('', 20)
    try:
        answer = ast.literal_eval(answer)
        if hsh == answer:
            print('you love rsa so i <3 you :DD')
            print(flag)
        else:
            print("im upset")
    except Exception as e:
        print("im very upset")
except Exception as e:
    print("\nyou've let me down :(")
		    
```

Solve script :
		    
```py
		    
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from pwn import *

nList = []
ctList = []

#Connect to server and get 8 sets of modulli and ciphertexts
ctList.append(1586899938004778095774657270980533506037178182276860169301980254501265807766863811854199283554151039751551885974455602933582247036623286462464218041418441294371063302694701562161154906485951868419668989451374719064907054189064404300456877436627968465264750572850962732393983031208449218644038938022202232478087542638078601936573725093088148561577712439831524516897053568014982168991163331698186402771980127092809064901066790722175313255439886050322531022869065538932265457205146256442003078676265844448693800783809489221555907323093367943428429391351724977741479942195025488178047690127370367402505594959648239650591)
nList.append(21542898904782840730381940692965878450052155136073135514809709240546615466466704430258515672612029448987641529954265353594856290219065113903670006601821929346525123278013614321434419100023827713734026186884012683211780075781538657720826179127217197543751227803809342079844331622471462606994432871813186782545509117109164204671143837885179626866058758828199626412273366203743299242250370455584931634524615206918696366174202291973498920970929257754461141248597946813048382959238260612740775979544348205623583239620620942270891878060722287530222416244585809422261733568988877391075530692076413216518791261104679694593293)

ctList.append(1502802665396921310019935893453399264477451543946786782744726283737770516917632714077112714594332407786977241781615153435693677058365394524367437288754176876759254406214934071474539833031478172641165423239761531922934524292981977757769383923706154938424876599397957228771777501569954685940403657971137203096818842036878907688875019810620048963345140578725047123627863084571495915183961604864540537036925652569370627115589221933688339953493457713773386696375918676267860436307935346434821859348990457122097941853945567844138321134220582104654480154130387079580160774131672772202231245811043898258557320316534914954629)
nList.append(17959423860036355340797844025598826561840106499921785711221195531352470829626356283363520274590009426820082495311291165453870956014075752581233070564240296490238586806384659225419233839474395902759897119587645001604981107309289083645912440398757815747029346000962202191838793479529426716887330333181911071236363322641070145079928090344522030688235013345258561793000237710073039889692575523556913517581767211975866841627291707376956348584269917156763379734372717916095686217773318086451245084564229786963535687928006112007194697233007971761749842640256619343398221238162677218894260280423371552860988407140825855885741)

ctList.append(11509556917555886627410754790328211017899514698901284988554592978934592660319168421247197870765069631225178660728414681941443240871020875629376647316301826553377513455033723131056009840929304269439450201685636457653121909484277701799166565060180225828257681496438583616049193342373879927935864002171299995793678011883365083335140466014542563335858842079632158616936222506219287409727657565029416915877907433538032148816452002954025860056923786369471169000044284877021000712597763489012529623389582989080230637823901201899836221662322162964954294068158662109206035807856418393212751562719587058487646298346963739581768)
nList.append(15808179389867484520937177646947008229896862680315917717603421513925602139393441514860935241454567376800214501906822650533900146796634888451522125903333531400480367894445932434265333543522686518178498512046605007194583530963090252285350161819124593698039949778038907685752931224119168873896346434921751543241500053988181197331759356763872450298946650664784279232514961007632975937059016178655237371703094212518595429063587515961779897146754513632727905731446480676338084179768460684218248711594628070123407350705085977694664497405230313867746022905311627468550213832632875461978507926782455036469443992896883188153981)

ctList.append(16250662971662343408860271616172402030761988416529151103998414988788334421222430383895895665414664844406687731176596733013536480520633592497618103944026978234915446561441829654885257399639820076091996731919297430484294206863216484436201112533991929452335981973275001400996969137255566307422915738468533284154858010674433982956252121026836518759039529732107020699403396851450639913494011643429020509363662524113060929301967948438361484482996390096335653809464346957268171130622059096735791312345033160241033230608165073174412452702022761029208088866798085990922764482546068715425706742269000347123636677081057810192791)
nList.append(20076522601417084199073379258446691597579674112647906421340065767117908605121147773054346034425978068522127945434051240586860866870664083300154618011561075652470684952138901512162008850708440892966793412637220412069841360514123449707251755617480801445044104663766938212984033011866750898116545191768553677377832070305528666569175998291804789846312577098972076794022731875399733467800085624411848223865446967216671179734112176201880303848173607349859828969938418671214792391896569328711397156177471474044349296638185383875606223522829348221644450297041173320943605114953773068350764786862250218546678152892538737539073)

ctList.append(5761426936328602977234209719650227388867989681292548811604270073053000026844914624750683713124145146145943689955398969263724248458496013079612685433396814329207833984242139170123937048870124230021672645882857552568909850109470022745827311498863503051051261303808133863340420704202568023902745426922825340682827291295929628215600612832596226303405687627132644898263644398064217571735542628667522642686780354055310606398218886289623352596630851875461876266380730604370206240760533240264223189601101594613117786895015909557340670147672075846938822754312367646185527908620762103874418263263243863924922888596285188081413)
nList.append(17604538504125381868529987873415757551474228321809638875482900215576201703799082790807389358045858365290168624630142514134868408397398201034962633218853410035867871841549058800531784071487842064644854851034053666551149830157915079896907613100828036737643813942261354138958073212643375605390468519102603726437529285202815918369367624259357349243229967757891261978447255933948646418313277104906665008777612653518705176687072568680628430864008467643289338936872316922087157400735601595298794973709887192172617367507916916864427834815220347283226147423574787629514440643621919774588244695635688222388791276450846666458509)

ctList.append(2767568297968471785979621542057142075531337535936757452703845515884651337393716532851949441967284906587558611053750069333141839151067373878515002490384039779074877093563900594073056995008448651386726378447850290808647066583548092898930617730854876778155994754426158098106450479572335339192382412032034930034461459873830792978447107597519000917672431675628781532967134556795107216051809821647119632644059805031602606244809880247058751245489445999693319247439791134382108543929186178630490984564680517038157043444702264775052010808254844595206229253407076196990912997164935076203529836719936691530363483137510549699388)
nList.append(9315144377733248417983236637329659823088147478568324254986749006264468223262617025286408981204659157523496024976667785632565361307661176157419533981271899781762931260402910616627490822248512189320574107819289185233654815018300125591729915259910655092374827558979053279683949946797858258669390662787914570778205097993734341550850652015102844187151863871573869874202764393419689885888828611560886222407568364836876961756446949139569816161706218156314809750496032284131912456767763748053011821285002929723755180588926810745887942483567886897845494025382727956668169679779081057509992381485720253959132814037779766777571)

ctList.append(12978146555676642993877951140190829642887633482777067268415421159361816508427086465991517483263304880567772843233077316205582972178525541533339778921082252441145667358627232498956657318490291858573270429857563540081872925720957085192504951039098337418163821077245095327496668933931173014458206233781891413739653319418159789195751214701556874098691729896486777955911061892811779193302023719795052687342729529565556238267244703853696915020158238343490031877240050761298622295354314686181799653279391521987224278730586093746475725212934097399625722811845872947726078821670649880744670542492063667007125074111769859229412)
nList.append(15695210956165887877362777927726806797205468927710088311460280884661969535692832434495987578954703126850784180175694755590504782849903760305063423472196575562959740671092585559811437583710302857475896956033379847007756529714114915101247209051515508191124092887207637554103125409383992482625397032490167588014886568793196989188635453018717503317190274678872385437209204131741245799860988012904034620051954051285708960644295769738728277534198017327034147048585267916009036365710264438282151016987719721438253993712264062937230689439798626603540528386566457404048672062339473039860668005261495297352561010145744255873393)

ctList.append(8508123324873244662238361728048440402054587973222246513895416540531363634468089624805306267892142757539405372887728058987070709291255161229169783427744197554810929294624818841043277925382601062445700516343505356400603561640609350325447125887199279975249174625127295013176148629587709448262232689085803437842947914768311783512606427190626609128180255532699943180575394359316664134721271191580221689665876739027247646314643721230024537714489024052254607910247505267966021004720891619963238885181604695835124826256835095035153455912811066958212438599564767354287388934012818621057430074083183324162622895847005920761745)
nList.append(13031735353809996296084731404536929850281508848111623050218978507464753552372863655602128108861393923255535113289336317493442152496001204016874656289493346075300710424262876620966379248833851746457139396371749762173881515647740101948954471426350041495470490874113568032353821914145960365020383435441766663755639424935088054070962854797141113005874065324320490341190957577883206903548349793497955066147015966078282817520527874326696249078140214971417458474912564275090629627804178797742907749308633950303087585670823988555957577001094073517965009577352815740379464168629436298617245283550519950526737206884964954051361)

messagePower8 = crt(nList, ctList)[0]
hsh = int(iroot(int(messagePower8),8)[0])
print(f"{hsh=}")
hsh=146913410772757766194482407144214295333114411765260602423197339861209058274813

debug = True
r = remote("tjc.tf", 31628, level = 'debug' if debug else None)

r.recvuntil('n: ')
r.recvline()
r.sendline(str(hsh))
r.recvall()

#b'tjctf{iloversaasmuchasilovemymom0xae701ebb}\n'
		    
```
		    
<p> <b>Flag :</b> tjctf{iloversaasmuchasilovemymom0xae701ebb} </p>

<br/>

## Scramble

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img11.png)

Source code :  

```py
		    
#first 3 lines are given
import random
seed = 1000
random.seed(seed)

#unscramble the rest
def recur(lst):
l2[i] = (l[i]*5+(l2[i]+n)*l[i])%l[i]
l2[i] += inp[i]
flag = ""
flag+=chr((l4[i]^l3[i]))
return flag
l.append(random.randint(6, 420))
l3[0] = l2[0]%mod
for i in range(1, n):
def decrypt(inp):
for i in range(n):
assert(len(l)==n)
return lst[0]
l = []
main()
def main():
l4 = [70, 123, 100, 53, 123, 58, 105, 109, 2, 108, 116, 21, 67, 69, 238, 47, 102, 110, 114, 84, 83, 68, 113, 72, 112, 54, 121, 104, 103, 41, 124]
l3[i] = (l2[i]^((l[i]&l3[i-1]+(l3[i-1]*l[i])%mod)//2))%mod
if(len(lst)==1):
assert(lst[0]>0)
for i in range(1, n):
for i in range(n):
return recur(lst[::2])/recur(lst[1::2])
print("flag is:", decrypt(inp))
l2[0] +=int(recur(l2[1:])*50)
l2 = [0]*n
flag_length = 31
mod = 256
print(l2)
n = len(inp)
inp = [1]*flag_length
l3 =[0]*n

```
		    
Solve script :
		    
```py
		    
#first 3 lines are given
import random
seed = 1000
random.seed(seed)

#unscramble the rest

def recur(lst):
    if(len(lst)==1):
        assert(lst[0]>0)
        return lst[0]
    return recur(lst[::2])/recur(lst[1::2])

def decrypt(inp):

    l = []
    n = len(inp)
    for i in range(n):
        l.append(random.randint(6, 420))
    assert(len(l)==n)

    mod = 256
    l2 = [0]*n
    l3 =[0]*n

    for i in range(1, n):
        l2[i] = (l[i]*5+(l2[i]+n)*l[i])%l[i]
    for i in range(1, n):
        l2[i] += inp[i]
    l2[0] +=int(recur(l2[1:])*50)
    l3[0] = l2[0]%mod
    #print(l2)
    l4 = [70, 123, 100, 53, 123, 58, 105, 109, 2, 108, 116, 21, 67, 69, 238, 47, 102, 110, 114, 84, 83, 68, 113, 72, 112, 54, 121, 104, 103, 41, 124]
    for i in range(1, n):
        l3[i] = (l2[i]^((l[i]&l3[i-1]+(l3[i-1]*l[i])%mod)//2))%mod

    flag = ""
    for i in range(n):
        flag+=chr((l4[i]^l3[i]))
    return flag

def main():
    flag_length = 31
    inp = [1]*flag_length
    print("flag is:", decrypt(inp))

main()

#flag is: tjctf{unshuffling_scripts_xdfj}
		    
```
		    
<p> <b>Flag :</b> tjctf{iloversaasmuchasilovemymom0xae701ebb} </p>

<br/>

## Ezdlp

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img12.png)

Source code :  

```py
		    
g = 8999 
s = 11721478752747238947534577901795278971298347908127389421908790123 
p = 12297383901740584470151577318651150337988716807049317851420298478128932232846789427512414204247770572072680737351875225891650166807323215624748551744377958007176198392481481171792078565005580006750936049744616851983231170824931892761202881982041842121034608612146861881334101500003915726821683000760611763097

g^x = s mod p
flag = tjctf{x}

```
		    
Solve script : 
		    
```py
		    
g = 8999
s = 11721478752747238947534577901795278971298347908127389421908790123
p = 12297383901740584470151577318651150337988716807049317851420298478128932232846789427512414204247770572072680737351875225891650166807323215624748551744377958007176198392481481171792078565005580006750936049744616851983231170824931892761202881982041842121034608612146861881334101500003915726821683000760611763097

dlog = mod(int(s), p).log(g)
flag = 'tjctf{' + str(dlog) + "}"
print(flag)
		    
```

<p> <b>Flag :</b> tjctf{26104478854569770948763268629079094351020764258425704346666185171631094713742516526074910325202612575130356252792856014835908436517926646322189289728462011794148513926930343382081388714077889318297349665740061482743137948635476088264751212120906948450722431680198753238856720828205708702161666784517} </p>

<br/>

## Beep Boop Robot

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img13.png)
		    
Morse code. Use <a href="https://morsecode.world/international/decoder/audio-decoder-adaptive.html" target="_blank">this site</a>.
		    
<p> <b>Flag :</b> tjctf{thisisallonewordlmao} </p>

<br/>

## Baby RSA

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img14.png)

Solve script :  

```py
		    
from Crypto.Util.number import *

n = 10888751337932558679268839254528888070769213269691871364279830513893837690735136476085167796992556016532860022833558342573454036339582519895539110327482234861870963870144864609120375793020750736090740376786289878349313047032806974605398302398698622431086259032473375162446051603492310000290666366063094482985737032132318650015539702912720882013509099961316767073167848437729826084449943115059234376990825162006299979071912964494228966947974497569783878833130690399504361180345909411669130822346252539746722020515514544334793717997364522192699435604525968953070151642912274210943050922313389271251805397541777241902027
e = 3
c = 2449457955338174702664398437699732241330055959255401949300755756893329242892325068765174475595370736008843435168081093064803408113260941928784442707977000585466461075146434876354981528996602615111767938231799146073229307631775810351487333

print(long_to_bytes(c**(1/3)))
#b'tjctf{thr33s_4r3_s0_fun_fb23d5ed}'
		    
```
		    
<p> <b>Flag :</b> tjctf{thr33s_4r3_s0_fun_fb23d5ed} </p>

<br/>

## Hi

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img15.png)

Inspect element :
		    
![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img16.png)
		    
<p> <b>Flag :</b> tjctf{pretty_canvas_577f7045} </p>

<br/>

## Survey	    

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img17.png)
		    
<p> <b>Flag :</b> tjctf{thanks_for_playing} </p>

<br/>

## Discord	

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img18.png)
		    
<p> <b>Flag :</b> tjctf{b4ck_4t_1t_4ga1n} </p>
		    
