---
layout: page
title: TJCTF 2023 Writeup
---
<hr/>

![TJCTF 2023 Writeup](/assets/img/ctfImages/2023/tjctf2023/img1.png)

I participated in Thomas Jefferson High School for Science and Technology's <a href="[https://ctftime.org/event/1656](https://ctftime.org/event/1865)" target="_blank">TJCTF 2023</a> event (Fri, 26 May 2023, 08:00 SGT — Sun, 28 May 2023, 08:00 SGT), playing solo. In the end, I ranked 19<sup>th</sup> out of 1047 scoring teams. All the attached files can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/tree/master/assets/ctfFiles/2023/tjctf2023" target="_blank">here</a>.

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
|[Div3rev](#squishy) | Rev | 36 | 102 | 
|[IHeartRSA](#iheartrsa) | Crypto | 35 | 106 | 
|[Scramble](#scramble) | Rev | 23 | 153 | 
|[Ezdlp](#ezdlp) | Crypto | 18 | 188 | 
|[Beep Boop Robot](#beep-boop-robot) | Forensics | 6 | 558 | 
|[Baby RSA](#baby-rsa) | Crypto | 6 | 576 | 
|[hi](#hi) | Web | 4 | 840 | 
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
                                                      
                                                    
                                                      
                                                    
