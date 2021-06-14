---
layout: page
title: BCACTF 2021 CTF Writeup
---
<hr/>

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img1.png)

I competed in <a href="https://ctftime.org/event/1265" target="_blank">Bergen County Academies' 2021 BCACTF 2.0</a> CTF event on my own (first time playing solo in a CTF). I ranked 117th out of 953 teams (841 scoring) and I managed to solve 27 challenges.

I was pleased with my performance for the web challenges as since my first two CTFs (Whitehacks 2021 and CTF SG 2021), I have never solved a web challenge.

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img3.png)

I managed to solve 3/4ths of the binary exploitation challenges too :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img4.png)

Below are the writeups for the challenges that I managed to solve :

<br/>

# Wasm Protected Site 2 (Web)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img5.png)

When you go to the website that they provided, you would just see a textfield for entering the flag. If what you entered wasn't the flag, it would output incorrect flag and vice-versa. Nothing interesting here.

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img6.png)

Aftering looking around with my browser's developer tools, I found the heart of this website, a Wasm (<a href="https://en.wikipedia.org/wiki/WebAssembly
" target="_blank">Web Assembly</a>) file which contained some source code :

```wasm

(module
  (memory $memory (;0;) (export "memory") 1)
  (func $cmp (;0;) (param $v0 (;0;) i32) (param $v1 (;1;) i32) (result i32)
    (local $v2 (;2;) i32)
    loop $label0
      local.get $v2
      local.get $v0
      i32.add
      i32.load8_u
      local.get $v2
      local.get $v1
      i32.add
      i32.load8_u
      local.get $v2
      i32.const 9
      i32.mul
      i32.const 127
      i32.and
      i32.xor
      i32.ne
      local.get $v2
      i32.const 27
      i32.ne
      i32.and
      if
        i32.const 0
        return
      end
      local.get $v2
      i32.const 1
      i32.add
      local.tee $v2
      i32.const 1
      i32.sub
      local.get $v0
      i32.add
      i32.load8_u
      i32.eqz
      if
        i32.const 1
        return
      end
      br $label0
    end $label0
    i32.const 0
    return
  )
  (func $checkFlag (;1;) (export "checkFlag") (param $a (;0;) i32) (result i32)
    local.get $a
    i32.const 1000
    call $cmp
    return
  )
  (data (i32.const 1000) "bjsxPKMH|\227N\1bD\043b]PR\19e%\7f/;\17")
)

```

After a lot of Googling and trying to understand this code, this is what I came up with :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img7.png)

So at 0x04e, “i32.load8_u” loads a character from the encoded flag. Since the encoded flag is “bjsxPKMH|\x227N\x1bD\x043b]PR\x19e%\x7f/;\x17”, it loads the character “b” from this encoded flag the first time. The line “local.get $v2” loads the index of the loaded character so for “b” it would be 0, for “j” it would be 1 and so on (like index values in an array). This index is then multiplied by 9. That result is then put in a bitwise AND operation with 127. Then that result is XORed with the selected encoded character (so “b” for the first time, “j” for the second, “s” for the third and so on) and then the server checks the result with the corresponding correct flag character so “bactf{flag}” to see if the character matches. If it doesn't, it exits (lines 0x64 and 0x65) and if it does match, it continues this process character by character to see if the inputted flag matches. 

So to get the flag, you could reverse this process which is done using the following Python script :

```python

eflag = b'bjsxPKMH|\x227N\x1bD\x043b]PR\x19e%\x7f/;\x17'

flag = ""
c9 = 0
for ea in eflag:
    m = c9 & 127
    v = ea ^ m
    #print(ea, c9, m, v, chr(v))
    c9 += 9
    flag += str(chr(v))

print("Flag:",flag)

```

And after running this script, you get the flag :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img8.png)

**Flag :** bcactf{w4sm-w1z4rDry-Xc0wZ}

<br/>



