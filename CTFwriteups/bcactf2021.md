---
layout: page
title: BCACTF 2021 CTF Writeup
---
<hr/>

I competed in <a href="https://ctftime.org/event/1265" target="_blank">Bergen County Academies' 2021 BCACTF 2.0</a> CTF event on my own (first time playing solo in a CTF). I ranked 117th out of 953 teams (841 scoring) and I managed to solve 27 challenges.

Below are the writeups for the challenges that I managed to solve :

<br/>

# Wasm Protected Site 2 (Web)

![BCACTF 2021 Writeup](/assets/img/ctfImages/actf2021/img5.png)

When you go to the website that they provided, you would just see a textfield for entering the flag. If what you entered wasn't the flag, it would output incorrect flag and vice-versa. Nothing interesting here.

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






