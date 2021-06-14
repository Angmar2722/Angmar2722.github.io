---
layout: page
title: BCACTF 2021 CTF Writeup
---
<hr/>

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img1.png)

I competed in <a href="https://ctftime.org/event/1265" target="_blank">Bergen County Academies' 2021 BCACTF 2.0</a> CTF event on my own (first time playing solo in a CTF). I ranked 117th out of 953 teams (841 scoring) and I managed to solve 27 challenges. Date and time : Fri, 11 June 2021, 08:00 SGT — Mon, 14 June 2021, 08:00 SGT.

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

<p>So at 0x04e, “i32.load8_u” loads a character from the encoded flag. Since the encoded flag is “bjsxPKMH|\x227N\x1bD\x043b]PR\x19e%\x7f/;\x17”, it loads the character “b” from this encoded flag the first time. The line “local.get $v2” loads the index of the loaded character so for “b” it would be 0, for “j” it would be 1 and so on (like index values in an array). This index is then multiplied by 9. That result is then put in a bitwise AND operation with 127. Then that result is XORed with the selected encoded character (so “b” for the first time, “j” for the second, “s” for the third and so on) and then the server checks the result with the corresponding correct flag character so “bactf{flag}” to see if the character matches. If it doesn't, it exits (lines 0x64 and 0x65) and if it does match, it continues this process character by character to see if the inputted flag matches. </p>

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

# Advanced Math Analysis (Binary Exploitation)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img9.png)

The source code and executable was provided. Here is the source code :

```c

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cheat() {
    FILE *fp = fopen("flag.txt", "r");
    char flag[100];

    if (fp == NULL) {
        puts("My bad, I can't find the answers.");
        puts("Oh wait, that's a foodable offense!");
        puts("[If you are seeing this on the remote server, please contact admin].");
        exit(1);
    }

    fgets(flag, sizeof(flag), fp);
    puts(flag);
}

int main() {
    char response[50];

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    puts("Welcome to the more advanced math class!");
    puts("Unlike the folks in regular analysis, you'll have to put in more effort.");
    puts("That's because this class has a strict anti-cheating defense.");
    puts("Ha, take that!");
    puts("We have to maintain the BCA reputation somehow, y'know.");
    printf("> ");
    gets(response);

    if (strcmp(response, "i pledge to not cheat")) {
        puts("I'm sorry, but you did not type out the honor pledge.");
        puts("This obviously means that you are a cheater.");
        puts("And we certainly cannot have that.");
        puts("Goodbye.");
        exit(1);
    }

    puts("Hey, I'm glad you decided to be honest and not cheat!");
    puts("Makes my life a whole lot easier when I can let my guard down.");
    puts("You still have to do tests and whatnot, but that's a you problem.");
}

```

And after running the standard chekcs on the executable, we can see that this challenge involves a buffer overflow (due to the vulnerability of `gets`) as no stack canaries were found and NX was enabled (so this challenge probably had nothing to do with shellcode execution) :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img10.png)

A quick objdump of `main` shows that even though the buffer was initialized with 50 bytes, the buffer is actually allocated 64 bytes :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img11.png)

Note that we also have the line `if (strcmp(response, "i pledge to not cheat")) {` which means that if the strings are equal, the program would not enter this if clause as equal strings in strcmp returns 0. Anything else would have returned a non zero value and hence entered this clause and exited (`exit(1)`). So we know that inside `main`, the buffer is 64 bytes, the next 8 bytes are the base pointer and the next 8 bytes are the return address of main. So if we overflow these 72 bytes and then add the return address of `cheat` (found using objdump) which is where we want to go, `main` would return to `cheat` and then print out the flag.

This was the payload : `python2 -c 'print("i pledge to not cheat"+"\x00"*51+"\x16\x12\x40\x00\x00\x00\x00\x00")' | nc bin.bcactf.com 49156`

And after running it on their server, we get the flag :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img12.png)

**Flag :** bcactf{corresponding_parts_of_congurent_triangles_are_congruent_ie_CPCCTCPTPPTCTC}

<br/>

# Movie-Login-3 (Web)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img13.png)

When we go to the website, we are shown a login page where we have to enter the username and password :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img14.png)

To bypass this authentication scheme, we have to use a SQL injection. There was a list of blacklisted characters though :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img15.png)

None of those characters could be used. After a bit of Googling, I found <a href="https://github.com/Ne3o1/PayLoadAllTheThings/blob/master/SQL%20injection/README.md#authentication-bypass" target="_blank">this</a>
list of SQL injections for authentication bypass. This command seemed to work : `admin' or 2 LIKE 2--`. After entering that, we get the flag :
 
![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img16.png)

**Flag :** bcactf{gu3ss_th3r3s_n0_st0pp1ng_y0u!}

<br/>

# American Literature (Binary Exploitation)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img17.png)

The source code and executable was provided. Here is the source code :

```c

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    int length;
    char essay[50];

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    puts("Hey all!");
    puts("Welcome to Amer Lit!");
    puts("In this class, we will be reading books");
    puts("(wow who would have guessed)");
    puts("and then doing fun things like writing essays!");
    sleep(1);
    puts("Y'know what, let me get a really good example of an essay.");

    FILE *fp = fopen("flag.txt", "r");
    char example_essay[100];

    if (fp == NULL) {
        puts("Oh no, I can't find my former students' essays!");
        puts("How now will I set the bar redicuolously high for new students??");
        puts("[If you are seeing this on the remote server, please contact admin].");
        exit(1);
    }

    fgets(example_essay, sizeof(example_essay), fp);

    sleep(1);
    puts("Actually, on further thought...");
    puts("You're a BCA student, you should be able to write a perfect essay immediately.");
    puts("Let's see it!");

    fgets(essay, sizeof(essay), stdin);
    essay[strcspn(essay, "\n")] = 0;
    length = strlen(essay);

    sleep(1);
    puts("");
    puts("TURNITIN SUBMISSION RECEIVED:");

    printf("╔═");
    for (int i = 0; i < length; ++i) printf("═");
    printf("═╗\n");

    printf("║ ");
    for (int i = 0; i < length; ++i) printf(" ");
    printf(" ║\n");

    printf("║ ");
    for (int i = 0; i < length; ++i) printf(" ");
    printf(" ║\n");

    printf("║ ");
    printf(essay);
    printf(" ║\n");

    printf("║ ");
    for (int i = 0; i < length; ++i) printf(" ");
    printf(" ║\n");

    printf("║ ");
    for (int i = 0; i < length; ++i) printf(" ");
    printf(" ║\n");

    printf("╚═");
    for (int i = 0; i < length; ++i) printf("═");
    printf("═╝\n");

    sleep(2);
    puts("");
    puts("You've clearly put a lot of work and effort into this.");
    puts("How about an 89?");
}

```

This challenge involved exploiting the format string vulnerbility in the line `printf(essay);` as you could leak pointer values from the stack with your input. The flag was leaked from the 20th to 32nd argument (%20$p to %32$p). It would give a hexadecimal output which when converted to ASCII and then reversed would give 8 bytes of the flag at a time.

**Flag :** bcactf{totally_not_employing_the_use_of_generic_words_to_reach_the_required_word_limit_nope_not_me}
