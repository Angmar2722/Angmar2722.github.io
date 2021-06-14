---
layout: page
title: BCACTF 2021 CTF Writeup
---
<hr/>

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img1.png)

I competed in <a href="https://ctftime.org/event/1265" target="_blank">Bergen County Academies' 2021 BCACTF 2.0</a> CTF event on my own (first time playing solo in a CTF). I ranked 117th out of 953 teams (841 scoring) and I managed to solve 27 challenges. This was the first time that I managed to solve atleast one challenge from every category in a CTF. Date and time : Fri, 11 June 2021, 08:00 SGT — Mon, 14 June 2021, 08:00 SGT.

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

<br/>

# Math Analysis (Binary Exploitation)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img18.png)

The source code and executable was provided. Here is the source code :

```c

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void cheat() {
    FILE *fp = fopen("flag.txt", "r");
    char flag[100];

    if (fp == NULL) {
        puts("Hmmm... I can't find my answers.");
        puts("That's not good, but at least it means you can't cheat!");
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

    puts("It's math time, baby!");
    puts("WOOO I love my numbers and functions and stuff!!");
    printf("For example, here's a number: %d.\n", cheat);
    puts("What do you think about that wonderful number?");
    printf("> ");
    gets(response);

    srand(time(NULL));
    switch (rand() % 5) {
        case 0:
            puts("Hmm, that's an interesting way to look at that.");
            break;
        case 1:
            puts("Oh, but you forgot about [insert obscure math fact].");
            break;
        case 2:
            puts("Yeah, isn't that pretty cool?");
            break;
        case 3:
            puts("Well, you better like it because that's what we're learning about.");
            break;
        case 4:
            puts("Numbeerrrrrs!");
            break;
    }

    puts("Anyways, we have a test coming up.");
    puts("Be sure to study!");
}

```

Similar to the Advanced Math Analysis, we have a buffer overflow vulnerability here due to `gets()`. The buffer is again 64 bytes even though it is initialized wiht 50 bytes. An interesting thing to note here is that we don't even need to use objdump to get the address of `cheat()` as the line `printf("For example, here's a number: %d.\n", cheat);` prints out the address of cheat as calling a function without parentheses in C returns the address of that function. So our payload is similar to the previous challenge - overflow 72 bytes consisting of the 64 byte buffer and 8 byte base pointer and then add the address of `cheat()`. This was the payload : `python2 -c 'print("\x00"*72+"\x56\x12\x40\x00\x00\x00\x00\x00")' | nc bin.bcactf.com 49158`.

After running it we get the flag :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img19.png)

**Flag :** bcactf{challenges_are_just_functions_mapping_from_coffee_to_points}

<br/>

# Movie-Login-2 (Web)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img21.png)

Login page was the exact same as Movie-Login-3. The exploit involved a SQL injection and there was a shorter list of blacklisted characters :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img20.png)

The command to bypass the authentication scheme was `' or true--`.

**Flag :** bcactf{h0w_d1d_y0u_g3t_h3r3_th1s_t1m3?!?}

<br/>

# Agent Gerald (Web)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img22.png)

I changed my browser's user agent to "Agent Gerald" and then got the flag when I entered the website.

**Flag :** bcactf{y0u_h@ck3d_5tegos@urus_1nt3lligence}

<br/>

# AP ABCs (Binary Exploitation)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img23.png)

Source code for the challenge :

```c

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

char *correct = "abcdefghijklmnopqrstuvwxyz";

int main() {
    int score = 1;
    char response[50];

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    puts("Welcome to AP ABCs!");
    puts("Unlike the non-AP class, you get the privilege of taking the AP test.");
    puts("Wow, I know, so exciting right\?\?!1");
    puts("Anyways, good luck!");
    sleep(2);
    puts("");
    puts("╔══════════════════════════════════════════╗");
    puts("║ 2021              AP® | 🌰 College Board ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║  ───────────────────────                 ║");
    puts("║  AP Alphabet                             ║");
    puts("║  Free-Response Questions                 ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║ Something about trademarks               ║");
    puts("╚══════════════════════════════════════════╝");
    sleep(2);
    puts("");
    puts("╔══════════════════════════════════════════╗");
    puts("║          2021 AP® Alphabet FRQs          ║");
    puts("║                                          ║");
    puts("║                 ALPHABET                 ║");
    puts("║                Section II                ║");
    puts("║             Total Time—1 hour            ║");
    puts("║           Number of Questions—1          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║ 1. Recite the alphabet                   ║");
    puts("║                                          ║");
    puts("║ ──────────────────────────────────────── ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                                          ║");
    puts("║                   STOP                   ║");
    puts("║                END OF EXAM               ║");
    puts("║                                          ║");
    puts("║                    -2-                   ║");
    puts("╚══════════════════════════════════════════╝");
    sleep(1);
    puts("");
    printf("Answer for 1: ");
    gets(response);

    for (int i = 0; i < 26; ++i) {
        if (response[i] == 0)
            break;
        if (response[i] != correct[i])
            break;

        if (i == 0)
            score = 1;
        if (i == 7 || i == 14 || i == 20 || i == 24)
            ++score;
    }

    puts("");
    printf("You got a %d on your APs.\n", score);

    if (score == 1)
        puts("Ouch. That hurts.");
    else if (score == 2)
        puts("At least that's not a 1...");
    else if (score == 3)
        puts("You are \"qualified\".");
    else if (score == 4)
        puts("You are \"very well qualified\".");
    else if (score == 5)
        puts("Nice job!");
    else if (score == 0x73434241) {
        puts("Tsk tsk tsk.");
        sleep(2);
        puts("Cheating on the AP® tests is really bad!");
        sleep(2);
        puts("Let me read you the College Board policies:");
        sleep(2);
        
        FILE *fp = fopen("flag.txt", "r");

        if (fp == NULL) {
            puts("AAAA, I lost my notes!");
            puts("You stay here while I go look for them.");
            puts("And don't move, you're still in trouble!");
            puts("[If you are seeing this on the remote server, please contact admin].");
            exit(1);
        }

        int c;
        while ((c = getc(fp)) != EOF) {
            putchar(c);
            usleep(20000);
        }

        fclose(fp);
    }
}

```

I have to overflow the buffer to make the score equal 0x73434241 and if that happens, I get the flag. Once again, `gets()` allows me to overflow the buffer and after playing around with the `print_hex_memory()` function from the Angstrom 2021 CTF, I desgined my payload : `python2 -c 'print("\x00"*76+"\x41\x42\x43\x73")' | nc bin.bcactf.com 49154`.

After injecting this into the server, we get the flag :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img24.png)

**Flag :** bcactf{bca_is_taking_APs_in_june_aaaaaaaa_wish_past_me_luck}

<br/>

# More than Meets the Eye (Forensics)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img25.png)

We are given a zwsp.txt file which contains just a single string "Pretty empty over here​‌​​​‌‌​‌‌​​​‌‌​‌​​​​‌‌​‌‌​​​‌‌​​​‌​‌‌‌​​‌‌​​‌‌​‌‌​‌‌‌‌​​‌​‌‌‌‌​‌‌​​‌‌​​​‌​​‌‌‌​​​​​‌‌​​‌‌‌‌‌​‌​‌‌‌​‌‌‌​‌​​​‌‌​​​​‌​​‌‌​​​‌​‌‌‌​​​​‌​‌‌​‌‌‌‌‌​‌​​‌​‌​‌‌​‌​‌​‌‌‌​​‌‌‌​‌‌​‌‌‌​​‌‌​​​‌‌​‌‌​‌‌​​‌‌​​‌‌‌‌‌​‌​​‌​‌​‌‌​​​​‌‌‌​​​‌​​‌‌​​‌​​​​‌‌​​​​‌‌‌‌​​​​‌​​‌​​​‌​‌‌​​‌​‌‌‌‌‌​." 

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img26.png)

The interesting thing about this string is that between the "e" and "." in "here.", there are dozens of <a href="https://en.wikipedia.org/wiki/Zero-width_space" target="_blank">zero-width spaces</a> hence the name `zwsp.txt`. After putting the string in this <a href="https://www.fontspace.com/unicode/analyzer#e=ZeKAi-KAjOKAi-KAi-KAi-KAjOKAjOKAi-KAjOKAjOKAi-KAi-KAi-KAjOKAjOKAi-KAjOKAi-KAi-KAi-KAi-KAjOKAjOKAi-KAjOKAjOKAi-KAi-KAi-KAjOKAjOKAi-KAi-KAi-KAjOKAi-KAjOKAjOKAjOKAi-KAi-KAjOKAjOKAi-KAi-KAjOKAjOKAi-KAjOKAjOKAi-KAjOKAjOKAjOKAjOKAi-KAi-KAjOKAi-KAjOKAjOKAjOKAjOKAi-KAjOKAjOKAi-KAi-KAjOKAjOKAi-KAi-KAi-KAjOKAi-KAi-KAjOKAjOKAjOKAi-KAi-KAi-KAi-KAi-KAjOKAjOKAi-KAi-KAjOKAjOKAjOKAjOKAjOKAi-KAjOKAi-KAjOKAjOKAjOKAi-KAjOKAjOKAjOKAi-KAjOKAi-KAi-KAi-KAjOKAjOKAi-KAi-KAi-KAi-KAjOKAi-KAi-KAjOKAjOKAi-KAi-KAi-KAjOKAi-KAjOKAjOKAjOKAi-KAi-KAi-KAi-KAjOKAi-KAjOKAjOKAi-KAjOKAjOKAjOKAjOKAjOKAi-KAjOKAi-KAi-KAjOKAi-KAjOKAi-KAjOKAjOKAi-KAjOKAi-KAjOKAi-KAjOKAjOKAjOKAi-KAi-KAjOKAjOKAjOKAi-KAjOKAjOKAi-KAjOKAjOKAjOKAi-KAi-KAjOKAjOKAi-KAi-KAi-KAjOKAjOKAi-KAjOKAjOKAi-KAjOKAjOKAi-KAi-KAjOKAjOKAi-KAi-KAjOKAjOKAjOKAjOKAjOKAi-KAjOKAi-KAi-KAjOKAi-KAjOKAi-KAjOKAjOKAi-KAi-KAi-KAi-KAjOKAjOKAjOKAi-KAi-KAi-KAjOKAi-KAi-KAjOKAjOKAi-KAi-KAjOKAi-KAi-KAi-KAi-KAjOKAjOKAi-KAi-KAi-KAi-KAjOKAjOKAjOKAjOKAi-KAi-KAi-KAi-KAjOKAi-KAi-KAjOKAi-KAi-KAi-KAjOKAi-KAjOKAjOKAi-KAi-KAjOKAi-KAjOKAjOKAjOKAjOKAjOKAiw" target="_blank">website</a>, you can see that after the 'e', there are 264 zero-width spaces and zero-width non joiners (special Unicode characters). Since we know that the first letter in the flag is "b" because of the flag format "bcactf{....}", we can see that if the zero-width space corresponds to a 0 and the zero-width non joiner corresponds to a 1, for the first 8 characters we have "01100010" which when reversed to "01100010" corresponds to a "b" in ASCII. Doing the same for the other bytes yields use the flag.

I tried to use <a href="https://github.com/enodari/zwsp-steg-py" target="_blank">zwsp-steg-py</a> but couldn't get it to work so I decoded the flag manually :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/IMG_0602.png)

**Flag :** bcactf{z3r0_w1dth_jungl3_j82axH4}

<br/>

# Secure Zip (Forensics)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img27.png)

This was a password protected zip file so I used the rockyou.txt list of common passwords to bruteforce the password and then get the flag :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img28.png)

**Flag :** bcactf{cr4ck1ng_z1p_p455w0rd5_15_fun_a12ca37bdacef7}

<br/>

# Gerald's New Job (Forensics)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img29.png)

The 'PDF' file was a polyglot generated using <a href="https://github.com/ansemjo/truepolyglot" target="_blank">truepolyglot</a>. I used `binwalk` to extract the file's signature, realized it was a zip, unzipped it and got the flag :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img30.png)

**Flag :** bcactf{g3ra1d_15_a_ma5ter_p01yg1ot_0769348}

<br/>

# A Fun Game (Reverse Engineering)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img31.png)

When you run the executable, it would display a letter and when you enter that letter you get 1 point. You get the flag after getting 1000 points and as pointed out by the hint, instead of painfully typing in 1000 letters, you could use a program like Game Conqueror which can modify the score variable in order to easily get the flag. I installed it on my Kali Linux machine and followed this <a href="https://linuxhint.com/use-gameconqueror-cheat-engine-linux/" target="_blank">guide</a> in order to learn how to use Game Conqueror. After figuring that out and changing the score variable to 1000, I got the flag :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img32.png)

**Flag :** bcactf{h0p3fu1ly_y0U_d1dNt_actUa1ly_tYpe_1000_1ett3rs}

<br/>

# Movie-Login-1 (Web)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img33.png)

The website was the same as the movie login 2 and 3 challenges, you had to bypass the username and password authentication using a SQL injection. There was no set of blacklisted characters and to bypass the authentication, I used this command : `admin' or '1'='1'--`.

**Flag :** bcactf{s0_y0u_f04nd_th3_fl13r?}

<br/>

# Wasm Protected Site 1 (Web)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img35.png)

The website just had a field for entering the password. Looking around the source code with Chrome Developer tools, I found the flag :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img36.png)

<br/>

# Little e (Cryptography)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img33.png)

Modulus (N) and ciphertext (ct) was given along with the public exponent (e) of 3. The plaintext was the cube root of ct % N which is just the cube root of ct (as ct < N) as ct = m^3 mod N.

**Flag :** bcactf{R54_N0T_50_S3CUR3_33}

<br/>

# BCA Mart (Binary Exploitation)

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img37.png)

Source code provided : 

```c

#include <stdio.h>
#include <stdlib.h>

int money = 15;

int purchase(char *item, int cost) {
    int amount;
    printf("How many %s would you like to buy?\n", item);
    printf("> ");
    scanf("%d", &amount);

    if (amount > 0) {
        cost *= amount;
        printf("That'll cost $%d.\n", cost);
        if (cost <= money) {
            puts("Thanks for your purchse!");
            money -= cost;
        } else {
            puts("Sorry, but you don't have enough money.");
            puts("Sucks to be you I guess.");
            amount = 0;
        }
    } else {
        puts("I'm sorry, but we don't put up with pranksters.");
        puts("Please buy something or leave.");
    }

    return amount;
}

int main() {
    int input;

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    puts("Welcome to BCA MART!");
    puts("We have tons of snacks available for purchase.");
    puts("(Please ignore the fact we charge a markup on everything)");

    while (1) {
        puts("");
        puts("1) Hichew™: $2.00");
        puts("2) Lays® Potato Chips: $2.00");
        puts("3) Water in a Bottle: $1.00");
        puts("4) Not Water© in a Bottle: $2.00");
        puts("5) BCA© school merch: $20.00");
        puts("6) Flag: $100.00");
        puts("0) Leave");
        puts("");
        printf("You currently have $%d.\n", money);
        puts("What would you like to buy?");

        printf("> ");
        scanf("%d", &input);

        switch (input) {
            case 0:
                puts("Goodbye!");
                puts("Come back soon!");
                puts("Obviously, to spend more money :)");
                return 0;
            case 1:
                purchase("fruity pieces of goodness", 2);
                break;
            case 2:
                purchase("b̶a̶g̶s̶ ̶o̶f̶ ̶a̶i̶r̶ potato chips", 2);
                break;
            case 3:
                purchase("bottles of tap water", 1);
                break;
            case 4:
                purchase("generic carbonated beverages", 2);
                break;
            case 5:
                purchase("wonderfully-designed t-shirts", 20);
                break;
            case 6:
                if (purchase("super-cool ctf flags", 100) > 0) {
                    FILE *fp = fopen("flag.txt", "r");
                    char flag[100];

                    if (fp == NULL) {
                        puts("Hmm, I can't open our flag.txt file.");
                        puts("Sorry, but looks like we're all out of flags.");
                        puts("Out of luck, we just sold our last one a couple mintues ago.");
                        puts("[If you are seeing this on the remote server, please contact admin].");
                        exit(1);
                    }

                    fgets(flag, sizeof(flag), fp);
                    puts(flag);
                }
                break;
            default:
                puts("Sorry, please select a valid option.");
        }
    }
}

```

The objective is to buy the flag which costs $100 when we are given only $15. In C, an integer is 32 bits that is signed by default so if I input an amount that is slightly more than (2^32 / 100), the cost would be negative and we would get the flag :

![BCACTF 2021 Writeup](/assets/img/ctfImages/bcactf2021/img38.png)

**Flag :** <p> bcactf{bca_store??_wdym_ive_never_heard_of_that_one_before} </p>
