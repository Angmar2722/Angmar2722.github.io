---
layout: page
title: Google 2021 CTF Writeup
---
<hr/>

![Google CTF 021 Writeup](/assets/img/ctfImages/google2021/googleCTFlogo.png)

Initially, I wasn't planning on even participating in the <a href="https://ctftime.org/event/1318" target="_blank">2021 Google CTF</a> event because it had a rating weight of 99.22 on CTFtime which speaks volumes about its immensive difficulty. I was rightfully positive about the fact that even the simplest challenges would be much more difficult than normal CTFs. I was still relatively new to CTFs (it had been nearly 5 months since I started) and I knew that this was definitely an 'elite' CTF which all the top teams would participate in.

The CTF time schedule was Sat, 17 July 2021, 08:00 SGT — Mon, 19 July 2021, 07:59 SGT. When it started at 8 am, I just briefly looked at the challenges incase there was something that I could even remotely think of attempting and turns out there wasn't :( However, at 4 pm or after 12 hours, they released new challenges and one of them was the cryptography challenge known as "Pythia" which was a challenge about AES-GCM. I knew just a bit about how that worked and could understand what was happening in the attached server code so I thought that I could give it a shot. Instead of the usual team name 'Isengard', I instead chose 'gcmTime' for this CTF. I called up Diamondroxxx and we immeditaly started working on Pythia and after solving that, we tried other challenges till the end of the CTF. 

As expected, even the easiest challenge (in terms of solves) would still be considered a medium difficulty challenge in some other CTFs (at least in my opinion). The challenges were of very high quality and most proved to be out of reach for us. In the end, we managed to solve 3 challenges and we ranked 80th out of 379 scoring teams. 

![Google CTF 021 Writeup](/assets/img/ctfImages/google2021/img1.png)

Overall, this CTF was a fantastic learning experience and gave me a sense of what a top or elite CTF looked like, suffice to say it was very challenging.... Even for the challenges that I couldn't solve but at least attempted, I managed to learn a lot and was introduced to new concepts which I had absolutely no knowledge about previously such as the Hidden Number Problem and Huffman Coding.

Below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[Story](#story) | Crypto | 249 | 32 | 
|[Pythia](#pythia) | Crypto | 173 | 65 |
|[Filestore](#scrambled-elgs) | Misc | 50 | 321 |

<br/>

<br/>

## Story

![Google CTF 021 Writeup](/assets/img/ctfImages/google2021/img3.png)

Server source code provided (this is in the <a href="https://en.wikipedia.org/wiki/Dart_(programming_language)" target="_blank">Dart</a> programming language) :

```dart

#!/usr/bin/env dart

import 'dart:convert';
import 'dart:io';

// NOTE: calculate and randomize functions are private (i.e., you don't have access).
import 'package:ctf_story/private.dart' show calculate, randomize;

int main(List<String> arguments) {
  final flag = File('flag.txt').readAsStringSync();
  print('Hello! Please tell me a fairy tale!');
  var line = stdin.readLineSync(encoding: utf8);
  if (utf8.encode(line).where((i) => i < 32 || i >= 128).isNotEmpty) {
    print('There are unprintable characters in your story.');
    return 0;
  }
  final firstText = line.toLowerCase();
  var crcValues = calculate(utf8.encode(line));
  print('The CRC values of your text are $crcValues.');
  List<String> expectedValues;
  do {
    expectedValues = randomize(utf8.encode(line));
  } while (expectedValues == crcValues);
  if (expectedValues == null) {
    print('Your story is too short. Bye!');
    return 0;
  }
  print('But I am looking for a story of $expectedValues.');
  line = stdin.readLineSync(encoding: utf8);
  final secondText = line.toLowerCase();
  crcValues = calculate(utf8.encode(line));
  if (firstText != secondText) {
    print('Perhaps you would like to start from scratch? Bye!');
    return 0;
  }
  if (List.generate(
              expectedValues.length, (i) => crcValues[i] == expectedValues[i])
          .indexOf(false) <
      0) {
    print('What a lovely story! Your flag is ${flag}');
  }
  print('Bye!');
  return 0;
}

```


