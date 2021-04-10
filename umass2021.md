---
layout: page
title: UMass 2021 CTF Writeup
---
<hr/>

Me and my team competed in the <a href="https://ctftime.org/event/1282" target="_blank">University of Massachusetts Amherst's Capture The Flag (CTF)</a> event (Fri, 26 March 2021, 22:00 UTC — Sun, 28 March 2021, 22:00 UTC). This was my first 48 hour CTF as well as my first international CTF. We ranked 46th out of 660 scoring teams.

I learnt alot of new skills and came across my first Python Jail CTF challenge.

Below are the writeups for the 3 challenges that I managed to solve :

<br/>

# Jeopardy (Python Jail Escape Challenge)

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img1-ConvertImage.png)

This challenge is based on a famous TV game show / quiz competition called Jeopardy. As shown in the image below, after entering the correct answer for a particular challenge, you are awarded certain characters. A lot of the questions were very hard but we managed to get the answer to every question save one (the Cybersecurity Yesterday 500 point question, if someone is curious the question is "DoD wrote this during the Cold War").

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img3-ConvertImage.png)

The miscellaneous 10,000 point question (Question : "The Umass Cybersecurity club holds many talks from a wide variety of industry professionals in the tech scence. One such company may have leaked a password to something they were demoing during their presentation but did not care. What was the password displayed on the screen?") was particularly hard to get and looked really random and incredibly daunting. However, after looking at the hint I guessed that this must be a video uploaded on Youtube or somewhere where a company was presenting something to the UMass Amherst Cybersecurity Club (the event organisers) and the password was revealed (within the first 30 minutes of the video).

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img2-ConvertImage.png)

After a lot of Googling and a lot of patience, I managed to find the <a href="https://www.youtube.com/watch?v=Ph2ojl3qbmI" target="_blank">Youtube video</a> where at around the 10 and half minute mark the password (gSH1GgcJHimHy0XaMn) was shown. I was incredibly ecstatic after getting this!!!! But the job was far from over.

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img4-ConvertImage.png)

Below are the two images of the answers to the questions as well as the characters that we received.

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img5-ConvertImage.png)

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img6-ConvertImage.png)

If you inputted in a wrong answer, you would not receive the character and would hence have to redo everything again because the jail break would require us to have as many characters available to us as possible. If you get a question wrong, you cannot reanswer that question again. Inputting all the answers also takes a lot of time. As a result, I made an Apple Script to input the answers that we got to save us from the hassle of redoing everything if we inputted a wrong answer. 

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img7-ConvertImage.png)

After this, I was stuck with regards to what should be done. However, my teammate had just solved another jailbreak question which gave us a few ideas. We realized that we could print out all the files in the directory using the characters that we had (the image below shows all the characters that we could use after answering the questions as well as the command we used to print out all of the files). 

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img8-ConvertImage.png)

We knew that the flag was inside the `flag.txt` file however the problem was that we did not have access to the letter 'l' (I am guessing that the one question we could not answer would allow us to use the letters j,k and l). After a lot of Googling, I found a way to print out the contents of files based on their first letter. This allowed me to bypass the problem of not having the letter 'l' in order to print out the contents of flag.txt. There was also only one file that started with the letter 'f' so that certainly helped. Sure enough, after printing out the contents of every file that starts with the letter 'f' (since we wanted the contents of flag.txt), we got the flag!

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img9-ConvertImage.png)

**Flag :** UMASS{thank-you-alex}

I am presuming that Alex refers to the late Alex Trebek (he died a few months earlier in November 2020), the famous Jeopardy host who hosted the show for 37 seasons from 1984 to 2020). RIP Alex! 

<br/>

# Notes (Memory Forensics Challenge)

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img10-ConvertImage.png)

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img11-ConvertImage.png)

This challenge was really similar to the memory forensics challenge that I solved in the SMU WhiteHacks 2021 CTF using the memory forensics framework known as Volatility. The title of the challenge even suggested that the flag was probably in the notepad.exe application. After getting some basic information about the memory image as well as supplying a profile to Volatility, I listed out all the processes that were running on the machine when the RAM image was made using the `pslist` command.

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img12-ConvertImage.png)

After that I dumped the data from the only notepad.exe process that was running and then used strings and grep to search for the flag. I did not realize that notepad stores text in 16-bit little-endian (this <a href="https://www.andreafortuna.org/2018/03/02/volatility-tips-extract-text-typed-in-a-notepad-window-from-a-windows-memory-dump/" target="_blank">website</a> clarified that). The website said that the “-e l” switch is needed because notepad stores text in 16-bit little-endian. So I ran the command `strings -e l ./2696.dmp | grep "UMASS" -B 10 -A 10` to search for the flag (the -B 10 and -A 10 just prints out the ten precedding and succeeding lines after the main search "UMASS". I did this incase the text spanned multiple lines). Sure enough, after that I got the flag!

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img13-ConvertImage.png)

**Flag :** UMASS{$3CUR3_$70Rag3}

<br/>

# Scan Me (Image Editing Challenge? Idk which category this fell under)

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img14-ConvertImage.png)

This challenge was the easiest of the three that I could solve. We had a .xcf file which is the native image format of the GIMP image-editing application. After opening the image in GIMP and reducing the opacity I got a QR code where the bottom left was corrupted. 

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img15-ConvertImage.png)

All I did was add the top left square and paste it into the bottom left to make it mimic what a normal QR code looks like. 

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img16-ConvertImage.png)

After that I used a scanner to scan the QR code, I got an <a href="https://imgur.com/a/57VgQ8M" target="_blank">Imgur link</a>. 

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img17-ConvertImage.png)

When I opened that link, the flag was there!

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img18-ConvertImage.png)

**Flag :** UMASS{QR-3Z-m0d3}
