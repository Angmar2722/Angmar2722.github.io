---
layout: page
title: UMass 2021 CTF Writeup
---
<hr/>

Me and my team competed in the University of Massachusetts Amherst's Capture The Flag (CTF) event (Fri, 26 March 2021, 22:00 UTC — Sun, 28 March 2021, 22:00 UTC). This was my first 48 hour CTF as well as my first international CTF. We ranked 46th out of 660 scoring teams.

I learnt alot of new skills and came across my first Python Jail CTF challenge.

Below are the writeups for the 3 challenges that I managed to solve :

# Jeopardy (Python Jail Escape Challenge)

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img1-ConvertImage.png)

This challenge is based on a famous TV game show / quiz competition called Jeopardy. As shown in the image below, after entering the correct answer for a particular challenge, you are awarded certain characters. A lot of the questions were very hard but we managed to get the answer to every question save one (the Cybersecurity Yesterday 500 point question, if someone is curious the question is "DoD wrote this during the Cold War").

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img3-ConvertImage.png)

The miscellaneous 10,000 point question (Question : "The Umass Cybersecurity club holds many talks from a wide variety of industry professionals in the tech scence. One such company may have leaked a password to something they were demoing during their presentation but did not care. What was the password displayed on the screen?") was particularly hard to get and looked really random and incredibly daunting. However, after looking at the hint I guessed that this must be a video uploaded on Youtube or somewhere where a company was presenting something to the UMass Amherst Cybersecurity Club (the event organisers) and the password was revealed (within the first 30 minutes of the video).

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img2-ConvertImage.png)

After a lot of Googling and a lot of patience, I managed to find the <a href="https://www.youtube.com/watch?v=Ph2ojl3qbmI" target="_blank">Youtube video</a> where at around the 10 and half minute mark the password was shown. I was incredibly ecstatic after getting this!!!! But the job was far from over.

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img4-ConvertImage.png)

Below are the two images of the answers to the questions as well as the characters that we received.

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img5-ConvertImage.png)

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img6-ConvertImage.png)

If you inputted in a wrong answer, you would not receive the character and would hence have to redo everything again (because the jail break would require us to have as many characters available to us as possible). Inputting all the answers also takes a lot of time. As a result, I made an Apple Script to input the answers that we got to save us from the hassle of redoing everything if we inputted a wrong answer. 

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img7-ConvertImage.png)

After this, I was stuck with regards to what should be done. However, my teammate had just solved another jailbreak question which gave us a few ideas. We realized that we could print out all the files in the server using the characters that we had (the image below shows all the characters that we could use after answering the questions as well as the command we used to print out all of the files). 

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img8-ConvertImage.png)

We knew that the flag was inside the flag.txt file however the problem was that we did not have access to the letter 'l'. After a lot of Googling, I found a way to print out the contents of files based on their first letter. This allowed me to bypass the problem of not having the letter 'l' in order to print out the contents of flag.txt. There was also only one file that started with the letter 'f' so that certainly helped. Sure enough, after printing out the contents of every file that starts with the letter 'f' (since we wanted the contents of flag.txt), we got the flag!

![UMass 2021 Writeup](/assets/img/ctfImages/umass2021/img9-ConvertImage.png)

**Flag :** UMASS{thank-you-alex}

I am presuming that Alex refers to the late Alex Trebek (he died a few months earlier in November 2020), the famous Jeopardy host who hosted the show for 37 seasons from 1984 to 2020). RIP Alex! 



