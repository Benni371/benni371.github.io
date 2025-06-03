---
layout: post
title:  "DFIRLABS: Gotham Hustle"
date:   2025-06-01 19:41:34 -0400
tags: dfir ctf-dfirlabs
author: Benshkies
---

## The Beginning to Suffering
Volatility has always been one of those tools that was like cool but I never saw true utility out of it other than running basic modules and having the ouput for flag given for me. This challenge is definitely not that. It makes you sweat, and bleed for the flags. So in spirit of that, I will give you a run down of my hardships while learning the ins and outs of basic volatility.


## The Suffering

First things first, lets get the basic image information so we know what we are dealing with:
```powershell
python3 vol.py -f "C:\Users\benshkies\Desktop\Cases\gotham\gotham.raw" windows.info.Info | ForEach-Object { $_.Trim() } | Set-Content "$output_dir\mem_info.txt"
```
By default, volatility's output is kind of wack so I used some powershell to trim up the white space
For the rest of the plugins, ill use this line and then just set the plugin before i run it. That way output is consistent:
```powershell
# set $plugin = "<plugin name>"
python3 vol.py -f "C:\Users\benshkies\Desktop\Cases\gotham\gotham.raw" $plugin | ForEach-Object { $_.Trim() } | Set-Content "$output_dir\$plugin.txt"
```
Nothing catches my eye with the output of pslist
Moving on to the Envars (plugin: windows.envars.Envars):
- Computername: Bruce-PC
- USERNAME	bruce
- USERPROFILE	C:\Users\bruce
Not seeing anything else here. Lots of repeating data about a csilogfile.log but dont thin kthats anything

Not shown here is me trying 13 other modules finding zilch, nada, zero on anything at all. Then a well placed question to the DFIRLABS discord nets me:
"\[I\] would suggest you to try volatility 2 for this lab as it's an older version of windows and it's only the challenge to give you experience on using volatility"

## The Suffering but with Vol2
Volatility2 can be downloaded but after spending an hour trying to get Python2 installed on my Win11 VM and it failing to read my Env Variables and install python2 correctly, I downloaded SANS SIFT workstation image and did that instead because it has Vol2 included along with all the community modules. SCORE!

So a quick boot of that VM and we are off with Vol2

Volatility2 is specific in that it needs a specific profile to run the modules on. To do that we use the `imageinfo` module:
`vol.py -f gotham.raw imaginfo`

Then we get output somewhat like:
```text
Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
```

Since `Win7SP1x64_23418` is the latest version, I'll just stick with that.

Now lets try some basic commands:
`vol.py -f gotham.raw --profile Win7SP1x64_23418 psscan` -- Yields......nothing.....great.

When in doubt run strings. Lets get a string dump of the image and see if we can get some easy wins:
`strings gotham.raw >> strings.txt`
Now we'll use the strings command for some analysis with grep, is this necessary? Idk but I did it

`vol.py -f gotham.raw --profile Win7SP1x64_23418 strings -s strings.txt | grep gotham
This outputs a peculiar set of strings

```text
Volatility Foundation Volatility Framework 2.6.1
744406256 [FREE MEMORY:-1] <h2 id="Challenge-Description"><a href="#Challenge-Description" class="headerlink" title="Challenge Description:"></a>Challenge Description:</h2><p>Bruce Wayne was alerted that Joker have escaped from Arkham Asylum, Joker with all the Gotham outlaws crafts a letter for Bruce, He wants to make it go all crazy x_0!,and now Batman gets a message sent to Him with a letter, but apparently as Damain was in the Desktop, he opens it and everything goes crazy, the letter is now distributed to everyone in gotham, if Batman doesn
1085961673 [FREE MEMORY:-1] Jgotham
1098571519 [FREE MEMORY:-1] gotham-chess.com/
```

BUT The above is actually a clue to Batman 4 so not very helpful. 

BUT below using another basic command, `cmdscan` we can see a command history of our boi brucey wayne:
```text
$ vol.py -f gotham.raw --profile Win7SP1x64_23418 cmdscan
Volatility Foundation Volatility Framework 2.6.1
**************************************************
CommandProcess: conhost.exe Pid: 4188
CommandHistory: 0x130de0 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 8 LastAdded: 7 LastDisplayed: 7
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
Cmd #0 @ 0x12f7c0: whoami
Cmd #1 @ 0x130110: dir
Cmd #2 @ 0x12f800: bi0s
Cmd #3 @ 0x12f820: dfirlabs
Cmd #4 @ 0x12d690: Ymkwc2N0Znt3M2xjMG0zXw==
Cmd #5 @ 0x12d6d0: azr43ln1ght.github.io
Cmd #6 @ 0x125650: Azr43lKn1ght
Cmd #7 @ 0x125680: did you find flag1?
Cmd #15 @ 0xb0158: 
Cmd #16 @ 0x12ff50: 
**************************************************
CommandProcess: conhost.exe Pid: 4140
CommandHistory: 0x280e10 Application: DumpItog.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x10
Cmd #15 @ 0x200158: (
Cmd #16 @ 0x27ff70: (

```

Is that a flag I see? Yes! Is that also [Azr43lKn1ght](azr43ln1ght.github.io) doing some self promotion in a challenge? 
Up for debate. Nonetheless decoding the base64 string gives us
```bash
$ echo "Ymkwc2N0Znt3M2xjMG0zXw==" | base64 -d
bi0sctf{w3lc0m3_
```

![[theoffice-stevecarrell.gif]]
So the flag is in parts, so we are in for ride with this challenge.

I saw some activity on bruces desktop so i did the `filescan` command with a grep pipe to look for files specifically in that directory because filescan is a beasty to parse through without any grep.
The -F means to take the string as a string and not a regular expression.

`vol.py -f gotham.raw --profile=Win7SP1x64_23418 filescan | grep -F "bruce\Desktop"`
```text
Volatility Foundation Volatility Framework 2.6.1
0x000000011ca4a800     15      0 R--rwd \Device\HarddiskVolume2\Users\bruce\Desktop\desktop.ini
0x000000011ec0eae0      2      1 R--rwd \Device\HarddiskVolume2\Users\bruce\Desktop
0x000000011ee1af20     13      0 R--r-d \Device\HarddiskVolume2\Users\bruce\Desktop\DumpItog.exe
0x000000011f2538c0      1      1 RW-rw- \Device\HarddiskVolume2\Users\bruce\Desktop\BRUCE-PC-20240806-183717.raw
0x000000011f558280      2      1 R--rwd \Device\HarddiskVolume2\Users\bruce\Desktop
0x000000011f97ca70      1      1 R--rw- \Device\HarddiskVolume2\Users\bruce\Desktop
0x000000011fdaff20     16      0 -W-r-- \Device\HarddiskVolume2\Users\bruce\Desktop\flag5.rarp\VirtualBox Dropped Files\2024-08-06T18_36_43.522668500Z\flag5.rar
```

Flag5.rar seems promising. Lets see if we can extract it:
```bash
vol.py -f gotham.raw --profile=Win7SP1x64_23418 dumpfiles --dump-dir=output/ -Q 0x000000011fdaff20 
```

-q references the offset (first column)

Getting that downloaded and running strings outputs
```text
$ cat output/file.None.0xfffffa80049f86a0.dat 
Rar!�3���
���틴��C�rB�CMTThe password for the zip file is the computer's passwordi���U<�� b�%flag.txt0��?$�:��q���6�<���HP7���ؖ��6������
!�7^ ��C�����k��
                �a��r��(i�sb?^P"�����v�͝�����wVQ
```

Just to see real quick if we could get bruces password, i used the `hashdump` module to dump the ntlm hashes:
```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:10eca58175d4228ece151e287086e824:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
bruce:1001:aad3b435b51404eeaad3b435b51404ee:b7265f8cc4f00b58f413076ead262720:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:bda4ed0acc67d6d60540d1a20cf444c6:::
```

Bruces password gets cracked into `batman` using crackstation.net. Using that password on the zip file yeilds part 5 of the flag: `m0r3_13337431}`

So we got the first and last flag first...guess that means we are pretty elite....or that we are really bad at finding basic things. 

On another note, I see a lot of chrome processes and activity in the processes list but when i do the `chromehistory` plugin, there are no results. It looks to be broken, (Did I know that it was broken for the 2 hrs that I spent trying to find artifacts from chrome? I certainly did not!) so after a gracious DFIRLABS admin clued me in that it should return stuff, I copied the chromehistory.py file [here](https://github.com/superponible/volatility-plugins/blob/master/chromehistory.py)and pasted it over the code in the plugins/community directory and now it works and shows me the chrome history.

First lines shows this:
```text
20 https://www.google.com/search?q=flag3+%...l2.321545j0j7&sourceid=chrome&ie=UTF-8 flag3 = aDBwM190aDE1Xw== - Google Search                                              2     0 2024-08-06 18:32:53.359953        N/A 
```

Another flag I see, base 64 decode it and shall be: `h0p3_th15_`

Ok so now we got 1,3,5. only 2 to go. And by 2 i mean two as in flag2 and flag4. The whole flag so far is:

`bi0sctf{w3lc0m3_{FLAG2}h0p3_th15_{FLAG4}m0r3_13337431}

Lets try seeing what the paint and notepad processes were up to
From `pslist`, i got the following:
```text
0xfffffa8003c9c4f0 notepad.exe            2592 
0xfffffa80039c2490 mspaint.exe            2516  
```
lets try dumping those processes
`volatility -f test.raw --profile=Win7SP1x86_23418 memdump --dump-dir=./ -p 2592


running `strings` on the notepad data, i was able to find flag 4, LOL is that flag3 so if I was smart I could have found both.....great......
```bash
$ sudo strings -e l /mnt/windowsmount/2592.data | grep "flag"
windows_tracing_flags=3
windows_tracing_flags=3
flag4 = YjNuM2YxNzVfeTB1Xw==
flag3 = aDBwM190aDE1Xw== - Google Search - Google Chrome
\Registry\Machine\Software\Microsoft\Windows nt\currentversion\appcompatflags\AIT
Allow flag to be passed with CreateFile call that indicates to perform downgrade if applicable.
Repairing the flags for file record 0x%1.
<SNIP>
```
Is it cheeky to grep for flag? Maybe....but you get desperate when you have spent the last 2 hours searching the interwebs on how to parse a notepad file with volatility only to find out that you forgot the already quoted quote: "When in doubt, run strings" and could have found it much much earlier.

flag4 decodes to: `b3n3f175_y0u_`

Doing the same for mspaint doesnt yield any results for flag two. OR does it. Turns out you gotta be simp and use GIMP to have any success here. This involved a lot of fiddling or I did I mention that scrolling to the bottom of the image when changing the options helps a bunch. I had to do a lot of fiddling with this to find the correct layout. Micro adjustments will make your life a lot easier as you transform the image.  In the end, I used RGB 16 bit and tried a bunch of offsets and finally found some text at the bottom Once you have the image set in place, you can flip it 180 and horizontal to reveal an image of a base64 encoded value. 
`dDBfZGYxcl9sNGl1Xw==`
C
an you tell what is a capital i and wat is an L well you better start guessing and mixing and matching to find out! Ah I just love ambiguous fonts.

Finally decoding this last value and putting it in its place yields:

`bi0sctf{w3lc0m3_t0_df1r_l4iu_h0p3_th15_b3n3f175_y0u_m0r3_13337431}

## Reflections on Suffering
This challenge was very well written. It gives a broad introduction into Volatility and presents you with unique situations that require some volatility documentation digging to get the flags. When the challenge says Easy, it does not mean easy for anyone. It means easy for those already acquainted with volatility and memory forensics. This gave me a new appreciation for the tool and showed me just how much I had been missing. There is still so much that I don't know but hope to learn about the tool as I continue learning in DFIR. Thanks to [DFIRLABS](https://github.com/Azr43lKn1ght/DFIR-LABS/tree/main) for putting this challenge together! Next up is Trinity of Secrets