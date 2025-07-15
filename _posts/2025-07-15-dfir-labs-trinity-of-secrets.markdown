---
layout: post
title:  "DFIRLABS: Trinity of Secrets"
date:   2025-07-15 15:36:34 -0400
tags: dfir ctf-dfirlabs
author: Benshkies
---

Unzipping the file shows another raw file, so lets search for a profile in volatility
```text
$ vol.py -f DFIRLABS.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win10x64_19041
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/sansforensics/DFIRLABS.raw)
                      PAE type : No PAE
                           DTB : 0x1aa000L
                          KDBG : 0xf80681a00b20L
          Number of Processors : 4
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff8067dee2000L
                KPCR for CPU 1 : 0xffffa2814c5a0000L
                KPCR for CPU 2 : 0xffffa2814bfa1000L
                KPCR for CPU 3 : 0xffffa2814c30e000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2024-05-22 16:22:06 UTC+0000
     Image local date and time : 2024-05-22 21:52:06 +0530
```
Looks like our image profile will be `Win10x64_19041`

Since its windows 10 its possible volatility 3 will be better but since im already in vol2 ill see if i can grab some things. From cmdlist:
```text
Code.exe pid:   6252
Command line : "C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe" 
************************************************************************
Discord.exe pid:   7672
Command line : "C:\Users\User\AppData\Local\Discord\app-1.0.9147\Discord.exe" 
************************************************************************
OneDrive.exe pid:   7384
Command line : "C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
```

VSCode is a possible place for looking. Possible malware or other files
Discord is another one that we could probably extract some text maybe?
OneDrive could just be used from a start up process but worth verifying

Since VSCode was used quite a bit, there are possibly files that we can uncover so lets use filescan.

There wasnt a lot in there for me to see for now at least. Might come back to it to see if there was anything else.

Another avenue for discovering potential files is malfind. Running that module shows me MsMpEng.exe multiple times so lets do some research to see if this is a normal program. According to google, "MsMpEng.exe is the **Antimalware Service Executable, a core component of Windows Defender**" So if this is getting activated its possible there could be a malicious file somewhere. The rest of the mentions in the malfind output arent too interesting at least to my knowledge. 

The part of the riddle says it lies in your code. But I cant find anything related to VsCode or any files that relate to that. So i think i missed something in filescan so lets go back there and start grepping.

Grepping for "Code" I see git.log which could be helpful.
```text
0x0000cb0f5ef608b0  32761      1 -W-rw- \Device\HarddiskVolume1\Users\User\AppData\Roaming\Code\logs\20240522T215144\window1\exthost\vscode.git\Git.log
```
Also possibly interesting is this workspace state file
```text
0x0000cb0f58c54af0  32674      1 RW-rw- \Device\HarddiskVolume1\Users\User\AppData\Roaming\Code\User\workspaceStorage\1716390920783\state.vscdb
```
So lets dump those and see what we are working with:

For some reason they werent dumping with Vol2 but they do with vol3. After all that work there was nothing really to report from either of these.

With some guidance from the Admins, I was pointed to look for VSCode Backups. Doing some research on where these might be found, I found articles that said the backups or Hot Exits are  usually found in `\Users\<User>\AppData\Roaming\Code\Backups` and sure enough that path was in the `filescan` output. Dumping the virtual address:
```powershell
vol3 -f .\trinity.raw -o .\ dumpfiles --virtaddr 0xcb0f58c6b890
```
Printing the files content to the screen shows:
```text
untitled:Untitled-1 {"typeId":""}
untitled:Untitled-2 {"typeId":""}
Function Decrypt(message, password)
    Dim key
    Dim i
    Dim encrypted_message
    Dim char

    key = Hash(password)

    For i = 1 To 10
        encrypted_message = ""
        For j = 1 To Len(message)
            char = Mid(message, j, 1)
            encrypted_message = encrypted_message & Chr(Asc(char) Xor Asc(Mid(key, (i - 1) Mod Len(key) + 1, 1)))
        Next
        message = encrypted_message
    Next

    Encrypt = encrypted_message
End Function

Function Hash(text)
    Dim sha256
    Dim bytes
    Dim i

    Set sha256 = CreateObject("System.Security.Cryptography.SHA256Managed")
    bytes = sha256.ComputeHash_2((StrConv(text, vbFromUnicode)))

    Hash = ""
    For i = 1 To LenB(bytes)
        Hash = Hash & Right("0" & Hex(AscB(MidB(bytes, i, 1))), 2)
    Next
End Function

Dim password, ciphertext, decrypted
password = " "
ciphertext = " "
decrypted = Decrypt(ciphertext, password)
WScript.Echo "Decrypted:", decrypted


"""
Deep within the gamer's lore
Is a secret waiting to be unlocked

Find the file that holds the cached key
Maybe what you are looking for is data_3
It might hold the images that you seek

Conversations notified but left unseen.
And within the quiet pings, where alerts softly chime,
Another piece awaits, revealing the r1ddl3r's crime.
""" 
```

Looks to be a VBS file. I changed the files name to keep track of it but we may need to use this later on to decrypt a flag.

`The gamers lore`, not sure about that, possibly a discord hint?
`A cached key related to data_3`, I remember some files had some of that appended to the end
The last part seems to hint at discord again.

Lol funny enough when i looked back at my screen from the filescan I saw `Users\User\AppData\Roaming\Code\Cache\Cache_Data\data_3` so lets dump that. Also of note is some discord data that has that so we will dump that as well
```text
0xcb0f58c70520  \Users\User\AppData\Roaming\Code\Cache\Cache_Data\data_3
0xcb0f58c70b60  \Users\User\AppData\Roaming\Code\Cache\Cache_Data\data_3
0xcb0f5f437d40  \Users\User\AppData\Roaming\discord\Cache\Cache_Data\data_3
0xcb0f5f438510  \Users\User\AppData\Roaming\discord\Cache\Cache_Data\data_3
```

Errors on the dumping the files. but i think it got some stuff. the clue says they might be images so im going to try and open them up in gimp to see whats there. Im not really finding anything with GIMP. lots of just garbled images not really images at all to be honest. Maybe Im missing something. I did a blanket search for data_3 and think that There may be some other data I can get from the GPUCache or the DawnCache. Do i know what those do? Nope. But they could be a lead.
```text
0xcb0f58c630a0  \Users\User\AppData\Roaming\Code\GPUCache\data_3
0xcb0f58c63550  \Users\User\AppData\Roaming\Code\GPUCache\data_3
0xcb0f58c657b0  \Users\User\AppData\Roaming\Code\DawnCache\data_3
0xcb0f58c66110  \Users\User\AppData\Roaming\Code\DawnCache\data_3
0xcb0f5f42b860  \Users\User\AppData\Roaming\discord\DawnCache\data_3
0xcb0f5f42bb80  \Users\User\AppData\Roaming\discord\DawnCache\data_3
0xcb0f5f42bd10  \Users\User\AppData\Roaming\discord\GPUCache\data_3
0xcb0f5f42bea0  \Users\User\AppData\Roaming\discord\DawnCache\data_2
0xcb0f5f42c4e0  \Users\User\AppData\Roaming\discord\GPUCache\data_3

```

Hmmm even less data for the GPUCache and DawnCache. Screw that...

After creating my own forensic machines and getting the updated tools this was a lot easier to process. 

Using binwalk on the data_3 files, i extracted SSL certs from the code source. Maybe that will come about later. The Discord one had a TIFF image and PNG image. The TIFF image I couldnt open possibly corrupted? Or maybe its the one that is encrypted. Not sure but will come back to it.

Extracting the png image yields this image:
![[Pasted image 20250614200956.png]]
I pasted a screengrab of this into google image search and they are semaphore flag signals apparently so I looked into them. Using the schematic here: https://upload.wikimedia.org/wikipedia/commons/0/0a/Semaphore_Signals_A-Z.jpg we get the message:
`JCNNQ`
Hmmm no signal for the next letter but there is one for the reverse of the signal? maybe ill flip the images?
`PENNYWORTH` 
Ahh yes that seems more likely. From my batman knowledge pennyworth is the last name of Batmans butler Alfred.

So now where? lets look at the clue again:
```text
"""
Deep within the gamer's lore
Is a secret waiting to be unlocked

Find the file that holds the cached key
Maybe what you are looking for is data_3
It might hold the images that you seek

Conversations notified but left unseen.
And within the quiet pings, where alerts softly chime,
Another piece awaits, revealing the r1ddl3r's crime.
""" 
```
Ok first 2 sentences are just lead in I think, The file with the cached key, so the vscode file had a bunch of keys so I think i got that? the second it says images, plural? so maybe the TIFF file needs to be looked at again.

So yeah lots of binwalking these files. binwalking the PNG shows another tiff file. The tiff is actually supposed to be a WEBP possibly? not sure but looking at the file in XXD I see this encoded string. Its about discord and mentions a url 

```hex
00005210: 0000 3010 0000 036d 470a 1352 a09c a377  ..0....mG..R...w
00005220: 2f00 b12b a69c a377 2f00 2e03 0000 4854  /..+...w/.....HT
00005230: 5450 2f31 2e31 2032 3030 0064 6174 653a  TP/1.1 200.date:
00005240: 5765 642c 2032 3220 4d61 7920 3230 3234  Wed, 22 May 2024
00005250: 2031 363a 3231 3a33 3920 474d 5400 636f   16:21:39 GMT.co
00005260: 6e74 656e 742d 7479 7065 3a69 6d61 6765  ntent-type:image
00005270: 2f77 6562 7000 636f 6e74 656e 742d 6c65  /webp.content-le
00005280: 6e67 7468 3a35 3734 3200 6366 2d72 6179  ngth:5742.cf-ray
00005290: 3a38 3837 6532 3366 3461 6533 6638 3030  :887e23f4ae3f800
000052a0: 342d 4d41 4100 6366 2d63 6163 6865 2d73  4-MAA.cf-cache-s
000052b0: 7461 7475 733a 4d49 5353 0061 6363 6570  tatus:MISS.accep
000052c0: 742d 7261 6e67 6573 3a62 7974 6573 2c20  t-ranges:bytes, 
000052d0: 6279 7465 7300 6163 6365 7373 2d63 6f6e  bytes.access-con
000052e0: 7472 6f6c 2d61 6c6c 6f77 2d6f 7269 6769  trol-allow-origi
000052f0: 6e3a 2a00 6361 6368 652d 636f 6e74 726f  n:*.cache-contro
00005300: 6c3a 7075 626c 6963 2c20 6d61 782d 6167  l:public, max-ag
00005310: 653d 3331 3533 3630 3030 0065 7870 6972  e=31536000.expir
00005320: 6573 3a54 6875 2c20 3232 204d 6179 2032  es:Thu, 22 May 2
00005330: 3032 3520 3136 3a32 313a 3339 2047 4d54  025 16:21:39 GMT
00005340: 006c 6173 742d 6d6f 6469 6669 6564 3a57  .last-modified:W
00005350: 6564 2c20 3232 204d 6179 2032 3032 3420  ed, 22 May 2024 
00005360: 3136 3a32 313a 3338 2047 4d54 0076 6172  16:21:38 GMT.var
00005370: 793a 4163 6365 7074 2d45 6e63 6f64 696e  y:Accept-Encodin
00005380: 6700 782d 6469 7363 6f72 642d 7472 616e  g.x-discord-tran
00005390: 7366 6f72 6d2d 6475 7261 7469 6f6e 3a31  sform-duration:1
000053a0: 3500 7265 706f 7274 2d74 6f3a 7b22 656e  5.report-to:{"en
000053b0: 6470 6f69 6e74 7322 3a5b 7b22 7572 6c22  dpoints":[{"url"
000053c0: 3a22 6874 7470 733a 5c2f 5c2f 612e 6e65  :"https:\/\/a.ne
000053d0: 6c2e 636c 6f75 6466 6c61 7265 2e63 6f6d  l.cloudflare.com
000053e0: 5c2f 7265 706f 7274 5c2f 7634 3f73 3d53  \/report\/v4?s=S
000053f0: 425a 6153 4b73 2532 4644 367a 3061 7154  BZaSKs%2FD6z0aqT
00005400: 305a 4c65 5768 7966 4b6d 6f37 6d43 7a69  0ZLeWhyfKmo7mCzi
00005410: 5443 7659 6c7a 4965 6d45 6b6b 4b61 496f  TCvYlzIemEkkKaIo
00005420: 4a38 6148 4b79 344c 4641 3255 6a69 6264  J8aHKy4LFA2Ujibd
00005430: 7874 7749 5746 6c59 2532 4241 466c 7267  xtwIWFlY%2BAFlrg
00005440: 7241 5673 734d 7070 5267 6645 7043 6547  rAVssMppRgfEpCeG
00005450: 4831 517a 4b59 6e62 6561 6135 4833 2532  H1QzKYnbeaa5H3%2
00005460: 4254 4f55 646f 6563 7130 4a62 544b 615a  BTOUdoecq0JbTKaZ
00005470: 7a68 696e 4c59 6245 756d 6f53 5622 7d5d  zhinLYbEumoSV"}]
00005480: 2c22 6772 6f75 7022 3a22 6366 2d6e 656c  ,"group":"cf-nel
00005490: 222c 226d 6178 5f61 6765 223a 3630 3438  ","max_age":6048
000054a0: 3030 7d00 6e65 6c3a 7b22 7375 6363 6573  00}.nel:{"succes
000054b0: 735f 6672 6163 7469 6f6e 223a 302c 2272  s_fraction":0,"r
000054c0: 6570 6f72 745f 746f 223a 2263 662d 6e65  eport_to":"cf-ne
000054d0: 6c22 2c22 6d61 785f 6167 6522 3a36 3034  l","max_age":604
000054e0: 3830 307d 0078 2d72 6f62 6f74 732d 7461  800}.x-robots-ta
000054f0: 673a 6e6f 696e 6465 782c 206e 6f66 6f6c  g:noindex, nofol
00005500: 6c6f 772c 206e 6f61 7263 6869 7665 2c20  low, noarchive, 
00005510: 6e6f 6361 6368 652c 206e 6f69 6d61 6765  nocache, noimage
00005520: 696e 6465 782c 206e 6f6f 6470 0073 6572  index, noodp.ser
00005530: 7665 723a 636c 6f75 6466 6c61 7265 0061  ver:cloudflare.a
00005540: 6c74 2d73 7663 3a68 333d 223a 3434 3322  lt-svc:h3=":443"
00005550: 3b20 6d61 3d38 3634 3030 0000 0000 0300  ; ma=86400......

```
 {"url":"https:\/\/a.nel.cloudflare.com\/report\/v4s=SBZaSKs%2FD6z0aqT0ZLeWhyfKmo7mCziTCvYlzIemEkkKaIoJ8aHKy4LFA2UjibdxtwIWFlY%2BAFlrgrAVssMppRgfEpCeGH1QzKYnbeaa5H3%2BTOUdoecq0JbTKaZzhinLYbEumoSV
 
Looks base encoded with some url encoding as well. Possibly a discord token since it looks like an API request. I tried navigating there but nothing to report. 

So the hint talks about notifications unseen so I think there is some way to find discord messages?

Online i found some reference to cache data again so I'm going to try that:
```text
0xcb0f5f439c80	\Users\User\AppData\Roaming\discord\Cache\Cache_Data\data_0
0xcb0f5f439e10	\Users\User\AppData\Roaming\discord\Cache\Cache_Data\data_1
0xcb0f5f43a130	\Users\User\AppData\Roaming\discord\Cache\Cache_Data\data_2
```
So i found some images in data_2 but they are all just discord asset images. 
data_1 had a gzip compressed file and uncompressing it shows a list of regions and ips:
```text
[{"region":"india","ips":["35.207.240.251","66.22.239.5","35.207.210.191","35.207.211.253","35.207.224.151"]},{"region":"dubai","ips":["66.22.242.8","66.22.242.133","66.22.242.137","66.22.242.6","66.22.242.10"]},{"region":"singapore","ips":["66.22.220.14","35.213.168.191","35.213.165.33","35.213.167.165","35.213.145.149"]},{"region":"hongkong","ips":["35.215.190.51","35.215.161.122","35.215.128.17","35.215.172.57","35.215.149.186"]},{"region":"tel-aviv","ips":["34.0.64.32","34.0.64.225","34.0.64.50","34.0.65.227","34.0.65.31"]}]
```
I doubt this is significant and could possibly be related to some type of CDN type stuff but the locations are pretty suspicious to say the least.

So I was kind of in a stump so I asked for a hint. I knew it had to do with notifications. So i grepped filescan for notifi to see what was there:
```text
vol3 -f trinity.raw windows.filescan | grep notifi
0xcb0f5de9a540.0\Users\User\AppData\Local\Discord\app-1.0.9147\modules\discord_utils-1\discord_utils\node_modules\macos-notification-state\build\Release\notificationstate.node
0xcb0f5e1aad90	\Windows\System32\notificationplatformcomponent.dll
0xcb0f5f0042b0	\Users\User\AppData\Local\Discord\app-1.0.9147\modules\discord_utils-1\discord_utils\node_modules\windows-notification-state\build\Release\notificationstate.node
0xcb0f5f43bbc0	\Users\User\AppData\Local\Discord\app-1.0.9147\modules\discord_utils-1\discord_utils\node_modules\macos-notification-state\package.json
0xcb0f5f43f8b0	\Users\User\AppData\Local\Discord\app-1.0.9147\modules\discord_utils-1\discord_utils\node_modules\macos-notification-state\lib\index.js
0xcb0f5f43fef0	\Users\User\AppData\Local\Discord\app-1.0.9147\modules\discord_utils-1\discord_utils\node_modules\windows-notification-state\package.json
0xcb0f5f441660	\Users\User\AppData\Local\Discord\app-1.0.9147\modules\discord_utils-1\discord_utils\node_modules\windows-notification-state\lib\index.js
```
It came back with this which i dont know if its helpful but worth a look

Looking for notifications in general, discord and other programs occassionally have notifications storedin the NTUSER.dat registry so diving into that registry i see under SOFTWARE/Microsoft/Windows/Current Version/Notifications/ some interesting keys that could lead to some clues. Nope. Not even. Close. 

After struggling on this for a bit, I reached out to an admin to get some hints on where else I could look. Apparently there is a db called wpndatabase.db that you can dump and analyze so I did windows.filescan and greped for that db and found the virtual address and dumped the file. Now to analyze it. Using SQLITE DB Browser and navigating the Notification table, I found an encrypted string: `Y2lwaGVydGV4dCA9ICI6MD07J1x4MTFoLyhvLlx4MGJoJTJvXHgwM1x4MGI0M1x4MTUvXHgwODQ5XHgwOC4pb1x4MTFoLyhvLjFtMjhceDAzXHgwZW04ODBvXHgxMW9ceDA4NGgoISIK`

So lets use the password PENNYWORTH and the this cipher text and use the vb script to decrypt it. It doesnt really look like an encrypted string. Lets see if its base64 encoded...Yep! It decodes to: 
`ciphertext = ":0=;'\x11h/(o.\x0bh%2o\x03\x0b43\x15/\x0849\x08.)o\x11h/(o.1m28\x03\x0em880o\x11o\x084h(!"`
So our cipher text is actually `:0=;'\x11h/(o.\x0bh%2o\x03\x0b43\x15/\x0849\x08.)o\x11h/(o.1m28\x03\x0em880o\x11o\x084h(!`

The VBS script does not really work as its missing some components so lets convert it to python for some easier decrypting. I used Claude AI to look at the vbs code and generate this script. Basically though, the vbs script does some XOR encryption 10x. So the following is the script that I used to decipher the string:
```python
import hashlib

def decrypt(message, password):
    key = hash_password(password)
    for i in range(1, 11):
        encrypted_message = ""
        for j in range(len(message)):
            char = message[j]
            key_char = key[(i - 1) % len(key)]
            decrypted_char = chr(ord(char) ^ ord(key_char))
            encrypted_message += decrypted_char
        message = encrypted_message
    return encrypted_message

def hash_password(text):
    sha256_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()
    return sha256_hash

if __name__ == "__main__":
    password = "PENNYWORTH"
    ciphertext = ":0=;'\x11h/(o.\x0bh%2o\x03\x0b43\x15/\x0849\x08.)o\x11h/(o.1m28\x03\x0em880o\x11o\x084h(!"
    decrypted = decrypt(ciphertext, password)
    print(f"Decrypted: {decrypted}")
```

Running the script we get:
Decrypted: `flag{M4st3rW4yn3_WhoIsTheTru3M4st3rm1nd_R1ddl3M3Th4t}`