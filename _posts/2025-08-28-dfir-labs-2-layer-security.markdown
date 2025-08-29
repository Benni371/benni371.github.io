---
layout: post
title:  "DFIRLABS: 2-Layer Security"
date:   2025-08-28 20:15:25 -0400
tags: dfir ctf-dfirlabs
author: Benshkies
---

At the beginning of the challenge, you can quickly realize that we are dealing with a Linux filesystem. Looking through the folders to see if we have any suspicious files we see recycle.bin. For those with a Windows background this may look familiar but remember that we are in a Linux system. Linux does not have a recycle bin and handles recycling files very differently. So lets mark that as suspicious and see if there is anything else on the system. After searching the rest of the files and folders it doesnt look like there is much else to be had. 

## ZSH History
A key artifact in Linux forensics is the bash history. In this case it will actually be the zsh_history since they are using the zsh shell. Printing the history to the screen we can quickly tell that some sus things have been happening:
```bash
cd ~
cd Desktop
ls
clear
cd ../../../../../../../../
cd /var/log
cd ~
sudo apt install curl
curl https://pastebin.com/raw/awhuFZse -0 tienbip.txt
LESSCLOSE=/usr/bin/lesspipe %s %s
cd -
cd Desktop
ls
gpg --quick-gen-key Cocainit
gpg --quick-gen-key VNvodich
gpg --quick-gen-key Siuuuuuu
ls
gpg -er VNvodich RestrictedAccess.pdf
ls
rm -rf RestrictedAccess.pdf
cat /etc/shadow | grep idek{
cat /etc/shadow | grep "idek{"
mv RestrictedAccess.pdf.gpg $(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 5 | head -n 1)
pwsh
ls
mv T3C4U.SOS recycle.bin
reboot
```
The first few lines are whatever, but then we start curl-ing for a pastebin file. Very suspicious. As we go on, it looks like the user generates gpg keys and then encrypts the file `RestrictedAccess.pdf` using VNvodich's gpg key (1st layer in the 2-layer encryption). Afterwards the file is moved to a randomly generated folder name. After that they enter into powershell (`pwsh`) powershell on linux is not really normal but not unheard of. So fortunately we can look at those logs as well in `home\kalilinux\.local\share\powershell\PSReadLine\ConsoleHost_history.txt`

## Powershell History
Opening the ConsoleHost_history.txt file shows us the next steps this user did to encrypt the file:
```powershell
ls
whoami
( nEw-oBJECT syStem.io.sTrEamReadeR( ( nEw-oBJECT sysTeM.iO.COMPReSsioN.deflAtEsTREaM([sySTEM.iO.MeMoRyStreaM] [ConVert]::froMbaSe64striNg('hVXbbuJIEH2PlH/omZfYGrAwtxCkPASWXLTDgGL2Mot46MENeGLaqN3WLov873uqbQPGiRZhulz3OlXVBKM/mWVZnw/tRnpw79JDs5Me2l3QOF0XNJ4mydqge+mh1cJ5i5Me6DQhAkVakLjQwLcNAXy1yB9em2QLaYto2HVIk94Rpw0dF2eLYkDWBN2ENxeOwepQCumBEqI3eqALWQvcDs42niY9FA+vYN+mn+srdsPyT3p9dX1VvHyfjoVcqv1OR4rd0ysX8ZjLm9oNXwsfrG/i7/rkx0+x1Mzbx1psHU8sExXovTM0dmvFd1BnJeNDKUS84WCTQ+eXIN5FsbBsKEBPGaKSjPAHey3iLKNjgs5McRmvIrV9DCQPYZ7rlVxkOVSCXXxOnGDFLJhNud7Y7CxvSm8QRss3ku5CHkgTq8YaNVbiOF+FXMP4ohCYn0ID9JTK5bsNcAt2G6HGkS8W/f5wMLw2lThT7vuBXKPo+cdIwzzXy+3/gnEVsxMIEG+zHCyQ/f6r4P5DGBpdquwxCIXzmIThN74VF0BBHCWakMm8lnTZF/ZTThxv4uG4vqJyR5M3+/+xptlScKCF8oQ2ru7JlSmSQoC2FyejuacV6l3kTcoEdjHFA7EOJHtv3gze+BnjKecExvsAQ2AVoeeTRO8S4sCXzzF/+wwFrRJRY1Oa+VOrXiYOpb6gVpYRUEInSlKBpMCOE850VAAMI/+jGaY2mzgEcME0c+kF/wowtVk+9gfqEPWRUljk+ljEMRSPQWWk2SpKpP/J9OqyQT+U4G9ldlqZhNPAU8AsaJEttVRvSr7T4+AXnRpJn8zMOGWJPix1EEnmIUWpw/0wkjqQyQV+NDOfKoOKjsMXtuGhgCrL6LIf/b4B5oHQIz7Os+HPp7tWvXqOYwyDZqebA3/GfO/GyOAwiN+zJygVK+s9UwLNnlkToSJzY4FcJTKDYJQFJzJ3OB9u/VDoQSBp2aF7thDTYn/APi3mVx5rU+ws2GbD6R679N7FeL4WZ2KwZ/udsOZxtnbFPkxpl8oL88G/BNWo6y+Am9VNt7/ThDsvv+PKOAGdG8OT4FrkAETHjK2nwsepT3apRsE+Ku9XsaflQF5o3dkcmjJUtMR2XNwYZeNsz8/+tYbRdpdo8czjjVVM2Ez8ox2kHVF/MGe/zR57DpLOhgtX4eVM3di2o8Q05EthWfPlM39ddO++ZMRtQbiNW7s292avL/JpkbFadxU7t9Et9N3G0UXFsF0x7BVxekezaryuzez/AA==' ), [SyStem.IO.comPreSSION.cOmpreSSIONModE]::DEcOmPREsS ) ), [text.ENcodiNg]::AScII)).ReAdToend()|&( $sHeLLid[1]+$shELliD[13]+'x')
Encryption -Path ./T3C4U
Remove-Item -Path ./T3C4U -Force -Recurse
exit
```

Oof what the flip is that huge blob! Its definitely base64 encoded so lets decode it. Using the From Base64 and Raw Inflate recipe in CyberChef gives us:
```powershell
iEX ((("{40}{19}{25}{46}{15}{11}{41}{20}{14}{48}{33}{47}{37}{35}{2}{1}{31}{23}{18}{8}{45}{9}{39}{28}{24}{43}{38}{27}{53}{13}{36}{49}{16}{30}{17}{26}{21}{12}{0}{51}{4}{6}{10}{50}{5}{32}{34}{52}{42}{22}{29}{3}{44}{7}"-f '        }

        YPMencryptor = YPMaesMan','aged = New-Object System.Security.Cryptograp','  YPMaesMan','{
        YPMshaManaged.Dispose()
 ','r()
        YPMencryptedBytes = YPMencryptor.TransformFinal','edBytes
        YPMaesManaged.Dispose()
                
        if (YPMPath) {
         ','Block(YPMplainBytes, 0, YPMplainBytes.Length)
        YPMen','se()
    }
}','raphy.CipherMode]::CBC
','ed.Padding = [System.Security.Cryptography.PaddingMode]::Z','cryptedBytes = YPMaesManaged','m
    (','::ReadAllBytes(YPMFile.FullName)
            YPMoutPath = YPMFile.FullName + jnO.SOSjnO
','sEOk))
                
        if (Y','arameterSetName = jnOCryptFilejnO)]
        [String]YPMPath
    )

    Begin {
        YPMshaMan','ra','M','
             ','ystem.Security.Cryptog','()]
    [Outpu','(Mandatory = YPMtrue, P',' = [System.IO.File]','e
            return jnOFile encrypted to YPMoutP','d
        YPMaesManaged.Mode = [S','sManaged.BlockSize','t','   Write-Error -Message jnOFile not found!jnO
                break
            }
            YPMplainBytes',' ','      YPMae','athjnO
        }
    }


    End ','Path -ErrorAction SilentlyContinue
            if (!YPMFile.FullName) {
','hy.AesManage','   [System.IO.File]::WriteA','stem.','llBytes(YPMoutPath, YPMencryptedBytes)
      ','256Managed
      ','PMPath) {
            YPMFile = G','ography.SHA','28
','eros
  ','function Encryption {
    [CmdletBinding','
        [Parameter','= YPMFile.LastWriteTim',' = 1','       YPMaesManaged.Dispo','
        YPMaesManag','Type([string])]
    Pa','Security.Crypt','aged = New-Object Sy','et-Item -Path YP','.IV + YPMencrypt','aged.CreateEncrypto','      (Get-Item YPMoutPath).LastWriteTime ','       YPMaesManaged.KeySize = 256
    }

    Process {
        YPMaesManaged.Key = YPMshaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(EOkYPMencryptedByte')).rePlace(([cHaR]69+[cHaR]79+[cHaR]107),[STRInG][cHaR]39).rePlace(([cHaR]106+[cHaR]110+[cHaR]79),[STRInG][cHaR]34).rePlace(([cHaR]89+[cHaR]80+[cHaR]77),[STRInG][cHaR]36) )
```
Not much better. Lets see if ChatGPT can help. After a few failed prompts and some guidance chat helped us put this all back together:
```powershell
function Encryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC

        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes('$encryptedBytes'))

        if ($Path) {
            $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
            if (!$File.FullName) {

                Write-Error -Message "File not found!"
                break
            }
            $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
            $outPath = $File.FullName + ".SOS."
        }

        $encryptor = $aesManaged.CreateEncryptor()
        $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        $encryptedBytes = $aesManaged.IV + $encryptedBytes
        $aesManaged.Dispose()

        if ($Path) {
            [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
            (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
            return "File encrypted to $outPath"
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
```
So its an custom encryption algorithm. Although, ChatGPT says its kind of janky because in the laine where it sets the key the variable `$encryptedBytes` has not been set yet. In powershell this would be treated as an empty value, meaning that the key is actually just an empty string. LOL so now that we know the key, lets reverse the encryption. I had ChatGPT write me a function to do this:
```powershell
function Decryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "DecryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }
    
    Process {
        # Generate the same key as the encryption function (uses literal '$encryptedBytes' string)
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes('$encryptedBytes'))
        
        if ($Path) {
            $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
            if (!$File.FullName) {
                Write-Error -Message "File not found!"
                break
            }
            
            # Read the encrypted file
            $encryptedBytes = [System.IO.File]::ReadAllBytes($File.FullName)
            
            # Extract IV (first 16 bytes) and encrypted data (remaining bytes)
            $iv = $encryptedBytes[0..15]
            $encryptedData = $encryptedBytes[16..($encryptedBytes.Length - 1)]
            
            # Set the IV
            $aesManaged.IV = $iv
            
            # Create output path (remove .SOS. extension)
            $outPath = $File.FullName -replace '\.SOS\.$', ''
            
            # If the file doesn't end with .SOS., just add .decrypted
            if ($outPath -eq $File.FullName) {
                $outPath = $File.FullName + ".decrypted"
            }
        }
        
        # Decrypt the data
        $decryptor = $aesManaged.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
        
        # Remove zero padding (since we used PaddingMode.Zeros)
        # Find the last non-zero byte
        $lastNonZeroIndex = -1
        for ($i = $decryptedBytes.Length - 1; $i -ge 0; $i--) {
            if ($decryptedBytes[$i] -ne 0) {
                $lastNonZeroIndex = $i
                break
            }
        }
        
        # If we found non-zero bytes, trim to that point, otherwise keep original
        if ($lastNonZeroIndex -ge 0) {
            $trimmedBytes = $decryptedBytes[0..$lastNonZeroIndex]
        } else {
            $trimmedBytes = $decryptedBytes
        }
        
        $aesManaged.Dispose()

        if ($Path) {
            [System.IO.File]::WriteAllBytes($outPath, $trimmedBytes)
            (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
            return "File decrypted to $outPath"
        }
    }

    End {
        $shaManaged.Dispose()
        if ($aesManaged) {
            $aesManaged.Dispose()
        }
    }
}
```
Ok so with this function, lets try and decrypt this last layer of encryption. 
```powershell
# <paste code into powershell>
Decyrption -Path \Evidence\recycle.bin
```
So we really wont know that its decrypted this 1st layer until we try to decrypt the next layer.

## GPG Decryption
Usually GPG decyption is pretty simple if you have access to the system and user account (and password if one was set for the key) but here with an offline copy its a little more janky. We know that the .gnupg folder is in the `/home/kalilinux` folder and `gpg` will let you specify a home directory if needed. So when I tried to do that, it gave me a bunch of errors and didnt like it. So instead I did this:
```bash
mkdir ~/gnupg-temp
cp -r /home/kalilinux/.gnupg/* ~/gnupg-temp/
chmod 700 ~/gnupg-temp
gpg --homedir ~/gnupg-temp --output decrypted_file.pdf --decrypt /Evidence/recycle.bin.decrypted
```
You should see some output similar to this:
![2-layer](\assets\images\2-layer-screenshot.png)
Afterwards you can open the file and the flag is right there in the photo
FLAG: `idek{Cr34t1n9_ch4ll3ngEs_6_d4ys_6_n1gts_w1th0ut_sl33p}`

This challenge was really cool, I havent ever messed with gpg keys so it was a fun way to learn how to manipulate them to reverse the encryption.