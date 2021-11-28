# MrSign
MrSign is an application used for generate and verify a signature by of the contents of a directory . This is application is based on client/server architecture and It is developed in Go language. This is a POC version and we are using it in combination with [FIT](https://github.com/zitelog/fit).

The mechanism to calculate the signature is created and delevoped by **Marcello Russo @markel1974**. It uses the message authentication method provided in the [HMAC protocol with MD5](https://it.wikipedia.org/wiki/HMAC), obtained from the union of a series of variables. This signature is generated and stored on a server together with other elements, such as: SID (Signature ID),  server (timestamp), client username, etc.  

**The following flow explain it better.**


![alt text](https://github.com/zitelog/mrsign/blob/main/mrsign-signature-flow-en.png?raw=true)

## Prerequisites
Make sure you have installed all of the following prerequisites on your development machine:
* [Download & Install Golang compiler](https://go.dev/dl/).

### Cloning the github repository
The recommended way to get FIT is to use git to directly clone the FIT repository:

```
git clone git@github.com:zitelog/mrsign.git mrsign
```

This will clone the latest version of the FIT repository to a **mrsign** folder.

## Compile
Once you've downloaded MrSign and installed all the prerequisites:

* go in mrsign folder:
```
cd mrsign
```
* compile it:
```
go build
```

## Usage
$ ./mrsign.exe -h

arguments:
  -h, --help        show this help message and exit

  -c                (string) the config file path (default "config.json").

  -f                (string) client signature filename
  
  -g                (string) generate hash
  
  -k                generate key
  
  -l                (string) logfile path
        
  -p                (string) client path
        
  -r                (string) server url (default "http://127.0.0.1:8123")
 
  -s                start local server
  
  -sp               (string) server path
        
  -t                (string) client host
        
  -u                (string) client user

  -v                show version
  
  ### Example
First run MrSign as a local server:
```
./mrsign.exe -s
starting server 127.0.0.1:8123
FolderName:
```

```
./mrsign.exe -t hostname -u username -r server_url -p path_of_directory_that_you_make_a_signature -f signature.txt -sp server_db_of_signatures_path
```


