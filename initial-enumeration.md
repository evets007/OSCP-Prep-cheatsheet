# Scanning 

### NMAP TCP quick 
````
> sudo nmap -Pn -v -sS -sV -sC -oN tcp-quick.nmap IP
````
### NMAP TCP Full 
````
> sudo nmap -Pn -sS --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p1-65535 -oN tcp-full.nmap -sV IP 
````
### NMAP TCP - Repeat if extra ports found 
````
> sudo nmap -Pn -v -sS -A -oN tcp-extra.nmap -p PORTS IP 
````
### NMAP UDP quick 
````
> sudo nmap -Pn -v -sU -sV --top-ports=30 -oN udp-quick.nmap IP
````
### NMAP UDP 1000 
````

> sudo nmap -Pn --top-ports 1000 -sU --stats-every 3m --max-retries 1 -T4 -oN udp-1000.nmap IP
````

### NMAP UDP - Repeat if extra ports found 
````

> sudo nmap -Pn -sU -A -oN udp-extra.nmap -p PORTS IP 
````

# Enumeration 

### FTP - Port 21 
````
Check for FTP version vulns
Check for Anonymous login 
Check for Read access
Check for Web root or root directories of any other accessible service 
Check for write access 
````

### SSH - Port 22 
````
Check for SSH version vulns
Check for User enumeration if necessary 
Check if host key was seen somewhere else 
Check if it prompts for a password - means password login is allowed for some users
nmap -sV --script=ssh-hostkey -p22 IP
Bruteforce if necessary with CeWL, Hydra, Patator, Crowbar, MSF (if port gets filtered, there's defense mechanisms - fail2ban) 
````

### Telnet - Port 23
Connect and check for service running

### SMTP - Port 25
Check for SMTP vulns 
Check version with HELO / HELLO <domain>  

### POP - PORT 110 
````
Connect using telnet 
user <username> 
pass <pass> 
LIST - to list emails 
RETR <email numbr> - To retrieve emails 
````


### DNS - Port 53 
````
Might indicate a domain controller on Windows 
Check for zone transfer - 
````

### Kerberos - Port 88 
Indication that its a DC 

### Netbios - Port 139
````
> nmblookup -A IP
> nbtscan IP 
> On older hosts, this port servers SMB / SAMBA, scan by adding 'client min protocol = LANMAN1' to GLOBAL setting in /etc/samba/smb.conf or by using --option='client min protocol'=LANMAN1 with smbclient
````

### RPC - PORT 135 
````
> sudo nmap -sS -Pn -sV --script=rpcinfo.nse -p135 0 
> rpcinfo IP
> rpcclient -U "" -N [ip]
````

### LDAP - Ports 389,636,3268,326
````
> sudo nmap -sS -Pn -sV --script=ldap* -p389,636,3268,3269  
````
### WEB - PORT 80 / 443 

NMAP Web 
````
> sudo nmap -Pn -sC -p80,443 

````
Checks 
````
Browse the webapp 
Check for usernames, keywords 
Check Web server vulns
Check for Cgi's shellshock
Check Certificates for hostname
Check robots.txt
Check sitemap.xml
Check for known software - View source 
Check for default credentials 
Check for input validation - SQLi
Check for OS Command execution
Check for LFI / RFI 
````
Dirb 
````
> dirb IP
> dirb with -X extensions based on web technology, .php,.asp,.txt,.jsp
> dirb IP -a  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
````
Gobuster 
````
> gobuster dir --url IP --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt
> gobuster dir --url IP --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt -k -a 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
````
Nikto 
````
> nikto -host IP
````


### SMB - Ports 
NMAP vuln scripts
````
> sudo nmap -Pn --script=smb-proto* -p139,445 
> sudo nmap -Pn --script=smb-os-discovery.nse -p139,445
> sudo nmap -Pn --script=smb-enum* -p139,445
> sudo nmap -Pn --script=smb-vuln* -p139,445
> nmap -p 445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 
````

Check for Null logins 
````
> nmap --script smb-enum-shares -p 139,445 
> smbclient -L \\\\ip\\ -N 
> smbclient -m=SMB2 -L \\\\Hostname\\ -N
````

Connect to a share with Null session 
````
> smbclient \\\\IP\\$Admin -N 
> smbmap -H IP
> smbmap -u DoesNotExists -H IP
> enum4linux -a IP
````

Check permissions on a connect share
````
> smb: \> showacls # enable acl listing
> smb: \> dir # list directories with acls
````

Mount share on local machine 
````
> sudo mount -t cifs //10.10.10.134/SHARENAME ~/path/to/mount_directory
````

List share with credentials 
````
> smbmap -u USERNAME -p PASSWORD -d DOMAIN.TLD -H <TARGET-IP>
````

Recursively list all files in share
````
> smbmap -R -H <TARGET-IP>
> smbmap -R Replication -H <TARGET-IP>
````
With smbclient (recurse downloads all files)
````
> smbclient //<TARGET-IP>/Replication
> smb: \> recurse ON
> smb: \> prompt OFF
> smb: \> mget *
````

Upload / Download specific files 
````
> smbmap -H <TARGET-IP> --download 'Replication\active.htb\ 
> smbmap -H <TARGET-IP> --upload test.txt SHARENAME/test.txt 
````
### NFS - Port 2049 
````
> showmount -e IP 
> mount -t nfs -o vers=3 10.1.1.1:/home/ ~/home
> mount -t nfs4 -o proto=tcp,port=2049 127.0.0.1:/srv/Share mountpoint
````

### TFTPD - UDP 69
````
> tftp client to connect
> atftp is a better client 
> Can be used to read system files, MSSQL password mdf file
````

### Finding exploits 
````
Search on EDB and searchsploit
Check each service on CVE details for RCE / LFI / RFI / SQLI issues 
Google search the with the service banner 
````







