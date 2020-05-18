# RS
This simple tool is made for Lazy people who are lazy to visit pentestmonkey blog x)))
#### UPDATE: migrate fork to python3.6+ and compact the output
#### UPDATE 2: Added multi choice based on https://github.com/0xprashant/Reverse-shell-Generator- 

![screen_1](https://i.imgur.com/Cej2OI3.png)

# Why RS 
Fast way to read the default tun0 ip adress ,get the full list of the possible reverse shells ,and open an nc port to get ur pwned system shell ^-^ ,I use it for Hackthebox machines .

# Usage:

## Setup listening port only (the tool will read the VPN address on tun0 interface )


```sh
python rs.py 1234
```

## IP & Port
```sh
python rs.py 127.0.0.1 1234
```

# Advanced usage:
Well nothing is advanced you can simply add it as a bash command to look like "ls"    xD

```sh
nano /bin/rs
```
```sh
#!/bin/bash
python /home/tools/rs/rs.py $1 $2
```

```sh
chmod +x /bin/rs
```
Finally:
```sh
rs 1234
```
or
```sh
rs 127.0.0.1 1234
```


