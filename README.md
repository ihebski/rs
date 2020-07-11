# RS

Getting reverse shells with your IP has never been easier.
How easy? ls easy!
It's a fast way to read the default tun0 ip address, get the full list of Reverse Shell payloads,and listen using netcat on a port to get a shell back.
Being used mainly for Hackthebox machines.

What did I changed?
- Migrate fork to python3.6+ and compact the output (Thanks to @t0nik0)
- Added multi choice based on https://github.com/0xprashant/Reverse-shell-Generator- 
- Added more payloads

#### Todo:
Let me know if you need to add new features, error handling, payloads or other funny messages.

![screen_1](https://i.imgur.com/Cej2OI3.png)

# How to use:

## Setup listening port only (the tool will read the VPN address on tun0 interface )
### It's a must to install rlwrap for readline support. You'll thank me for that ;)

```sh
python3 rs.py 1234
```

## IP & Port
```sh
python3 rs.py 127.0.0.1 1234
```

# Advanced usage:
Follow the instructions bellow and get ready for some 0wn4g3

```sh
nano /bin/rs
```
```sh
#!/bin/bash
python3 /home/tools/rs/rs.py $1 $2
```

```sh
chmod +x /bin/rs
```

And finally:
```sh
rs 1234
```

Or
```sh
rs 127.0.0.1 1234
```


