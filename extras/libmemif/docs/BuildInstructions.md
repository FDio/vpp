## Build Instructions

Install dependencies
```
# sudo apt-get install -y git autoconf pkg_config libtool check
```

Clone repository to your local machine. 
```
# git clone https://github.com/JakubGrajciar/libmemif.git
```

From root directory execute:
For debug build:
```
# ./bootstrap
# ./configure
# make
# make install
```

For release build:
```
# ./bootstrap
# ./configure
# make release
# make install
```
Verify installation:
```
# ./.libs/icmpr-epoll
```
> Make sure to run the binary file from ./.libs. File ./icmp\_responder in libmemif root directory is script that links the library, so it only verifies successful build. Default install path is /usr/lib.
Use _help_ command to display build information and commands:
```
ICMP_Responder:add_epoll_fd:204: fd 0 added to epoll
MEMIF_DEBUG:src/main.c:memif_init:383: app name: ICMP_Responder
ICMP_Responder:add_epoll_fd:204: fd 4 added to epoll
LIBMEMIF EXAMPLE APP: ICMP_Responder (debug)
==============================
libmemif version: 1.0 (debug)
memif version: 256
commands:
	help - prints this help
	exit - exit app
	conn <index> - create memif (slave-mode)
	del  <index> - delete memif
	show - show connection details
	ip-set <index> <ip-addr> - set interface ip address
	rx-mode <index> <qid> <polling|interrupt> - set queue rx mode
```
#### Examples

Once the library is build/installed, refer to [Examples](../examples/README.md) and [Getting started](GettingStarted.md) for additional information on basic use cases and API usage.
