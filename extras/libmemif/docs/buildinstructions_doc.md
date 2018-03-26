## Build Instructions    {#libmemif_build_doc}

Install dependencies
```
# sudo apt-get install -y git autoconf pkg_config libtool check
```

Libmemif is now part of VPP repository. Follow fd.io wiki to pull source code from VPP repository.
[https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Pushing_Patches](https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Pushing_Patches)

Libmemif is located under extras/libmemif.
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
ICMP_Responder:add_epoll_fd:233: fd 0 added to epoll
ICMP_Responder:add_epoll_fd:233: fd 5 added to epoll
LIBMEMIF EXAMPLE APP: ICMP_Responder (debug)
==============================
libmemif version: 2.0 (debug)
memif version: 512
commands:
	help - prints this help
	exit - exit app
	conn <index> <mode> [<interrupt-desc>] - create memif. index is also used as interface id, mode 0 = slave 1 = master, interrupt-desc none = default 0 = if ring is full wait 1 = handle only ARP requests
	del  <index> - delete memif
	show - show connection details
	ip-set <index> <ip-addr> - set interface ip address
	rx-mode <index> <qid> <polling|interrupt> - set queue rx mode
	sh-count - print counters
	cl-count - clear counters
	send <index> <tx> <ip> <mac> - send icmp
```

#### Examples

Once the library is built/installed, refer to @ref libmemif_examples_doc and @ref libmemif_gettingstarted_doc for additional information on basic use cases and API usage.
