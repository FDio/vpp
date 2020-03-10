## Build Instructions    {#libmemif_build_doc}

#### Install dependencies
```
# sudo apt-get install -y git cmake autoconf pkg_config libtool check
```

Libmemif is now part of VPP repository. Follow fd.io wiki to pull source code from VPP repository.
[https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Pushing_Patches](https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Pushing_Patches)

Libmemif is located under extras/libmemif. From extras/libmemif:
```
# mkdir build
# cd build
# cmake ..
# make install
```

#### Verify installation and build information:
```
build# ./examples/ping
LIBMEMIF EXAMPLE APP: Ping (debug)
==============================
libmemif version: 3.1 (debug)
memif version: 512

Example usage: ping --vdev=memif0 --master-lcore=0
	creates one connection with name of memif0 and set affinity of main thread on cpu with id 0

Arguments:
	--vdev=<name>,[opt1=<val>,opt2=<val>,...] - create device with specific options
	--master-lcore=<id_cpu> - set affinity of main thread on specific cpu

Options for --vdev:
	id=<num>                   : Number of connection interface.
	ip=<ip4>                   : Ip of interface.
	role=<master|slave>        : Role in which interface operates.
	soscket=<filename>         : name of socket connection.
	domain=<num>               : Bridge domain, packets are replicated to all interfaces
	                             assigned to the same bridge domain.
	qpairs=<num>               : Number of queue pairs.
	q0-rxmode=<interrupt|poll> : Mode in which qid0 operates.
	rsize=<num>                : Log2 of ring size. If rsize is 10, actual ring size is 1024.
	bsize=<num>                : Size of single packet buffer.
	lcores=[0,1,...]           : Core list. Polling queues are assigned cores from this list.
```


Minimal condition for suscced starting of ping program is neccesary setting of name of interface connection. In example below is set as name memif0. After starting program is possible write commands. Use help command to display  commands:
```
build# ./examples/ping --vdev=memif0
> help

commands:
	help - prints this help
	show - show connection details
	show log <filter> - show specific logs from starting of program by filter
	filters:
		DBG - debug messages
		INFO - info messages
	sh-count - print counters
	cl-count - clear counters
	exit - exit app
	ping <ip> [-q idx][-i idx]
	,where
		-q set index of queue, where packet will be transmited
		-i set index of connection, where packet will be transmited
>
```

#### Examples

Once the library is built/installed, refer to @ref libmemif_examples_doc and @ref libmemif_gettingstarted_doc for additional information on basic use cases and API usage.
