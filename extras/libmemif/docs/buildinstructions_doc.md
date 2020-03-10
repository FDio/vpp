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
LIBMEMIF EXAMPLE APP: Ping
==============================
libmemif version: 3.1
memif version: 512

Example usage: ping --vdev=memif0 --master-lcore=0
	Creates one memif interface named memif0 and sets the affinity of main thread to cpu 0.

Arguments:
	--vdev=<name>,[opt1=<val>,opt2=<val>,...] - Create memif interface with specific options.
	--master-lcore=<id_cpu> - Set affinity of main thread to specific cpu.

Options for --vdev:
	id=<num>                   : Unique interface id.
	ip=<ip4>                   : Ipv4 address.
	role=<master|slave>        : Role in which interface operates.
	socket=<filename>          : Controll channel socket filename.
	domain=<num>               : Bridge domain, packets are replicated to all interfaces
	                             assigned to the same bridge domain. Interfaces in
	                             bridge domain won't respond to ICMP requests.
	qpairs=<num>               : Number of queue pairs.
	q0-rxmode=<interrupt|poll> : Mode in which qid0 operates.
	rsize=<num>                : Log2 of ring size. If rsize is 10, actual ring size is 1024.
	bsize=<num>                : Size of single packet buffer.
	lcores=[0,1,...]           : Core list. Polling queues are assigned cores from this list.
```


Ping is an interractive application, use `help` command to print available commands:
```
build# ./examples/ping --vdev=memif0
> help

commands:
	help - prints this help
	show - show connection details
	show log <info|debug> - show runtime logs
	sh-count - print counters
	cl-count - clear counters
	exit - exit app
	ping <ip4> [-q idx] [-i idx] - ping ip4 address. ping specific queue and
		                         interface by setting -q and -i respectively
```

#### Examples

Once the library is built/installed, refer to @ref libmemif_examples_doc and @ref libmemif_gettingstarted_doc for additional information on basic use cases and API usage.
