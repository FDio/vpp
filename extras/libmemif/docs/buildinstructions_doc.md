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
LIBMEMIF EXAMPLE APP: ICMP_Responder (debug)
==============================
libmemif version: 3.1 (debug)
memif version: 512
starting arguments:
	./ping --aff={cpu0,cpu1,..,cpun}
	--vdev=<id0_name>,[i=id],[ip=address],[r=master|slave],[s=socket_name],
	[domain=id],[q0=poll|interrupt],[qn=qn_count],[rs=ring_size],[bs=buffer_size],
	[aff={cpu0,cpu1,..,cpun}] --vdev=<id1_name>...
	where --aff - setting affinity of cpu on specific id numbers of cpu for
		main thread of program
	in --vdev:
		id for domain - numeric id. interface with same domain id will be routed
		id for i - index of connetion
		address - address of this example
		socket_name - name of socket for communication
		qn_count - number of queues
		ring_size - size of ring
		buffer_size - size of buffer
		q0 - setting of mode for qid 0
		aff - setting affinity of cpu on specific id numbers of cpu for qid0
			(in interrupt mode will be this parameter ignored).

```


Minimal condition for suscced starting of ping program is neccesary setting of name of interface connection. In example below is set as name memif0. After starting program is possible write commands. Use help command to display  commands:
```
build# ./examples/ping --vdev=memif0
> help

commands:
	help - prints this help
	show - show connection details
	show log - show logs of program from his starting to using this command
	show log INFO - show info logs of program from his starting to using this command
	show log DBG - show debug logs of program from his starting to using this command
	sh-count - print counters
	cl-count - clear counters
	exit - exit app
	ping <ip> [-q idx][-i idx]
	,where
		idx for -q is index of queue, where packet be transmited
		idx for -i is index of connection, where packet be transmited
> 
```

#### Examples

Once the library is built/installed, refer to @ref libmemif_examples_doc and @ref libmemif_gettingstarted_doc for additional information on basic use cases and API usage.
