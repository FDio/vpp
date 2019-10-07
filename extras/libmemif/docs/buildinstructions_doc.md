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

#### Verify installation:
```
build# ./examples/icmpr-epoll
```
Use _help_ command to display build information and commands:
```
LIBMEMIF EXAMPLE APP: ICMP_Responder
==============================
libmemif version: 3.0
memif version: 512
	use CTRL+C to exit
MEMIF DETAILS
==============================
	interface name: memif_connection
	app name: ICMP_Responder
	remote interface name:
	remote app name:
	id: 0
	secret: (null)
	role: slave
	mode: ethernet
	socket filename: /run/vpp/memif.sock
	socket filename: /run/vpp/memif.sock
	rx queues:
	tx queues:
	link: down
```

#### Examples

Once the library is built/installed, refer to @ref libmemif_examples_doc and @ref libmemif_gettingstarted_doc for additional information on basic use cases and API usage.
