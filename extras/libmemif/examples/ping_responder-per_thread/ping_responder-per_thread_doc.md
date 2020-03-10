## Example    {#libmemif_ping_responder-per_thread_doc}


#### Starting arguments

This example application creates multiple instances of memif driver, each in separate thread using APIs in `memif_per_thread_` namespace. Memif driver instances are completely separated and accessed using `libmemif_main_handle_t`. Each driver instance must use unique socket name. The pattern is "/run/vpp/memif<thread-id>.sock". Each driver creates number of memif interfaces. Ids are assinged starting at 0 and incrementing. Ip address assiging patter is "192.168+<thread-id>.<memif-id>.2".
```
-t <num> - number of threads, each thread creates memif driver instance
-i <num> - number of interfaces per thread
```
Default values are 4 threads and 2 connections per thread.

Create 3 threads, each having 3 interfaces:
```
ping_responder-per_thread -t 3 -i 3
```
> sockets: "/run/vpp/memif0.sock", "/run/vpp/memif1.sock" and "/run/vpp/memif2.sock". Interface ids: 0,1,2. For each thread/driver instance.

#### Console commands

THe example is interractive:

```
cmd: help
exit - Exits the application.
help - Print this help.
show - Show memif interfaces
```

Command "show" is for getting information about all connections. Example above, may has output like this:

```
show
3 Threads 3 Memifs (per thread)
=================================
Thread 0 /run/vpp/memif0.sock
	Memif id 0
	Link up
	Memif id 1
	Link up
	Memif id 2
	Link up
Thread 1 /run/vpp/memif1.sock
	Memif id 0
	Link down
	Memif id 1
	Link down
	Memif id 2
	Link down
Thread 2 /run/vpp/memif2.sock
	Memif id 0
	Link down
	Memif id 1
	Link down
	Memif id 2
	Link down
cmd:
```

#### Connect VPP and ping application

> Libmemif example app(s) use memif default socket file: `/run/vpp/memif.sock`.

Description, as is possible installing of vpp is explains step by step on this link:
[Check](https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Running) 


VPP-side config:
```
DBGvpp# create memif socket id 1 filename /run/vpp/memif0.sock
DBGvpp# create memif socket id 2 filename /run/vpp/memif1.sock
DBGvpp# create memif socket id 3 filename /run/vpp/memif2.sock
DBGvpp# create interface memif id 0 socket-id 1 master
DBGvpp# create interface memif id 1 socket-id 1 master
DBGvpp# create interface memif id 0 socket-id 2 master
DBGvpp# create interface memif id 1 socket-id 2 master
DBGvpp# create interface memif id 0 socket-id 3 master
DBGvpp# create interface memif id 1 socket-id 3 master
DBGvpp# set int ip address memif1/0 192.168.1.1/24
DBGvpp# set int ip address memif1/1 192.168.2.1/24
DBGvpp# set int ip address memif2/0 192.169.1.1/24
DBGvpp# set int ip address memif2/1 192.169.2.1/24
DBGvpp# set int ip address memif3/0 192.170.1.1/24
DBGvpp# set int ip address memif3/1 192.170.2.1/24
DBGvpp# set int state memif1/0 up
DBGvpp# set int state memif1/1 up
DBGvpp# set int state memif2/0 up
DBGvpp# set int state memif2/1 up
DBGvpp# set int state memif3/0 up
DBGvpp# set int state memif3/1 up
```

start ping_responder-per_thread example:
```
sudo ping_responder-per_thread -t 3 -i 2
```

Then will be created folowing ip adresses on side of example: 
- 192.168.1.2, 192.168.2.2 on socket of /run/vpp/memif0.sock 
- 192.169.1.2, 192.169.2.2 on socket of /run/vpp/memif1.sock
- 192.170.1.2, 192.170.2.2 on socket of /run/vpp/memif2.sock

Check connected status.
Use show command in ping demo:
```
cmd: show
3 Threads 2 Memifs (per thread)
=================================
Thread 0 /run/vpp/memif0.sock
	Memif id 0
	Link up
	Memif id 1
	Link up
Thread 1 /run/vpp/memif1.sock
	Memif id 0
	Link up
	Memif id 1
	Link up
Thread 2 /run/vpp/memif2.sock
	Memif id 0
	Link up
	Memif id 1
	Link up
```

Send ping from VPP to ping example:
```
DBGvpp# ping 192.168.1.2
64 bytes from 192.168.1.2: icmp_seq=2 ttl=64 time=.1888 ms
64 bytes from 192.168.1.2: icmp_seq=3 ttl=64 time=.1985 ms
64 bytes from 192.168.1.2: icmp_seq=4 ttl=64 time=.1813 ms
64 bytes from 192.168.1.2: icmp_seq=5 ttl=64 time=.1929 ms

Statistics: 5 sent, 4 received, 20% packet loss
```

Repeat the same process with other ip on example side.

