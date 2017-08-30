## Example setup

#### VPP-memif master icmp_responder slave

> Libmemif example app(s) use memif default socket file: /run/vpp/memif.sock.

Run VPP and icmpr-epoll example (default example when running in container).
> Other examples work similar to icmpr-epoll. Brief explanation can be found in [Examples readme](README.md) file.

VPP-side config:
```
DBGvpp# create memif id 0 master
DBGvpp# set int state memif0/0 up
DBGvpp# set int ip address memif0/0 192.168.1.1/24
```
icmpr-epoll:
```
conn 0 0
```
Memif in slave mode will try to connect every 2 seconds. If connection establishment is successfull, a message will show.
```
INFO: memif connected!
```
> Error messages like "unmatched interface id" are printed only in debug mode.

Check connected status.
Use show command in icmpr-epoll:
```
show
MEMIF DETAILS
==============================
interface index: 0
	interface ip: 192.168.1.2
	interface name: memif_connection
	app name: ICMP_Responder
	remote interface name: memif0/0
	remote app name: VPP 17.10-rc0~132-g62f9cdd
	id: 0
	secret: 
	role: slave
	mode: ethernet
	socket filename: /run/vpp/memif.sock
	rx queues:
		queue id: 0
		ring size: 1024
		buffer size: 2048
	tx queues:
		queue id: 0
		ring size: 1024
		buffer size: 2048
	link: up
interface index: 1
	no connection

```
Use sh memif command in VPP:
```
DBGvpp# sh memif
interface memif0/0
  remote-name "ICMP_Responder"
  remote-interface "memif_connection"
  id 0 mode ethernet file /run/vpp/memif.sock
  flags admin-up connected
  listener-fd 12 conn-fd 13
  num-s2m-rings 1 num-m2s-rings 1 buffer-size 0
    master-to-slave ring 0:
      region 0 offset 32896 ring-size 1024 int-fd 16
      head 0 tail 0 flags 0x0000 interrupts 0
    master-to-slave ring 0:
      region 0 offset 0 ring-size 1024 int-fd 15
      head 0 tail 0 flags 0x0001 interrupts 0
```

Send ping from VPP to icmpr-epoll:
```
DBGvpp# ping 192.168.1.2
64 bytes from 192.168.1.2: icmp_seq=2 ttl=64 time=.1888 ms
64 bytes from 192.168.1.2: icmp_seq=3 ttl=64 time=.1985 ms
64 bytes from 192.168.1.2: icmp_seq=4 ttl=64 time=.1813 ms
64 bytes from 192.168.1.2: icmp_seq=5 ttl=64 time=.1929 ms

Statistics: 5 sent, 4 received, 20% packet loss
```
#### multiple queues VPP-memif slave icmp_responder master

Run icmpr-epoll as in previous example setup.
Run VPP with startup conf, enabling 2 worker threads.
Example startup.conf:
```
unix {
  interactive
  nodaemon
  full-coredump
}

cpu {
  workers 2
}
```
VPP-side config:
```
DBGvpp# create memif id 0 slave rx-queues 2 tx-queues 2
DBGvpp# set int state memif0/0 up
DBGvpp# set int ip address memif0/0 192.168.1.1/24
```
icmpr-epoll:
```
conn 0 1
```
When connection is established a message will print:
```
INFO: memif connected!
```
> Error messages like "unmatched interface id" are printed only in debug mode.

Check connected status.
Use show command in icmpr-epoll:
```
show
MEMIF DETAILS
==============================
interface index: 0
	interface ip: 192.168.1.2
	interface name: memif_connection
	app name: ICMP_Responder
	remote interface name: memif0/0
	remote app name: VPP 17.10-rc0~132-g62f9cdd
	id: 0
	secret: 
	role: master
	mode: ethernet
	socket filename: /run/vpp/memif.sock
	rx queues:
		queue id: 0
		ring size: 1024
		buffer size: 2048
		queue id: 1
		ring size: 1024
		buffer size: 2048
	tx queues:
		queue id: 0
		ring size: 1024
		buffer size: 2048
		queue id: 1
		ring size: 1024
		buffer size: 2048
	link: up
interface index: 1
	no connection

```
Use sh memif command in VPP:
```
DBGvpp# sh memif
interface memif0/0
  remote-name "ICMP_Responder"
  remote-interface "memif_connection"
  id 0 mode ethernet file /run/vpp/memif.sock
  flags admin-up slave connected
  listener-fd -1 conn-fd 12
  num-s2m-rings 2 num-m2s-rings 2 buffer-size 2048
    slave-to-master ring 0:
      region 0 offset 0 ring-size 1024 int-fd 14
      head 0 tail 0 flags 0x0000 interrupts 0
    slave-to-master ring 1:
      region 0 offset 32896 ring-size 1024 int-fd 15
      head 0 tail 0 flags 0x0000 interrupts 0
    slave-to-master ring 0:
      region 0 offset 65792 ring-size 1024 int-fd 16
      head 0 tail 0 flags 0x0001 interrupts 0
    slave-to-master ring 1:
      region 0 offset 98688 ring-size 1024 int-fd 17
      head 0 tail 0 flags 0x0001 interrupts 0

```
Send ping from VPP to icmpr-epoll:
```
DBGvpp# ping 192.168.1.2
64 bytes from 192.168.1.2: icmp_seq=2 ttl=64 time=.1439 ms
64 bytes from 192.168.1.2: icmp_seq=3 ttl=64 time=.2184 ms
64 bytes from 192.168.1.2: icmp_seq=4 ttl=64 time=.1458 ms
64 bytes from 192.168.1.2: icmp_seq=5 ttl=64 time=.1687 ms

Statistics: 5 sent, 4 received, 20% packet loss
```

#### icmp_responder master icmp_responder slave

> Example apps can only repond to ping. This setup creates connection between two applications using libmemif. Traffic functionality is the same as when connection to VPP. App can receive ARP/ICMP request and transmit response, but can not send ARP/ICMP request.

Run two instances of icmpr-epoll example.
> If not running in container, make sure folder /run/vpp/ exists before creating memif master.
Instance 1 will be in master mode, instance 2 in slave mode.
instance 1:
```
conn 0 1
```
instance 2:
```
conn 0 0
```
In 2 seconds, both instances should print connected! message:
```
INFO: memif connected!
```
Check peer interface names using show command.
