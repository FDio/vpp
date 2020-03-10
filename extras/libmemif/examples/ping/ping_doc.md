## Example    {#libmemif_ping_examples_doc}


#### Starting arguments

Command line arguments:

| parameter     | default value       | description                                                                                 | valid value               |
| :------------ | :------------------:|:-------------------------------------------------------------------------------------------:| :-----------------------: |
| id            | -                   | Interface id, used to match connection endpoints. First available, if not specified.        | `uint32`                  |
| ip            | 192.168.x.2         | Ipv4 address, 'x' is connection index.                                                      | `string`                  |
| role          | slave               | Role in which interface operates.                                                           | `string <master|slave>`   |
| soscket       | /run/vpp/memif.sock | Controll channel socket.                                                                    | `string`                  |
| domain        | -                   | Bridge domain, packets are replicated to all interfaces assigned to the same bridge domain. | `uint32`                  |
| qpairs        | 1                   | Number of queue pairs                                                                       | `uint8`                   |
| q0-rxmode     | interrupt           | Mode in which qid0 operates.                                                                | `string <interrupt|poll>` |
| rsize         | 10                  | Log2 of ring size. If rsize is 10, actual ring size is 1024                                 | `1-14`                    |
| bsize         | 2048                | Size of single packet buffer                                                                | `uint16_t`                |
| lcores        | -                   | Core list. Polling queues are assigned cores from this list                                 | `[0,1,...]`               |


> Master and slave can not share the same socket. Interface ids must be uniqueue per socket. Queue id 0 si handled by main thread.

#### Bridge domain (dev testing)

If bridge domain is specified, all packets received on the interface are replicated to all interfaces in the same bridge domain, except for the interface which received the packet. Ping functionality is disabled for bridged interfaces (including responds to any ICMP ECHO REQUEST).

> Intention of bridge domain is purely for dev testing.

#### Ping

Use of ping command is similar to any standard ping applications. Send ICMP ECHO REQUEST and wait for ICMP ECHO REPLY.
```
	ping <ip> [-q idx][-i idx]
	,where
		-q tx queue index
		-i tx interface index
```

#### Console commands

Ping example application works in interractive mode. Run help command:
```
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

#### Connect VPP and ping application

> Libmemif example app(s) use memif default socket file: `/run/vpp/memif.sock`.

Description, as is possible installing of vpp is explains step by step on this link:
[Check](https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Running)


VPP-side config:
```
DBGvpp# create interface memif id 0 master
DBGvpp# set int state memif0/0 up
DBGvpp# set int ip address memif0/0 192.168.1.1/24
```

start ping example:
```
sudo ping --vdev=memif0,id=0,role=slave
```
Memif in slave mode will try to connect every 2 seconds. If connection establishment is successful, a message will show after using "show log" command. Output can look like this:
```
> show log
12:13:54.748902327: memif connected!
>
```
> Error messages like "unmatched interface id" are printed only in debug mode.

Check connected status.
Use show command in ping demo:
```
> show
MEMIF DETAILS
==============================
index 0
	interface ip: 192.168.1.2
	interface name: memif0
	app name: ICMP_Responder
	remote interface name: memif0/0
	remote app name: VPP 20.01-rc0~583-gfb8f50808
	id: 0
	secret: (null)
	role: slave
	mode: ethernet
	socket filename: /run/vpp/memif.sock
	rx queues:
	queue id: 0
		ring size: 1024
		buffer size: 2048
		thread id: 0
		thread connection index: 0
		thread running: yes
	tx queues:
	queue id: 0
		ring size: 1024
		buffer size: 2048
		thread id: 0
		thread connection index: 0
		thread running: yes
	link: up

>
```

Use sh memif command in VPP:
```
vpp# sh memif
sockets
  id  listener    filename
  0   yes (1)     /run/vpp/memif.sock

interface memif0/0
  remote-name "ICMP_Responder"
  remote-interface "memif_connection"
  socket-id 0 id 0 mode ethernet
  flags admin-up connected
  listener-fd 28 conn-fd 29
  num-s2m-rings 1 num-m2s-rings 1 buffer-size 0 num-regions 2
  region 0 size 33024 fd 30
  region 1 size 4194304 fd 31
    master-to-slave ring 0:
      region 0 offset 16512 ring-size 1024 int-fd 33
      head 1024 tail 0 flags 0x0000 interrupts 0
    slave-to-master ring 0:
      region 0 offset 0 ring-size 1024 int-fd 32
      head 0 tail 0 flags 0x0001 interrupts 0

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

Send ping from demo example ping to vpp:
```
ping 192.168.1.1
42 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.0594 ms
42 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.0821 ms
42 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=0.1210 ms
42 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=0.0574 ms

Statistics: 5 sent, 4 received, 20% packet loss

```

#### multiple queues VPP-memif slave and ping example in master mode


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
DBGvpp# create interface memif id 0 slave rx-queues 4 tx-queues 4
DBGvpp# set int state memif0/0 up
DBGvpp# set int ip address memif0/0 192.168.1.1/24
```
start ping example:
```
sudo ping --vdev=memif0,id=0,role=master,qpairs=4
```

Number of queue pairs is set in command line arguments for each interface. If number of queue pairs is 4, then it's possible to ping from specific qid in range <0,3>.

#### Connect two instances of ping application

> This setup creates connection between two applications using libmemif. Traffic functionality is the same as when connection to VPP. App can receive ARP/ICMP request and transmit response.

Run two instances of ping example.
> If not running in container, make sure folder /run/vpp/ exists before creating memif master.
Instance 1 will be in master mode, instance 2 in slave mode.
instance 1:
```
sudo ping --vdev=memif0,id=0,role=master,ip=192.168.1.1
```
instance 2:
```
sudo ping --vdev=memif0,id=0,role=slave
```
Wait for 'memif connected!' mesage in the log:
```
> show log
12:13:54.748902327: memif connected!
>
```
