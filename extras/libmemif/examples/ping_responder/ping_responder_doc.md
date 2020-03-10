## Example    {#libmemif_ping_responder_doc}

#### Starting arguments

Example ping_responder supports only one constant connection in slave mode with interface id 0 and address 192.168.1.2. It's possible to set count of queues and queue id to send replies to. Ping_responder responds to ICMP REPLY. First argument is queue id, second is number of queue pairs.

```
sudo ping_responder 2 3
```

#### Connect VPP and ping_responder application

> Libmemif example app(s) use memif default socket file: `/run/vpp/memif.sock`.

Description, as is possible installing of vpp is explains step by step on this link:
[Check](https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Running) 


VPP-side config:
```
DBGvpp# create interface memif id 0 master rx-queues 3 tx-queues 3
DBGvpp# set int state memif0/0 up
DBGvpp# set int ip address memif0/0 192.168.1.1/24
```

start ping_responder example:
```
sudo ping_responder 2 3
```
Memif in slave mode will try to connect every 2 seconds. If connection establishment is successfull, a message will show.
```
memif connected!
```
> Error messages like "unmatched interface id" are printed only in debug mode.

Check connected status. Use sh memif command in VPP:
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
  num-s2m-rings 3 num-m2s-rings 3 buffer-size 0 num-regions 2
  region 0 size 99072 fd 30
  region 1 size 12582912 fd 31
    master-to-slave ring 0:
      region 0 offset 49536 ring-size 1024 int-fd 35
      head 1024 tail 0 flags 0x0000 interrupts 0
    master-to-slave ring 1:
      region 0 offset 66048 ring-size 1024 int-fd 36
      head 0 tail 0 flags 0x0000 interrupts 0
    master-to-slave ring 2:
      region 0 offset 82560 ring-size 1024 int-fd 37
      head 0 tail 0 flags 0x0000 interrupts 0
    slave-to-master ring 0:
      region 0 offset 0 ring-size 1024 int-fd 32
      head 0 tail 0 flags 0x0001 interrupts 0
    slave-to-master ring 1:
      region 0 offset 16512 ring-size 1024 int-fd 33
      head 0 tail 0 flags 0x0001 interrupts 0
    slave-to-master ring 2:
      region 0 offset 33024 ring-size 1024 int-fd 34
      head 0 tail 0 flags 0x0001 interrupts 0
```

Send ping from VPP to ping_responder:
```
vpp# ping 192.168.1.2
116 bytes from 192.168.1.2: icmp_seq=2 ttl=64 time=10.4628 ms
116 bytes from 192.168.1.2: icmp_seq=3 ttl=64 time=4.3641 ms
116 bytes from 192.168.1.2: icmp_seq=4 ttl=64 time=6.5105 ms
116 bytes from 192.168.1.2: icmp_seq=5 ttl=64 time=9.5104 ms

Statistics: 5 sent, 4 received, 20% packet loss
```

To inspect the behavior use 'show memif' command:
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
  num-s2m-rings 3 num-m2s-rings 3 buffer-size 0 num-regions 2
  region 0 size 99072 fd 30
  region 1 size 12582912 fd 31
    master-to-slave ring 0:
      region 0 offset 49536 ring-size 1024 int-fd 35
      head 1029 tail 5 flags 0x0000 interrupts 5
    master-to-slave ring 1:
      region 0 offset 66048 ring-size 1024 int-fd 36
      head 0 tail 0 flags 0x0000 interrupts 0
    master-to-slave ring 2:
      region 0 offset 82560 ring-size 1024 int-fd 37
      head 0 tail 0 flags 0x0000 interrupts 0
    slave-to-master ring 0:
      region 0 offset 0 ring-size 1024 int-fd 32
      head 0 tail 0 flags 0x0001 interrupts 0
    slave-to-master ring 1:
      region 0 offset 16512 ring-size 1024 int-fd 33
      head 0 tail 0 flags 0x0001 interrupts 0
    slave-to-master ring 2:
      region 0 offset 33024 ring-size 1024 int-fd 34
      head 5 tail 5 flags 0x0001 interrupts 0
```
In the output we see that 5 packets were transmited on ring 0 type "master-to-slave" and 5 packets were received on ring 2 type "slave-to-master".
> memif rings are represented as queues

