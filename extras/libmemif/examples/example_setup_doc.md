## Example setup    {#libmemif_example_setup_doc}

### VPP-memif master icmp_responder slave

Start VPP and configure memif interface:
```
# make run
...
DBGvpp# create interface memif id 0 master
DBGvpp# set int state memif0/0 up
DBGvpp# set int ip address memif0/0 192.168.1.2/24
```
Start icmp_responder example app:
```
build# ./examples/icmp_responder
```
Memif in slave mode will try to connect every 2 seconds. If connection establishment is successful, a message will show.
```
INFO: memif connected!
```
> Error messages like "unmatched interface id" are printed only in debug mode.

Verify that the memif is connected on VPP side:
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

Send ping from VPP to icmp_responder (Default IPv4: 192.168.1.1):
```
DBGvpp# ping 192.168.1.1
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=.1888 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=.1985 ms
64 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=.1813 ms
64 bytes from 192.168.1.1: icmp_seq=5 ttl=64 time=.1929 ms

Statistics: 5 sent, 4 received, 20% packet loss
```

### Loopback

The main use case of loopback feature is testing (debugging). The example app will connect two interfaces and transmit a packet to verify connection.

Start the loopback example:
```
build# ./examples/loopback
```
You should see `INFO: Received correct data.` message.
```
INFO: Received correct data.
INFO: Stopping the program
```