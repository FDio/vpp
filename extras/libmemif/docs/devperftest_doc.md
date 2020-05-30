## Development performance test    {#libmemif_devperftest_doc}

Simple test cases using ICMP. icmpr-epoll example app generates and transmits packets over memif interface.

#### TC1: LIB-VPP

Start icmpr-epoll example app and VPP.

VPP-side config:
```
DBGvpp# create interface memif id 0 master
DBGvpp# set int state memif0/0 up
DBGvpp# set int ip address memif0/0 192.168.1.1/24
```
icmpr-epoll:
```
conn 0 0 1
```
> Last argument specifies interrupt function to use. This function only responds to ARP requests. This is important because, packet generation and transmitting is handled by a separate thread. Calling memif_tx_burst from multiple threads writing on same queue could transmit uninitialized buffers.
Once connection is established, you can send ping from VPP to icmpr-epoll app to learn its mac address.
```
DBGvpp# ping 192.168.1.2
```
> There should be no ICMP response. Only ARP response.
Now send ICMP requests from icmpr-epoll:
```
send <index> <num-of-packets> <ip_daddr> <hw_daddr>
send 0 5 192.168.1.1 02:fe:ff:ff:ff:ff
```
this command will create new thread which will generate icmp packets and transmit them over memif connection with specified index. Once the sequence is finished status will be printed.

###### Example results (overview of test data)

(This test was run with modification in VPP-memif plugin. The modification disallows memif tx node to allocate last ring buffer)
lib-tx: 200M (if ring full don't drop packets)
vpp-rx: 200M
vpp-tx: 200M - 50K (if ring full drop packets)
lib-rx: =vpp-tx
drop: ~0.025% (full ring)
pps: ~650K
multiple interfaces:
pps: divided
drop: constant

#### TC2: LIB-LIB

This test case will not drop packets if memif ring is full. Instead it will loop until all required packets have been sent.

Start two instances of icmpr-epoll example app.
instance 1:
```
conn 0 1 0
```
instance 2:
```
conn 0 0 1
send 0 5 192.168.1.1 aa:aa:aa:aa:aa:aa
```
> icmpr-epoll example app doesn't check ip or mac address so as long as the format is correct you can type anything as ip_daddr and hw_daddr arguments.

###### Example results (overview of test data)

lib1-tx: 200M (if ring full don't drop packets)
lib2-rx: 200M
lib2-tx: 200M (if ring full don't drop packets)
lib1-rx: 200M
drop: obsolete
pps: 4.5M
multiple interfaces:
not tested (expected same as TC1)

#### TC3: LIB-LIB

Start two instances of icmpr-epoll example app.
instance 1:
```
conn 0 1
```
instance 2:
```
conn 0 0 1
send 0 5 192.168.1.1 aa:aa:aa:aa:aa:aa
```

###### Example results (overview of test data)

lib1-tx: 200M (if ring full don't drop packets)
lib2-rx: 200M
lib2-tx: 169626182 (if ring full drop packets)
lib1-rx: =lib2-tx
drop: ~15%
pps: ~6M
multiple interfaces:
not tested (expected same as TC1)
