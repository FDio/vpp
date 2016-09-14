# VPP L2-GRE over IPsec implementation    {#ipsec_gre_doc}

This is a memo intended to contain documentation of the VPP L2-GRE over IPsec implementation.
Everything that is not directly obvious should come here.


## L2-GRE over IPsec
GRE encapsulate layer 2 traffic and IPSec encrypt what is encapsulated by GRE. The whole point of L2-GRE over IPSec is to tunnel layer 2 over GRE and IPSec by bridging the physical interface with IPSec-GRE tunnel interface.

There are 2 dedicated nodes for encapsulation:
* ipsec-gre<n>-tx - add GRE header
* esp-encrypt - encrypt GRE packet to ESP packet

There are 3 dedicated nodes for decapsulation:
* ipsec-if-input - match IPSec SA by source IP address and SPI in ESP packet
* esp-decrypt - decrypt ESP packet
* ipsec-gre-input - remove GRE header


### Configuration

L2-GRE over IPsec support the following CLI configuration command:
    create ipsec gre tunnel src <addr> dst <addr> local-sa <id> remote-sa <id> [del]

src: tunnel source IPv4 address
dst: tunnel destination IPv4 address
local-sa: tunnel local IPSec Security Association
remote-sa: tunnel remote IPSec Security Association
del: delete IPSec-GRE tunnel

L2-GRE over IPsec support the following API configuration command:
    ipsec_gre_add_del_tunnel src <addr> dst <addr> local_sa <sa-id> remote_sa <sa-id> [del]

src: tunnel source IPv4 address
dst: tunnel destination IPv4 address
local_sa: tunnel local IPSec Security Association
remote_sa: tunnel remote IPSec Security Association
del: delete IPSec-GRE tunnel


### Configuration example

Interface GigabitEthernet0/9/0 is in bridge with ipsec-gre0 tunnel interface, interface GigabitEthernet0/8/0 sending encapsulated and encrypted traffic.

Configure IPv4 address on sending interface:
set int ip address GigabitEthernet0/8/0 192.168.1.1/24

Configure IPSec Security Associations:
ipsec sa add 10 spi 1001 esp crypto-key 4a506a794f574265564551694d653768 crypto-alg aes-cbc-128 integ-key 4339314b55523947594d6d3547666b45764e6a58 integ-alg sha1-96
ipsec sa add 20 spi 1000 esp crypto-key 49517065716d6235726c734a4372466c crypto-alg aes-cbc-128 integ-key 307439636a5542735133595835546f68534e4f64 integ-alg sha1-96

Create IPSec-GRE tunnel:
create ipsec gre tunnel src 192.168.1.1 dst 192.168.1.2 local-sa 10 remote-sa 20

Set interfaces state:
set int state GigabitEthernet0/8/0 up
set int state GigabitEthernet0/9/0 up
set int state ipsec-gre0 up

Bridge physical interface with IPSec-GRE tunnel interface:
set interface l2 bridge GigabitEthernet0/9/0 1
set interface l2 bridge ipsec-gre0 1


### Operational data

L2-GRE over IPsec support the following CLI show command:
    show ipsec gre tunnel

L2-GRE over IPsec support the following API dump command:
    ipsec_gre_tunnel_dump [sw_if_index <nn>]

sw_if_index: software interface index of the IPSec-GRE tunnel interface

