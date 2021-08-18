=============================
Network Policy (npol) Plugin
=============================

Overview
--------

The **Network Policy (npol)** plugin provides a programmable policy engine
for applying packet filtering and forwarding rules in VPP.
It allows you to:

- Create and manage **IP sets** (collections of IPs, subnets, or IP:port entries).
- Define **rules** to allow, deny, or log traffic based on IPs, prefixes, sets, ports, and direction.
- Build **policies** from rules and apply them on interfaces in RX (inbound) and TX (outbound) directions.


Quick Start
-----------

This example shows how to configure and apply a network policy on a loopback interface.

1. **Create a loopback interface and configure an IP address**

.. code-block:: console

   DBGvpp# create loopback interface
   loop0

   DBGvpp# set interface state loop0 up

   DBGvpp# set interface ip address loop0 10.0.0.1/32

   DBGvpp# sh int addr
   local0 (dn):
   loop0 (up):
     L3 10.0.0.1/32

2. **Explore npol commands**

.. code-block:: console

   DBGvpp# npol ?
        npol interface clear                     npol interface clear [interface | sw_if_index N]
        npol interface configure                 npol interface configure [interface | sw_if_index N] rx <num_rx> tx <num_tx> <policy_id> ...
        npol ipset add member                    npol ipset add member [id] [prefix]
        npol ipset add                           npol ipset add [prefix|proto ip port|ip]
        npol ipset del member                    npol ipset del member [id] [prefix]
        npol ipset del                           npol ipset del [id]
        npol policy add                          npol policy add [rx rule_id rule_id ...] [tx rule_id rule_id ...] [update [id]]
        npol policy del                          npol policy del [id]
        npol rule add                            npol rule add [ip4|ip6] [allow|deny|log|pass][filter[==|!=]value][[src|dst][==|!=][prefix|set ID|[port-port]]]
        npol rule del                            npol rule del [id]

3. **Create an IP set**

.. code-block:: console

   DBGvpp# npol ipset add 20.0.0.0/24
   npol ipset 0 added

   DBGvpp# sh npol ipsets
   [ipset#0;prefix;20.0.0.0/24,]

4. **Add rules**

- Rule 0: Deny packets with a source IP in the created set.
- Rule 1: Allow all other packets.

.. code-block:: console

   DBGvpp# npol rule add ip4 deny src==set0
   npol rule 0 added

   DBGvpp# npol rule add ip4 allow
   npol rule 1 added

   DBGvpp# sh npol rules
   [rule#0;deny][src==[ipset#0;prefix;20.0.0.0/24,],]
   [rule#1;allow][]

5. **Create a policy**

This policy applies Rule 0 and Rule 1 on RX,
and Rule 1 on TX.

.. code-block:: console

   DBGvpp# npol policy add rx 0 1 tx 1
   npol policy 0 added

   DBGvpp# sh npol policies verbose
   [policy#0]
     tx:[rule#1;allow][]
     rx:[rule#0;deny][src==[ipset#0;prefix;20.0.0.0/24,],]
     rx:[rule#1;allow][]

6. **Apply the policy to an interface**

.. code-block:: console

   DBGvpp# npol interface configure loop0 0
   npol interface 1 configured

   DBGvpp# sh npol interfaces
   Interfaces with policies configured:
   [loop0 sw_if_index=1  addr=10.0.0.1]
      rx-policy-default:1 rx-profile-default:1
      tx-policy-default:1 tx-profile-default:1
     profiles:
       [policy#0]
         tx:[rule#1;allow][]
         rx:[rule#0;deny][src==[ipset#0;prefix;20.0.0.0/24,],]
         rx:[rule#1;allow][]

Summary
-------

- **IP sets** define groups of IPs, prefixes, or IP:port pairs.
- **Rules** define match conditions and actions (allow, deny, log, pass).
- **Policies** group rules per direction (RX/TX).
- **Interfaces** are configured with policies, enforcing filtering in the datapath.

This modular design allows fine-grained policy enforcement
directly in VPP with efficient data structures.
