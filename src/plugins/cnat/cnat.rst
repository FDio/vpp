.. _dev_cnat:

.. toctree::

Cloud NAT
=========

Overview
________

This plugin covers specific NAT use-cases that come mostly
from the container networking world. On the contraty of the
NAT concepts used for e.g. a home gateway, there is no notion
of 'outside' and 'inside'. We handle Virtual (or Real) IPs and
translations of the packets destined to them

Terminology & Usage
___________________

Setting up the NAT will consist in the creation of a translation
that has several backends. A translation is 3-tuple containing :
a fully qualified IP address a port and a protocol. All packets
destined to it (ip, port) will then choose one of the backends,
and follow its rewrite rules.

A backend consists of four rewrites components (source & destination
address, source & destination port) that shall be applied to packets
on the way in, and reverted on the way back.

Backends are equally load-balanced with a flow hash. The choice
of a backend for a flow will trigger the creation of a NAT session,
that will store the packet rewrite to do and the one to undo
until the flow is reset or a timeout is reached

Translating Addresses
---------------------

In this example, all packets destined to 30.0.0.2:80 will be
rewritten so that their destination IP is 20.0.0.1 and destination
port 8080. Here 30.0.0.2 has to be a virtual IP, it cannot be
assigned to an interface

.. code-block:: console

  cnat translation add proto TCP vip 30.0.0.2 80 to ->20.0.0.1 8080


If 30.0.0.2 is the address of an interface, we can use the following
to do the same translation, and additionnaly change the source.
address with 1.2.3.4

.. code-block:: console

  cnat translation add proto TCP real 30.0.0.2 80 to 1.2.3.4->20.0.0.1 8080

To show existing translations and sessions you can use

.. code-block:: console

  cnat show session verbose
  cant show translation


SourceNATing outgoing traffic
-----------------------------

A independant part of the plugin allows changing the source address
of outgoing traffic on a per-interface basis.

.. code-block:: console

  cnat snat with 30::1
  cnat snat exclude 20::/100
  ex_ctl _calico_master cnat snat exclude 10::/100
  ex_ctl _calico_master set interface feature tap0 ip6-cnat-snat arc ip6-unicast



Extending the NAT
_________________

