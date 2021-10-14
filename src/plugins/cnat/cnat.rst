.. _dev_cnat:

.. toctree::

Cloud NAT
=========

Overview
________

This plugin covers specific NAT use-cases that come mostly
from the container networking world. On the contrary of the
NAT concepts used for e.g. a home gateway, there is no notion
of 'outside' and 'inside'. We handle Virtual (or Real) IPs and
translations of the packets destined to them

Terminology & Usage
___________________

Setting up the NAT will consist in the creation of a ``translation``
that has several backends. A ``translation`` is 3-tuple containing :
a fully qualified IP address a port and a protocol. All packets
destined to it (ip, port) will then choose one of the backends,
and follow its rewrite rules.

A ``backend`` consists of four rewrites components (source & destination
address, source & destination port) that shall be applied to packets
on the way in, and reverted on the way back.

Backends are equally load-balanced with a flow hash. The choice
of a ``backend`` for a flow will trigger the creation of a NAT ``session``,
that will store the packet rewrite to do and the one to undo
until the flow is reset or a timeout is reached

A ``session`` is a fully resolved 9-tuple of ``src_ip, src_port, dest_ip, dest_port, proto``
to match incoming packets, and their new attributes ``new_src_ip, new_src_port, new_dest_ip, new_dest_port``. It allows for ``backend`` stickiness and a fast-path for established connections.

These ``sessions`` expire after 30s for regular ``sessions`` and 1h for established
TCP connections. These can be changed in vpp's configuration file

.. code-block:: console

  cnat {
      session-max-age 60
      tcp-max-age 3600
  }

Traffic is matched by inserting FIB entries, that are represented
by a ``client``. These maintain a refcount of the number of ``sessions``
and/or ``translations`` depending on them and be cleaned up when
all have gone.

Translating Addresses
---------------------

In this example, all packets destined to ``30.0.0.2:80`` will be
rewritten so that their destination IP is ``20.0.0.1`` and destination
port ``8080``. Here ``30.0.0.2`` has to be a virtual IP, it cannot be
assigned to an interface

.. code-block:: console

  cnat translation add proto TCP vip 30.0.0.2 80 to ->20.0.0.1 8080


If ``30.0.0.2`` is the address of an interface, we can use the following
to do the same translation, and additionally change the source.
address with ``1.2.3.4``

.. code-block:: console

  cnat translation add proto TCP real 30.0.0.2 80 to 1.2.3.4->20.0.0.1 8080

To show existing translations and sessions you can use

.. code-block:: console

  show cnat session verbose
  show cnat translation


SourceNATing outgoing traffic
-----------------------------

A independent part of the plugin allows changing the source address
of outgoing traffic on a per-interface basis.

In the following example, all traffic coming from ``tap0`` and NOT
going to ``20.0.0.0/24`` will be source NAT-ed with ``30.0.0.1``.
On the way back the translation will be undone.

NB: ``30.0.0.1`` should be and address known to the FIB (e.g. the
address assigned to an interface)

.. code-block:: console

  set cnat snat-policy addr 30.0.0.1
  set cnat snat-policy if-pfx
  set cnat snat-policy if table include-v4 tap0
  set cnat snat-policy prefix 20.0.0.0/24
  set interface feature tap0 cnat-snat-ip4 arc ip4-unicast

To show the enforced snat policies:

.. code-block:: console

  show cnat snat-policy

Other parameters
----------------

In vpp's startup file, you can also configure the bihash sizes for

* the translation bihash ``(proto, port) -> translation``
* the session bihash ``src_ip, src_port, dest_ip, dest_port, proto -> new_src_ip, new_src_port, new_dest_ip, new_dest_port``
* the snat bihash for searching ``snat-policy`` excluded prefixes

.. code-block:: console

  cnat {
      translation-db-memory 64K
      translation-db-buckets 1024
      session-db-memory 1M
      session-db-buckets 1024
      snat-db-memory 64M
      snat-db-buckets 1024
  }

Extending the NAT
_________________

This plugin is built to be extensible. For now two NAT types are defined, ``cnat_node_vip.c`` and ``cnat_node_snat.c``. They both inherit from ``cnat_node.h`` which provides :

* Session lookup : ``rv`` will be set to ``0`` if a session was found
* Translation primitives ``cnat_translation_ip4`` based on sessions
* A session creation primitive ``cnat_session_create``
* A reverse session creation primitive ``cnat_rsession_create``

Creating a session will also create reverse session matching return traffic unless told otherwise by setting ``CNAT_TR_FLAG_NO_RETURN_SESSION`` on the translation. This will call the NAT nodes on the return flow and perform the inverse translation.

Known limitations
_________________

This plugin is still under development, it lacks the following features :
* Load balancing doesn't support parametric probabilities
* VRFs are not supported, all rules apply regardless of the FIB table.
* Programmatic session handling (deletion, lifetime updates) aren't supported
* translations (i.e. rewriting the destination address) only match on the three
tuple ``(proto, dst_addr, dst_port)`` other matches are not supported
* Statistics & session tracking are still rudimentary.





