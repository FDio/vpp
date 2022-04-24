.. _packetforge_doc:

Packetforge for generic flow
============================

Packetforge is a tool to support generic flow. Since the input format of
generic flow is hard to read and create, packetforge can help to create
generic flow rules using a format of naming protocols (like Scapy) or json
profile. Packetforge is built based on a parsegraph, users can modify the
graph nodes and edges if needed.

Command examples
----------------

::

     $ python flow_create.py -p "mac()/ipv4(src=1.1.1.1,dst=2.2.2.2)/udp()"
       -a "redirect-to-queue 3" -i 1

Naming format input. It needs two parameters. Pattern format is similar to
Scapy protocols. Actions format is the same as vnet/flow command. This
command will add and enable flow rules to interface 1.

::

     $ python flow_create.py -f "./flow_rule_examples/mac_ipv4.json" -i 1

Json profile format input. This command takes a json profile as parameter.
In the json profile, there will be protocols and their fields and values.
Users can define spec and mask for each field. Actions can be added in the
profile directly, otherwise "-a" option should be added in the command.
The example can be found in flow_rule_examples folder.

::

      $ show flow entry

It is a vnet/flow command, used in VPP CLI. It can show the added flow rules
after using the above commands. In addition, if users want to delete or
disable the rules, vnet/flow commands "test flow del" and "test flow disable"
are valid.

ParseGraph
----------

Packetforge is built based on a ParseGraph. The ParseGraph is constructed
with nodes and edges. Nodes are protocols, including information about
protocol's name, fields and default values. Edges are the relationship
between two protocols, including some actions needed when connecting two
protocols. For example, change the mac header ethertype to 0x0800 when
connecting mac and ipv4. More details are in the spec in parsegraph folder.
Users can build the ParseGraph following the spec by themselves, like
adding a new protocol. If NIC supports the new protocol, the rule can be
created. Otherwise, it will return error.
