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

     $ python flow_create.py --add -p "mac()/ipv4(src=1.1.1.1,dst=2.2.2.2)/udp()"
       -a "redirect-to-queue 3" -i 1

     $ python flow_create.py --add
       --pattern "mac()/ipv4(src=1.1.1.1,dst=2.2.2.2)/udp()"
       --actions "redirect-to-queue 3" --interface 1

     $ python flow_create.py --del -i 1 -I 0

     $ python flow_create.py --del --interface 1 --flow-index 0

Naming format input. There are two operations, add and delete flow rules.
For add, it needs three parameters. Pattern is similar to Scapy protocols.
Actions is the same as vnet/flow command. Interface is the device to which
we want to add the flow rule. For delete, flow index is the index of the
flow rule we want to delete. We can get the index number when we add the
flow or use command to show the existed flow entry in CLI.

::

     $ python flow_create.py --add -f "./flow_rule_examples/mac_ipv4.json" -i 1

     $ python flow_create.py --add --file "./flow_rule_examples/mac_ipv4.json"
       --interface 1

     $ python flow_create.py --add -f "./flow_rule_examples/mac_ipv4.json"
       -a "redirect-to-queue 3" -i 1

Json profile format input. This command takes a json profile as parameter.
In the json profile, there will be protocols and their fields and values.
Users can define spec and mask for each field. Actions can be added in the
profile directly, otherwise "-a" option should be added in the command to
specify actions. The example can be found in parsegraph/samples folder.
Users can create their own json files according to examples and Spec.

::

      $ show flow entry

It is a vnet/flow command, used in VPP CLI. It can show the added flow rules
after using the above commands. Users can get the flow index with this command
and use it to delete the flow rule.

ParseGraph
----------

Packetforge is built based on a ParseGraph. The ParseGraph is constructed
with nodes and edges. Nodes are protocols, including information about
protocol's name, fields and default values. Edges are the relationship
between two protocols, including some actions needed when connecting two
protocols. For example, change the mac header ethertype to 0x0800 when
connecting mac and ipv4. More details are in the Spec in parsegraph folder.
Users can build the ParseGraph following the spec by themselves, like
adding a new protocol. If NIC supports the new protocol, the rule can be
created. Otherwise, it will return error.
