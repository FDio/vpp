.. _extensible:

=============================
Extensible and Modular Design
=============================

* Pluggable, easy to understand & extend
* Mature graph node architecture
* Full control to reorganize the pipeline
* Fast, plugins are equal citizens

**Modular, Flexible, and Extensible**

The FD.io VPP packet processing pipeline is decomposed into a ‘packet processing
graph’.  This modular approach means that anyone can ‘plugin’ new graph
nodes. This makes VPP easily exensible and means that plugins can be
customized for specific purposes. VPP is also configurable through it's
Low-Level API.

.. figure:: /_images/VPP_custom_application_packet_processing_graph.280.jpg
   :alt: Extensible, modular graph node architecture?
   
   Extensible and modular graph node architecture. 

At runtime, the FD.io VPP platform assembles a vector of packets from RX rings,
typically up to 256 packets in a single vector. The packet processing graph is
then applied, node by node (including plugins) to the entire packet vector. The
received packets typically traverse the packet processing graph nodes in the
vector, when the network processing represented by each graph node is applied to
each packet in turn.  Graph nodes are small and modular, and loosely
coupled. This makes it easy to introduce new graph nodes and rewire existing
graph nodes.

Plugins are `shared libraries <https://en.wikipedia.org/wiki/Library_(computing)>`_ 
and are loaded at runtime by VPP. VPP find plugins by searching the plugin path 
for libraries, and then dynamically loads each one in turn on startup. 
A plugin can introduce new graph nodes or rearrange the packet processing graph. 
You can build a plugin completely independently of the FD.io VPP source tree,
which means you can treat it as an independent component.
