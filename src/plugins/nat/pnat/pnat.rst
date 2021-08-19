PNAT 1:1 match & rewrite NAT
============================

PNAT is a stateless statically configured, match and rewrite plugin. It
uses a set of match and rewrite rules that are applied on the IP input
and output feature paths. A PNAT rule is unidirectional.

The match is done using up to a 6-tuple; IP source and destination
address, IP protocol, transport layer source and destination ports, and
FIB table / interface index.

While multiple match/rewrite rules can be applied to an interface (per
direction), the match pattern must be the same across all rules on that
interface/direction.

If required in the future, matching could be done using the general
classifier, allowing matching on any protocol field, as well having an
ordered set of match patterns.

If the packet does not match, it will by default be passed to the next
graph node in the feature chain. If desired a different miss behaviour
could be implemented, e.g. similarly to dynamic NAT, the packet punted
to a slow path.

Rewrite instructions
--------------------

.. code:: c

   typedef enum {
     PNAT_INSTR_NONE                   = 1 << 0,
     PNAT_INSTR_SOURCE_ADDRESS         = 1 << 1,
     PNAT_INSTR_SOURCE_PORT            = 1 << 2,
     PNAT_INSTR_DESTINATION_ADDRESS    = 1 << 3,
     PNAT_INSTR_DESTINATION_PORT       = 1 << 4,
   } pnat_instructions_t;

These are the supported rewrite instructions. The IP checksum and the
TCP/UDP checksum are incrementally updated as required.

There are only a few “sanity checks” on the rewrites. For example, the
rewrite in the outbound direction is applied on the ip-output feature
chain. If one were to rewrite the IP destination address, the routing
decision and determination of the next-hop has already been done, and
the packet would still be forwarded to the original next-hop.
