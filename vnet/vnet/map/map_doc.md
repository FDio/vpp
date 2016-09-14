# VPP MAP and Lw4o6 implementation    {#map_doc}

This is a memo intended to contain documentation of the VPP MAP and Lw4o6 implementations.
Everything that is not directly obvious should come here.



## MAP-E Virtual Reassembly

The MAP-E implementation supports handling of IPv4 fragments as well as IPv4-in-IPv6 inner and outer fragments. This is called virtual reassembly because the fragments are not actually reassembled. Instead, some meta-data are kept about the first fragment and reused for subsequent fragments.

Fragment caching and handling is not always necessary. It is performed when:
* An IPv4 fragment is received and the destination IPv4 address is shared.
* An IPv6 packet is received with an inner IPv4 fragment, the IPv4 source address is shared, and 'security-check fragments' is on.
* An IPv6 fragment is received.

There are 3 dedicated nodes:
* ip4-map-reass 
* ip6-map-ip4-reass
* ip6-map-ip6-reass

ip4-map sends all fragments to ip4-map-reass.
ip6-map sends all inner-fragments to ip6-map-ip4-reass.
ip6-map sends all outer-fragments to ip6-map-ip6-reass.

IPv4 (resp. IPv6) virtual reassembly makes use of a hash table in order to store IPv4 (resp. IPv6) reassembly structures. The hash-key is based on the IPv4-src:IPv4-dst:Frag-ID:Protocol tuple (resp. IPv6-src:IPv6-dst:Frag-ID tuple, as the protocol is IPv4-in-IPv6). Therefore, each packet reassembly makes use of exactly one reassembly structure. When such a structure is allocated, it is timestamped with the current time. Finally, those structures are capable of storing a limited number of buffer indexes.

An IPv4 (resp. IPv6) reassembly structure can cache up to MAP_IP4_REASS_MAX_FRAGMENTS_PER_REASSEMBLY (resp. MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY) buffers. Buffers are cached until the first fragment is received.

#### Virtual Reassembly configuration

IPv4 and IPv6 virtual reassembly support the following configuration:
    map params reassembly [ip4 | ip6] [lifetime <lifetime-ms>] [pool-size <pool-size>] [buffers <buffers>] [ht-ratio <ht-ratio>]

lifetime: 
	The time in milliseconds a reassembly structure is considered valid. The longer, the more reliable is reassembly, but the more likely it is to exhaust the pool of reassembly structures. IPv4 standard suggests a lifetime of 15 seconds. IPv6 specifies a lifetime of 60 people. Those values are not realistic for high-throughput cases.

buffers:
	The upper limit of buffers that are allowed to be cached. It can be used to protect against fragmentation attacks which would aim to exhaust the global buffers pool.
	
pool-size:
	The number of reassembly structures that can be allocated. As each structure can store a small fixed number of fragments, it also sets an upper-bound of 'pool-size * MAP_IPX_REASS_MAX_FRAGMENTS_PER_REASSEMBLY' buffers that can be cached in total.
	
ht-ratio:
	The amount of buckets in the hash-table is pool-size * ht-ratio.


Any time pool-size and ht-ratio is modified, the hash-table is destroyed and created again, which means all current state is lost.


##### Additional considerations

Reassembly at high rate is expensive in terms of buffers. There is a trade-off between the lifetime and number of allocated buffers. Reducing the lifetime helps, but at the cost of loosing state for fragments that are wide appart.

Let:
R be the packet rate at which fragments are received.
F be the number of fragments per packet.

Assuming the first fragment is always received last. We should have:
buffers > lifetime * R / F * (F - 1)
pool-size > lifetime * R/F

This is a worst case. Receiving the first fragment earlier helps reducing the number of required buffers. Also, an optimization is implemented (MAP_IP6_REASS_COUNT_BYTES and MAP_IP4_REASS_COUNT_BYTES) which counts the number of transmitted bytes and remembers the total number of bytes which should be transmitted based on the last fragment, and therefore helps reducing 'pool-size'.

But the formula shows that it is challenging to forward a significant amount of fragmented packets at high rates. For instance, with a lifetime of 1 second, 5Mpps packet rate would require buffering up to 2.5 millions fragments.

If you want to do that, be prepared to configure a lot of fragments.


