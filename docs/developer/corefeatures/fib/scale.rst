.. _scale:

Scale
-----

The only limiting factor on FIB scale is the amount of memory
allocated to each heap the FIB uses, and there are 2:

* The main heap
* The stats heap


Main Heap
^^^^^^^^^

The main heap is used to allocate all memory needed for the FIB
data-structures. Each table, created by the user, i.e. with;

.. code-block:: console

   $ ip table add 1

or the default table, comprises 2 *ip4_fib_t* objects. 
The 'non-forwarding' *ip4_fib_t* contains all the entries in the table
and, the 'forwarding' contains the entries that are matched against in
the data-plane. The difference between the two sets are the entries
that should not be matched in the data-plane.
Each *ip4_fib_t* comprises an mtrie (for fast lookup in the data-plane)
and a hash table per-prefix length (for lookup in the control plane).

To see the amount of memory consumed by the IPv4 tables use:

.. code-block:: console
                
 vpp# sh ip fib mem
 ipv4-VRF:0 mtrie:335744 hash:4663
 ipv4-VRF:1 mtrie:333056 hash:3499
 totals: mtrie:668800 hash:8162 all:676962

this output shows two 'empty' (i.e. no added routes) tables. Each
mtrie uses about 150k of memory, so each table about 300k.


Below the output having added 1M, 2M and 4M routes respectively:

.. code-block:: console

 vpp# sh ip fib mem
 ipv4-VRF:0 mtrie:335744 hash:4695
 totals: mtrie:335744 hash:4695 all:340439

.. code-block:: console

 vpp# sh ip fib mem
 ipv4-VRF:0 mtrie:5414720 hash:41177579
 totals: mtrie:5414720 hash:41177579 all:46592299

.. code-block:: console

 vpp# sh ip fib mem
 ipv4-VRF:0 mtrie:22452608 hash:168544508
 totals: mtrie:22452608 hash:168544508 all:190997116


IPv6 also has the concept of forwarding and non-forwarding entries,
however for IPv6 all the forwarding entries are stored in a single
hash table (same goes for the non-forwarding). The key to the hash
table includes the IPv6 table-id.

To see the amount of memory consumed by the IPv4 tables use:

.. code-block:: console

 vpp# sh ip6 fib mem                                
 IPv6 Non-Forwarding Hash Table:
 Hash table ip6 FIB non-fwding table
     7 active elements 7 active buckets
     1 free lists
     0 linear search buckets
     arena: base 7f2fe28bf000, next 803c0
            used 525248 b (0 Mbytes) of 33554432 b (32 Mbytes)

 IPv6 Forwarding Hash Table:
 Hash table ip6 FIB fwding table
     7 active elements 7 active buckets
     1 free lists
     0 linear search buckets
     arena: base 7f2fe48bf000, next 803c0
            used 525248 b (0 Mbytes) of 33554432 b (32 Mbytes)
     
as we scale to 128k IPv6 entries:

.. code-block:: console

 vpp# sh ip6 fib mem
 IPv6 Non-Forwarding Hash Table:
 Hash table ip6 FIB non-fwding table
     131079 active elements 32773 active buckets
     2 free lists
        [len 1] 2 free elts
     0 linear search buckets
     arena: base 7fed7a514000, next 4805c0
            used 4720064 b (4 Mbytes) of 1073741824 b (1024 Mbytes)

 IPv6 Forwarding Hash Table:
 Hash table ip6 FIB fwding table
     131079 active elements 32773 active buckets
     2 free lists
        [len 1] 2 free elts
     0 linear search buckets
     arena: base 7fedba514000, next 4805c0
            used 4720064 b (4 Mbytes) of 1073741824 b (1024 Mbytes)

and 256k:

.. code-block:: console

 vpp# sh ip6 fib mem
 IPv6 Non-Forwarding Hash Table:
 Hash table ip6 FIB non-fwding table
     262151 active elements 65536 active buckets
     2 free lists
        [len 1] 6 free elts
     0 linear search buckets
     arena: base 7fed7a514000, next 880840
            used 8915008 b (8 Mbytes) of 1073741824 b (1024 Mbytes)

 IPv6 Forwarding Hash Table:
 Hash table ip6 FIB fwding table
     262151 active elements 65536 active buckets
     2 free lists
        [len 1] 6 free elts
     0 linear search buckets
     arena: base 7fedba514000, next 880840
            used 8915008 b (8 Mbytes) of 1073741824 b (1024 Mbytes)

and 1M:

.. code-block:: console

 vpp# sh ip6 fib mem
 IPv6 Non-Forwarding Hash Table:
 Hash table ip6 FIB non-fwding table
     1048583 active elements 65536 active buckets
     4 free lists
        [len 1] 65533 free elts
        [len 2] 65531 free elts
        [len 4] 9 free elts
     0 linear search buckets
     arena: base 7fed7a514000, next 3882740
            used 59254592 b (56 Mbytes) of 1073741824 b (1024 Mbytes)

 IPv6 Forwarding Hash Table:
 Hash table ip6 FIB fwding table
     1048583 active elements 65536 active buckets
     4 free lists
        [len 1] 65533 free elts
        [len 2] 65531 free elts
        [len 4] 9 free elts
     0 linear search buckets
     arena: base 7fedba514000, next 3882740
            used 59254592 b (56 Mbytes) of 1073741824 b (1024 Mbytes)

as can be seen from the output the IPv6 hash-table in this case was scaled
to 1GB and 1million prefixes has used 56MB of it.

The main heap is also used to allocate objects that represent the FIB
entries in the control and data plane (see :ref:`controlplane` and
:ref:`dataplane`) such as *fib_entry_t* and *load_balance_t*. These come
from the main heap because they are not protocol specific
(i.e. they are used to represent either IPv4, IPv6 or MPLS
entries).

With 1M prefixes allocated the memory usage is:

.. code-block:: console

 vpp# sh fib mem
 FIB memory
  Tables:
             SAFI              Number     Bytes   
         IPv4 unicast             1     33619968  
         IPv6 unicast             2     118502784 
             MPLS                 0         0     
        IPv4 multicast            1       1175    
        IPv6 multicast            1      525312   
  Nodes:
             Name               Size  in-use /allocated   totals
             Entry               72   1048589/ 1048589    75498408/75498408 
         Entry Source            40   1048589/ 1048589    41943560/41943560 
     Entry Path-Extensions       76      0   /    0       0/0 
        multicast-Entry         192      6   /    6       1152/1152 
           Path-list             40     18   /    18      720/720 
           uRPF-list             16     14   /    14      224/224 
             Path                72     22   /    22      1584/1584 
      Node-list elements         20   1048602/ 1048602    20972040/20972040 
        Node-list heads          8      24   /    24      192/192 

and with 2M

.. code-block:: console
       
 vpp# sh fib mem         
 FIB memory
  Tables:
             SAFI              Number     Bytes   
         IPv4 unicast             1     33619968  
         IPv6 unicast             2     252743040 
             MPLS                 0         0     
        IPv4 multicast            1       1175    
        IPv6 multicast            1      525312   
  Nodes:
             Name               Size  in-use /allocated   totals
             Entry               72   2097165/ 2097165    150995880/150995880 
         Entry Source            40   2097165/ 2097165    83886600/83886600 
     Entry Path-Extensions       76      0   /    0       0/0 
        multicast-Entry         192      6   /    6       1152/1152 
           Path-list             40     18   /    19      720/760 
           uRPF-list             16     18   /    18      288/288 
             Path                72     22   /    23      1584/1656 
      Node-list elements         20   2097178/ 2097178    41943560/41943560 
        Node-list heads          8      24   /    24      192/192 

However, the situation is not a simple as that. All of the 1M prefixes
added above were reachable via the same next-hop, so the path-list
(and path) they use is shared. As prefixes are added that use
different (sets of) next-hops, the number of path-lists and paths
requires will increase.


Stats Heap
^^^^^^^^^^

VPP collects statistics for each route. For each route VPP collects
byte and packet counters for packets sent to the prefix (i.e. the
route was matched in the data-plane) and packets sent via the prefix (i.e. the
matching prefix is reachable through it - like a BGP peer). This
requires 4 counters per route in the stats segment.

Below shows the size of the stats segment with 1M, 2M and 4M routes.

.. code-block:: console

 total: 1023.99M, used: 127.89M, free: 896.10M, trimmable: 830.94M
 total: 1023.99M, used: 234.14M, free: 789.85M, trimmable: 668.15M
 total: 1023.99M, used: 456.83M, free: 567.17M, trimmable: 388.91M

