.. _hash_doc:

Hash Infra
==========

Overview
________

Modern physical NICs uses packet flow hash for different purposes, i.e. Receive
Side Scaling, flow steering and interface bonding etc. NICs can also provide
packet flow hash prepended to data packet as metadata which can be used by
applications without recomputing the packet flow hash.

As more and more services are deployed in virtualized environment, making use of
virtual interfaces to interconnect those services.

The Hash Infrastructure
_______________________

VPP implements software based hashing functionality which can be used for different
purposes. It also provides users a centralized way to registry custom hash functions
based on traffic profile to be used in different vpp features i.e. Multi-TXQ,
software RSS or bonding driver.

Data structures
^^^^^^^^^^^^^^^

Hashing infra provides two types of hashing functions:
``VNET_HASH_FN_TYPE_ETHERNET`` and ``VNET_HASH_FN_TYPE_IP`` for ethernet traffic and
IP traffic respectively.
Hashing infra provides uniform signature to the functions to be implemented:

.. code:: c

  void (*vnet_hash_fn_t) (void **p, u32 *h, u32 n_packets);

Here ``**p`` is the array of pointers pointing to the beginning of packet headers
(either ethernet or ip).
``*h`` is an empty array of size n_packets. On return, it will contain hashes.
``n_packets`` is the number of packets pass to this function.

Custom hashing functions can be registered through ``VNET_REGISTER_HASH_FUNCTION``.
Users need to provide a name, description, priority and hashing functions for
registration.

Default hashing function is selected based on the highest priority among the registered
hashing functions.

.. code:: c

  typedef struct vnet_hash_function_registration
  {
    const char *name;
    const char *description;
    int priority;
    vnet_hash_fn_t function[VNET_HASH_FN_TYPE_N];

    struct vnet_hash_function_registration *next;
  } vnet_hash_function_registration_t;

For example, ``crc32c_5tuple`` provides two hashing functions: for IP traffic and for
ethernet traffic. It uses 5 tuples from the flow to compute the crc32 hash on it.

.. code:: c

  void vnet_crc32c_5tuple_ip_func (void **p, u32 *hash, u32 n_packets);
  void vnet_crc32c_5tuple_ethernet_func (void **p, u32 *hash, u32 n_packets);

  VNET_REGISTER_HASH_FUNCTION (crc32c_5tuple, static) = {
    .name = "crc32c-5tuple",
    .description = "IPv4/IPv6 header and TCP/UDP ports",
    .priority = 50,
    .function[VNET_HASH_FN_TYPE_ETHERNET] = vnet_crc32c_5tuple_ethernet_func,
    .function[VNET_HASH_FN_TYPE_IP] = vnet_crc32c_5tuple_ip_func,
  };


Users can see all the registered hash functions along with priority and description.

Hash API
^^^^^^^^

There is no Hash API at the moment.

Hash CLI
^^^^^^^^

::

  show hash
