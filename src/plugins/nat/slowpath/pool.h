#ifndef included_nat_slowpath_pool_h
#define included_nat_slowpath_pool_h

#include <vnet/ip/ip4_packet.h>
#include "../flowrouter/flowrouter.h"

typedef struct {
  u32 count;
  u32 vrf_id;
  ip4_address_t prefix;
  u8 prefixlen;
} nat_slowpath_pool_t;

ip4_address_t
nat_slowpath_pool_get_address(u32 vrf_id, ip4_address_t *ip);

#endif
