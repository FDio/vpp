#ifndef included_ip6_neighbor_h
#define included_ip6_neighbor_h

#include <vnet/fib/fib_types.h>

typedef struct {
  ip6_address_t ip6_address;
  u32 sw_if_index;
  u32 pad;
} ip6_neighbor_key_t;

typedef struct {
  ip6_neighbor_key_t key;
  u8 link_layer_address[8];
  u16 flags;
#define IP6_NEIGHBOR_FLAG_STATIC (1 << 0)
#define IP6_NEIGHBOR_FLAG_DYNAMIC  (2 << 0)
  u64 cpu_time_last_updated;
  fib_node_index_t fib_entry_index;
} ip6_neighbor_t;

ip6_neighbor_t * ip6_neighbors_entries (u32 sw_if_index);

#endif  /* included_ip6_neighbor_h */
