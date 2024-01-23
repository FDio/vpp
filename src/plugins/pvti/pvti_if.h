#ifndef PVTI_IF_H
#define PVTI_IF_H

#include <vnet/interface_funcs.h>

typedef enum
{
  PVTI_PEER_ADDRESS_FIXED = 0,
  PVTI_PEER_ADDRESS_FROM_PAYLOAD
} pvti_peer_address_method_t;

typedef walk_rc_t (*pvti_if_walk_cb_t) (index_t wgi, void *data);
void pvti_if_walk (pvti_if_walk_cb_t fn, void *data);

int pvti_if_create (ip_address_t *local_ip, u16 local_port,
		    ip_address_t *remote_ip, u16 remote_port,
		    pvti_peer_address_method_t peer_address_method,
		    u16 underlay_mtu, u32 underlay_fib_index,
		    u32 *sw_if_indexp);
index_t pvti_if_find_by_sw_if_index (u32 sw_if_index);
index_t pvti_if_find_by_remote_ip4_and_port (ip4_address_t *remote_ip4,
					     u16 remote_port);

index_t pvti_if_find_by_remote_ip_and_port (ip_address_t *remote_ip,
					    u16 remote_port);

int pvti_if_delete (u32 sw_if_index);

u8 *format_pvti_if (u8 *s, va_list *args);

static_always_inline pvti_if_t *
pvti_if_get (index_t pvtii)
{
  if (INDEX_INVALID == pvtii)
    return (NULL);
  return (pool_elt_at_index (pvti_main.if_pool, pvtii));
}

static_always_inline index_t
pvti_if_get_index (pvti_if_t *pvti_if)
{
  return pvti_if - pvti_main.if_pool;
}

#endif
