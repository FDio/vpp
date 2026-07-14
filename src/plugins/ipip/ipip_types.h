#ifndef included_ipip_types_h
#define included_ipip_types_h

#include <vnet/ip/ip46_address.h>
#include <vnet/tunnel/tunnel.h>

typedef enum
{
  IPIP_TRANSPORT_IP4,
  IPIP_TRANSPORT_IP6,
} __clib_packed ipip_transport_t;

typedef enum
{
  IPIP_MODE_P2P = 0,
  IPIP_MODE_P2MP,
  IPIP_MODE_6RD,
} __clib_packed ipip_mode_t;

typedef struct
{
  ip46_address_t src;
  ip46_address_t dst;
  u32 fib_index;
  ipip_transport_t transport;
  ipip_mode_t mode;
  u16 __pad;
} __clib_packed ipip_tunnel_key_t;

STATIC_ASSERT_SIZEOF (ipip_tunnel_key_t, 5 * sizeof (u64));

/**
 * @brief A representation of a IPIP tunnel
 */
typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  ipip_mode_t mode;
  ipip_transport_t transport;
  ip46_address_t tunnel_src;
  ip46_address_t tunnel_dst;
  u32 fib_index;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 dev_instance;		/* Real device instance in tunnel vector */
  u32 user_instance;		/* Instance name being shown to user */
  tunnel_encap_decap_flags_t flags;
  ip_dscp_t dscp;

  struct
  {
    ip6_address_t ip6_prefix;
    ip4_address_t ip4_prefix;
    u8 ip6_prefix_len;
    u8 ip4_prefix_len;
    u8 shift;
    bool security_check;
    u32 ip6_fib_index;
  } sixrd;
} ipip_tunnel_t;

/**
 * Function pointer types — used in ikev2_priv.h
 */
typedef int (*ipip_add_tunnel_fn_t) (ipip_transport_t transport,
                                     u32 instance,
                                     ip46_address_t *src,
                                     ip46_address_t *dst,
                                     u32 fib_index,
                                     tunnel_encap_decap_flags_t flags,
                                     ip_dscp_t dscp,
                                     tunnel_mode_t mode,
                                     u32 *sw_if_indexp);

typedef int (*ipip_del_tunnel_fn_t) (u32 sw_if_index);

typedef ipip_tunnel_t *(*ipip_tunnel_db_find_fn_t) (
  const ipip_tunnel_key_t *key);

#endif /* included_ipip_types_h */