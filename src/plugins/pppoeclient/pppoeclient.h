/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 RaydoNetworks.
 *------------------------------------------------------------------
 */

#ifndef _PPPOECLIENT_H
#define _PPPOECLIENT_H

#include <vnet/plugin/plugin.h>
#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>
#include <vlib/buffer_funcs.h>

typedef struct
{
  u8 ver_type;
  u8 code;
  u16 session_id;
  u16 length;
} pppoe_header_t;

typedef struct
{
  u16 type;
  u16 length;
  // depend on the type and length.
  u8 value[0];
} pppoe_tag_header_t;

#define ETH_JUMBO_LEN 1508

/* PPP Protocol Numbers */
#define PPP_LCP	   0xc021
#define PPP_PAP	   0xc023
#define PPP_CHAP   0xc025
#define PPP_IPCP   0x8021
#define PPP_IPV6CP 0x8057
#define PPP_IP	   0x0021
#define PPP_IPV6   0x0057

/* LCP Packet Types */
#define LCP_CONFIGURE_REQUEST 1
#define LCP_CONFIGURE_ACK     2
#define LCP_CONFIGURE_NAK     3
#define LCP_TERMINATE_REQUEST 5
#define LCP_TERMINATE_ACK     6
#define LCP_ECHO_REQUEST      9
#define LCP_ECHO_REPLY	      10

/* LCP Options */
#define LCP_OPTION_MRU	 1
#define LCP_OPTION_AUTH	 3
#define LCP_OPTION_MAGIC 5

/* LCP Packet Header */
typedef struct
{
  u8 code;
  u8 id;
  u16 length;
} lcp_header_t;

/* PAP Packet Header */
typedef struct
{
  u8 code;
  u8 id;
  u16 length;
} pap_header_t;

/* IPCP Packet Header */
typedef struct
{
  u8 code;
  u8 id;
  u16 length;
} ipcp_header_t;

typedef struct
{
  u16 type;   // net order for direct send.
  u16 length; // net order for direct send.
  // depend on the type and length.
  u8 value[ETH_JUMBO_LEN];
} pppoe_tag_t;

#define PPPOE_VER_TYPE	   0x11
#define PPPOE_PADI	   0x9
#define PPPOE_PADO	   0x7
#define PPPOE_PADR	   0x19
#define PPPOE_PADS	   0x65
#define PPPOE_PADT	   0xa7
#define PPPOE_SESSION_DATA 0x0

typedef void parse_func (u16 type, u16 len, unsigned char *data, void *extra);

// PPPoE Tags
#define PPPOE_TAG_END_OF_LIST	     0x0000
#define PPPOE_TAG_SERVICE_NAME	     0x0101
#define PPPOE_TAG_AC_NAME	     0x0102
#define PPPOE_TAG_HOST_UNIQ	     0x0103
#define PPPOE_TAG_AC_COOKIE	     0x0104
#define PPPOE_TAG_VENDOR_SPECIFIC    0x0105
#define PPPOE_TAG_RELAY_SESSION_ID   0x0110
#define PPPOE_TAG_PPP_MAX_PAYLOAD    0x0120
#define PPPOE_TAG_SERVICE_NAME_ERROR 0x0201
#define PPPOE_TAG_AC_SYSTEM_ERROR    0x0202
#define PPPOE_TAG_GENERIC_ERROR	     0x0203

#define foreach_pppoe_client_state                                                                 \
  _ (PPPOE_CLIENT_DISCOVERY)                                                                       \
  _ (PPPOE_CLIENT_REQUEST)                                                                         \
  _ (PPPOE_CLIENT_SESSION)

typedef enum
{
#define _(a) a,
  foreach_pppoe_client_state
#undef _
} pppoe_client_state_t;

typedef struct
{
  /* pppoe client is bounded to an ethernet interface, use it and the following tag as hash key */
  u32 sw_if_index;
  u32 hw_if_index;
  u32 hw_output_next_index;
  /* we may support multiple pppoe session using 1 ethernet interface, the use pppoe rfc host-uniq
     tag to mix key */
  u32 host_uniq;

  pppoe_tag_t cookie; // we have to send this if we get it.

  pppoe_client_state_t state;
  /* State machine retry counter */
  u32 retry_count;
  /* Send next pkt at this time */
  f64 next_transmit;
  u8 ac_mac_address[6];
  u8 *ac_name; /* AC-Name from PADO */
  u16 session_id;

  /* pppox intf index */
  u32 pppox_sw_if_index;
  u32 pppox_hw_if_index;

  /* Authentication */
  u8 *username;
  u8 *password;
  u32 mtu;
  u32 mru;
  u32 timeout;

  /* Options */
  u8 use_peer_dns;
  u8 use_peer_route4; /* add-default-route4: add IPv4 default route */
  u8 use_peer_route6; /* add-default-route6: add IPv6 default route */
  CLIB_UNUSED (u32 ip4_addr);
  CLIB_UNUSED (u32 ip4_netmask);
  u32 ip4_gateway;
  u32 dns1;
  u32 dns2;

  /* LCP state */
  u8 lcp_state;
  u8 lcp_id;
  u8 lcp_nak;

  /* IPCP state */
  u8 ipcp_state;
  u8 ipcp_id;

  /* IPv6 options (IPv6CP) */
  u8 use_peer_ipv6;
  u8 ipv6_prefix_len;
  ip6_address_t ip6_addr;
  ip6_address_t ip6_peer_addr;
  /* IPv6CP state */
  u8 ipv6cp_state;
  u8 ipv6cp_id;
} pppoe_client_t;

typedef enum
{
#define pppoeclient_error(n, s) PPPOECLIENT_ERROR_##n,
#include <pppoeclient/pppoeclient_error.def>
#undef pppoeclient_error
  PPPOECLIENT_N_ERROR,
} pppoeclient_input_error_t;

#define foreach_pppoeclient_discovery_input_next _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) PPPOECLIENT_DISCOVERY_INPUT_NEXT_##s,
  foreach_pppoeclient_discovery_input_next
#undef _
    PPPOECLIENT_DISCOVERY_INPUT_N_NEXT,
} pppoeclient_discovery_input_next_t;

#define foreach_pppoeclient_session_input_next                                                     \
  _ (IP4_INPUT, "ip4-input")                                                                       \
  _ (IP6_INPUT, "ip6-input")                                                                       \
  _ (PPPOX_INPUT, "pppox-input")                                                                   \
  _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) PPPOECLIENT_SESSION_INPUT_NEXT_##s,
  foreach_pppoeclient_session_input_next
#undef _
    PPPOECLIENT_SESSION_INPUT_N_NEXT,
} pppoeclient_session_input_next_t;

#define foreach_pppoeclient_session_output_next _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) PPPOECLIENT_SESSION_OUTPUT_NEXT_##s,
  foreach_pppoeclient_session_output_next
#undef _
    PPPOECLIENT_SESSION_OUTPUT_N_NEXT,
} pppoeclient_session_output_next_t;

#define MTU		     1500
#define MTU_BUFFERS	     ((MTU + VLIB_BUFFER_DATA_SIZE - 1) / VLIB_BUFFER_DATA_SIZE)
#define NUM_BUFFERS_TO_ALLOC 32

/*
 * The size of pppoe client table
 */
#define PPPOE_CLIENT_NUM_BUCKETS 128
#define PPPOE_CLIENT_MEMORY_SIZE 64 << 20
/*
 * The PPPoE client key is the sw if index and host uniq
 */
typedef struct
{
  union
  {
    struct
    {
      u32 sw_if_index;
      u32 host_uniq;
    } fields;
    struct
    {
      u32 w0;
      u32 w1;
    } words;
    u64 raw;
  };
} pppoe_client_key_t;
/*
 * The PPPoE client results
 */
typedef struct
{
  union
  {
    struct
    {
      u32 client_index;
      u32 rsved;
    } fields;
    u64 raw;
  };
} pppoe_client_result_t;
/*
 * The PPPoE client session key is the session id
 */
typedef struct
{
  union
  {
    struct
    {
      u16 session_id;
      u16 rsv0;
      u32 rsv1;
    } fields;
    struct
    {
      u32 w0;
      u32 w1;
    } words;
    u64 raw;
  };
} pppoe_client_session_key_t;
typedef struct
{
  /* For DP: vector of clients, */
  pppoe_client_t *clients;

  /* For CP:  vector of CP path */
  BVT (clib_bihash) client_table;
  // Session hash table share same lookup result structure.
  BVT (clib_bihash) session_table;

  /* Mapping from pppox sw_if_index to client index */
  u32 *client_index_by_pppox_sw_if_index;

  /* API message ID base */
  u16 msg_id_base;

  /* Packet template for PPPoE discovery packets */
  vlib_packet_template_t packet_template;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

} pppoeclient_main_t;

#define EVENT_PPPOE_CLIENT_WAKEUP 1

extern pppoeclient_main_t pppoeclient_main;

extern vlib_node_registration_t pppoeclient_discovery_input_node;
extern vlib_node_registration_t pppoeclient_session_input_node;
extern vlib_node_registration_t pppoeclient_session_output_node;

typedef struct
{
  u8 is_add;
  u32 sw_if_index;
  u32 host_uniq;
} vnet_pppoe_add_del_client_args_t;

int vnet_pppoe_add_del_client (vnet_pppoe_add_del_client_args_t *, u32 *);

int consume_pppoe_discovery_pkt (u32, vlib_buffer_t *, pppoe_header_t *);

always_inline u64
pppoeclient_make_key (u32 sw_if_index, u32 host_uniq)
{
  u64 temp;

  temp = ((u64) sw_if_index) << 32 | host_uniq;

  return temp;
}

static_always_inline void
pppoeclient_lookup_1 (BVT (clib_bihash) * client_table, u32 sw_if_index, u32 host_uniq,
		      pppoe_client_result_t *result0)
{
  pppoe_client_key_t key0;
  /* set up key */
  key0.raw = pppoeclient_make_key (sw_if_index, host_uniq);

  /* Do a regular client table lookup */
  BVT (clib_bihash_kv) kv;

  kv.key = key0.raw;
  kv.value = ~0ULL;
  BV (clib_bihash_search_inline) (client_table, &kv);
  result0->raw = kv.value;
}

static_always_inline void
pppoeclient_update_1 (BVT (clib_bihash) * client_table, u32 sw_if_index, u32 host_uniq,
		      pppoe_client_result_t *result0)
{
  pppoe_client_key_t key0;
  /* set up key */
  key0.raw = pppoeclient_make_key (sw_if_index, host_uniq);

  /* Update the entry */
  BVT (clib_bihash_kv) kv;

  kv.key = key0.raw;
  kv.value = result0->raw;
  BV (clib_bihash_add_del) (client_table, &kv, 1 /* is_add */);
}

static_always_inline void
pppoeclient_delete_1 (BVT (clib_bihash) * client_table, u32 sw_if_index, u32 host_uniq)
{
  pppoe_client_key_t key0;
  /* set up key */
  key0.raw = pppoeclient_make_key (sw_if_index, host_uniq);

  /* Update the entry */
  BVT (clib_bihash_kv) kv;

  kv.key = key0.raw;
  BV (clib_bihash_add_del) (client_table, &kv, 0 /* is_add */);
}

always_inline u64
pppoeclient_make_session_key (u16 session_id)
{
  u64 temp;

  temp = ((u64) 0) << 48 | session_id;

  return temp;
}

static_always_inline void
pppoeclient_lookup_session_1 (BVT (clib_bihash) * session_table, u16 session_id,
			      pppoe_client_result_t *result0)
{
  pppoe_client_session_key_t key0;
  /* set up key */
  key0.raw = pppoeclient_make_session_key (session_id);

  /* Do a regular client table lookup */
  BVT (clib_bihash_kv) kv;

  kv.key = key0.raw;
  kv.value = ~0ULL;
  BV (clib_bihash_search_inline) (session_table, &kv);
  result0->raw = kv.value;
}

static_always_inline void
pppoeclient_update_session_1 (BVT (clib_bihash) * session_table, u16 session_id,
			      pppoe_client_result_t *result0)
{
  pppoe_client_session_key_t key0;
  /* set up key */
  key0.raw = pppoeclient_make_session_key (session_id);

  /* Update the entry */
  BVT (clib_bihash_kv) kv;

  kv.key = key0.raw;
  kv.value = result0->raw;
  BV (clib_bihash_add_del) (session_table, &kv, 1 /* is_add */);
}

static_always_inline void
pppoeclient_delete_session_1 (BVT (clib_bihash) * session_table, u16 session_id)
{
  pppoe_client_session_key_t key0;
  /* set up key */
  key0.raw = pppoeclient_make_session_key (session_id);

  /* Update the entry */
  BVT (clib_bihash_kv) kv;

  kv.key = key0.raw;
  BV (clib_bihash_add_del) (session_table, &kv, 0 /* is_add */);
}

#endif /* _PPPOE_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
