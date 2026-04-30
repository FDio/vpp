/* SPDX-License-Identifier: Apache-2.0 */
/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
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
#include <vppinfra/bihash_16_8.h>
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
  /* depend on the type and length. */
  u8 value[0];
} pppoe_tag_header_t;

/* Max PPPoE payload: 1500 (standard MTU) + 8 (PPPoE header) = 1508 */
#define ETH_JUMBO_LEN 1508
/* Default PPPoE session MTU for standard Ethernet: 1500 - 8 (PPPoE overhead) = 1492.
 * Ref: RFC 2516 section 7.  The actual interface MTU is set by pppd during LCP
 * negotiation and may differ for jumbo frames or ISP-specific configurations. */
#define PPPOECLIENT_MTU_DEFAULT 1492

/* PPP Protocol Numbers */
#ifndef PPP_LCP
#define PPP_LCP 0xc021
#endif
#ifndef PPP_PAP
#define PPP_PAP 0xc023
#endif
#ifndef PPP_CHAP
#define PPP_CHAP 0xc223
#endif
#ifndef PPP_IPCP
#define PPP_IPCP 0x8021
#endif
#ifndef PPP_IPV6CP
#define PPP_IPV6CP 0x8057
#endif
#ifndef PPP_IP
#define PPP_IP 0x0021
#endif
#ifndef PPP_IPV6
#define PPP_IPV6 0x0057
#endif

/* LCP Packet Types */
#define LCP_CONFIGURE_REQUEST 1
#define LCP_CONFIGURE_ACK     2
#define LCP_CONFIGURE_NAK     3
#define LCP_CONFIGURE_REJECT  4
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

#define PPPOE_VER_TYPE	   0x11
#define PPPOE_PADI	   0x9
#define PPPOE_PADO	   0x7
#define PPPOE_PADR	   0x19
#define PPPOE_PADS	   0x65
#define PPPOE_PADT	   0xa7
#define PPPOE_SESSION_DATA 0x0

typedef void parse_func (u16 type, u16 len, unsigned char *data, void *extra);

/* PPPoE Tags */
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
} pppoeclient_state_t;

typedef enum
{
  PPPOECLIENT_CONTROL_MATCH_NONE = 0,
  PPPOECLIENT_CONTROL_MATCH_HOST_UNIQ = 1,
  PPPOECLIENT_CONTROL_MATCH_AC_NAME = 2,
  PPPOECLIENT_CONTROL_MATCH_SERVICE_NAME = 3,
  PPPOECLIENT_CONTROL_MATCH_ANY = 4,
  PPPOECLIENT_CONTROL_MATCH_COOKIE = 5,
  PPPOECLIENT_CONTROL_MATCH_UNIQUE = 6,
  PPPOECLIENT_CONTROL_MATCH_SESSION = 7,
  PPPOECLIENT_CONTROL_MATCH_AC_AND_SERVICE = 8,
  PPPOECLIENT_CONTROL_MATCH_AC_MAC = 9,
  PPPOECLIENT_CONTROL_MATCH_AC_MAC_AND_SERVICE = 10,
  PPPOECLIENT_CONTROL_MATCH_COOKIE_AND_SERVICE = 11,
} pppoeclient_control_match_reason_t;

typedef enum
{
  PPPOECLIENT_CONTROL_DISPOSITION_NONE = 0,
  PPPOECLIENT_CONTROL_DISPOSITION_ACCEPTED = 1,
  PPPOECLIENT_CONTROL_DISPOSITION_IGNORED = 2,
  PPPOECLIENT_CONTROL_DISPOSITION_ERROR = 3,
  PPPOECLIENT_CONTROL_DISPOSITION_ORPHAN = 4,
} pppoeclient_control_disposition_t;

typedef enum
{
  PPPOECLIENT_CONTROL_CLIENT_STATE_UNKNOWN = 0,
  PPPOECLIENT_CONTROL_CLIENT_STATE_DISCOVERY = 1,
  PPPOECLIENT_CONTROL_CLIENT_STATE_REQUEST = 2,
  PPPOECLIENT_CONTROL_CLIENT_STATE_SESSION = 3,
} pppoeclient_control_client_state_t;

#define PPPOECLIENT_CONTROL_HISTORY_LEN	     8
#define PPPOECLIENT_CONTROL_AC_NAME_LEN	     32
#define PPPOECLIENT_CONTROL_SERVICE_NAME_LEN 32
#define PPPOECLIENT_CONTROL_COOKIE_LEN	     64
#define PPPOECLIENT_CONTROL_RAW_TAGS_LEN     128

typedef struct
{
  u32 sw_if_index;
  f64 event_time;
  u32 host_uniq;
  u16 session_id;
  u16 cookie_len;
  u16 error_tag_type;
  u8 code;
  u8 client_state;
  u8 disposition;
  u8 parse_error;
  u8 match_reason;
  u8 match_score;
  u8 candidate_count;
  u8 top_match_count;
  u8 top_match_reason;
  u8 top_match_score;
  u8 host_uniq_present;
  u8 ac_name_len;
  u8 ac_name_truncated;
  u8 service_name_len;
  u8 service_name_truncated;
  u8 cookie_value_len;
  u8 cookie_value_truncated;
  u8 raw_tags_len;
  u8 raw_tags_truncated;
  u8 peer_mac[6];
  u8 ac_name[PPPOECLIENT_CONTROL_AC_NAME_LEN];
  u8 service_name[PPPOECLIENT_CONTROL_SERVICE_NAME_LEN];
  u8 cookie_value[PPPOECLIENT_CONTROL_COOKIE_LEN];
  u8 raw_tags[PPPOECLIENT_CONTROL_RAW_TAGS_LEN];
} pppoeclient_control_event_t;

typedef struct
{
  u32 matched_events;
  u32 min_age_msec;
  u32 max_age_msec;
  u32 pado_count;
  u32 pads_count;
  u32 padt_count;
  u32 accepted_count;
  u32 ignored_count;
  u32 error_count;
  u32 orphan_count;
  u32 discovery_state_count;
  u32 request_state_count;
  u32 session_state_count;
  u32 unknown_state_count;
  u32 parse_error_count;
  u32 host_uniq_present_count;
  u32 cookie_present_count;
  u32 service_name_count;
  u32 ac_name_count;
  u32 raw_tags_count;
  u32 error_tag_count;
  u32 service_name_truncated_count;
  u32 ac_name_truncated_count;
  u32 cookie_value_truncated_count;
  u32 raw_tags_truncated_count;
  u32 match_none_count;
  u32 match_host_uniq_count;
  u32 match_ac_name_count;
  u32 match_service_name_count;
  u32 match_any_count;
  u32 match_cookie_count;
  u32 match_unique_count;
  u32 match_session_count;
  u32 match_ac_and_service_count;
  u32 match_ac_mac_count;
  u32 match_ac_mac_and_service_count;
  u32 match_cookie_and_service_count;
  u32 top_match_none_count;
  u32 top_match_host_uniq_count;
  u32 top_match_ac_name_count;
  u32 top_match_service_name_count;
  u32 top_match_any_count;
  u32 top_match_cookie_count;
  u32 top_match_unique_count;
  u32 top_match_session_count;
  u32 top_match_ac_and_service_count;
  u32 top_match_ac_mac_count;
  u32 top_match_ac_mac_and_service_count;
  u32 top_match_cookie_and_service_count;
  u32 ambiguous_events_count;
  u32 max_match_score;
  u32 max_candidate_count;
  u32 max_top_match_score;
  u32 max_top_match_count;
} pppoeclient_control_history_summary_t;

void pppoeclient_control_history_summary_accumulate (pppoeclient_control_history_summary_t *summary,
						     pppoeclient_control_event_t *event);
void pppoeclient_clear_control_history (pppoeclient_control_event_t *history, u8 *count, u8 *next);

typedef struct
{
  /* pppoe client is bounded to an ethernet interface, use it and the following tag as hash key */
  u32 sw_if_index;
  u32 pppox_sw_if_index;
  u32 hw_if_index;
  u32 hw_output_next_index;
  /* we may support multiple pppoe session using 1 ethernet interface, the use pppoe rfc host-uniq
     tag to mix key */
  u32 host_uniq;
  u16 session_id;
  u8 ac_mac_address[6];

  /* AC-Cookie octets echoed back verbatim in PADR/PADS, allocated lazily from
   * the PADO parser.  Holds only the tag value (no TLV header); the emit path
   * wraps it with an AC-Cookie header.  vec_free'd by
   * pppoeclient_client_free_resources.  Previously an embedded 1508-byte tag
   * struct burned ~1.5 KB per client even for typical <64-byte cookies. */
  u8 *cookie_value;

  pppoeclient_state_t state;
  u32 retry_count;
  f64 next_transmit;

  u32 pppox_hw_if_index;

  u32 mtu;
  u32 mru;
  u32 timeout;

  /* Pointers (8-byte aligned on 64-bit) grouped together */
  u8 *ac_name;	      /* AC-Name from PADO */
  u8 *ac_name_filter; /* Required AC-Name; empty means accept any AC */
  u8 *service_name;   /* Requested Service-Name; empty means "any" */
  u8 *username;
  u8 *password;

  /* IPv4 state */
  u32 ip4_addr;
  u32 ip4_netmask;
  u32 ip4_gateway;
  u32 dns1;
  u32 dns2;

  /* IPv6 state (16-byte aligned) */
  ip6_address_t ip6_addr;
  ip6_address_t ip6_peer_addr;
  u8 ipv6_prefix_len;

  /* Pack all u8 flags/state together to minimise padding */
  u8 use_peer_dns;
  u8 use_peer_route4; /* add-default-route4: add IPv4 default route */
  u8 use_peer_route6; /* add-default-route6: add IPv6 default route */
  u8 use_peer_ipv6;
  u8 lcp_state;
  u8 lcp_id;
  u8 lcp_nak;
  u8 ipcp_state;
  u8 ipcp_id;
  u8 ipv6cp_state;
  u8 ipv6cp_id;

  /* Last discovery error tag seen (0 = none) */
  u32 discovery_error;

  /* Session statistics */
  u32 total_reconnects;		 /* lifetime reconnect count */
  u32 consecutive_auth_failures; /* reset when a PPPoE session is (re)established */
  u8 last_disconnect_reason; /* 0=none, 1=PADT, 2=echo-timeout, 3=admin, 4=ppp-dead, 5=auth-fail */
  u8 control_history_count;
  u8 control_history_next;
  u8 stats_pad[1];
  f64 session_start_time; /* vlib_time_now when SESSION state entered */

  /* Session-duration accounting.  last_session_duration_seconds is the length
   * of the most recent SESSION lifetime (0 if we've never been in SESSION);
   * total_session_seconds is the cumulative sum across every SESSION this
   * client has held since it was added.  Updated in pppoeclient_teardown_session. */
  u32 last_session_duration_seconds;
  u64 total_session_seconds;

  /* Per-client circular buffer of the last PPPOECLIENT_CONTROL_HISTORY_LEN
   * PADO/PADS/PADT events.  Lazily allocated on the first recorded event so
   * provisioned-but-inactive clients do not burn ~3 KB of unused slots.  An
   * embedded fixed-size array would inflate every pppoeclient_t past 4 KB
   * just to hold slots that may never see a packet.  All readers are
   * guarded by control_history_count > 0, which in turn implies the vec has
   * been allocated. */
  pppoeclient_control_event_t *control_history;
} pppoeclient_t;

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

/*
 * The size of pppoe client table
 */
#define PPPOE_CLIENT_NUM_BUCKETS 128
#define PPPOE_CLIENT_MEMORY_SIZE (64 << 20)
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
} pppoeclient_key_t;
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
} pppoeclient_result_t;
/*
 * The PPPoE client session key tracks ingress interface + peer AC MAC
 * + PPPoE session id so multiple sessions do not alias each other.
 */
typedef struct
{
  union
  {
    struct
    {
      u16 session_id;
      u16 rsv0;
      u32 sw_if_index;
      u8 ac_mac[6];
      u16 rsv1;
    } fields;
    u64 raw[2];
  };
} pppoeclient_session_key_t;

typedef struct
{
  /* For DP: vector of clients, */
  pppoeclient_t *clients;

  /* For CP:  vector of CP path */
  clib_bihash_8_8_t client_table;
  /* Session hash table share same lookup result structure. */
  clib_bihash_16_8_t session_table;

  /* Mapping from pppox sw_if_index to client index */
  u32 *client_index_by_pppox_sw_if_index;

  /* Access-interface refcounts for pppoeclient-dispatch */
  u32 *dispatch_refcount_by_sw_if_index;

  /* API message ID base */
  u16 msg_id_base;

  /* Packet template for PPPoE discovery packets */
  vlib_packet_template_t packet_template;

  /* Recently received discovery/control packets that could not be
   * attributed to a specific client. */
  u8 orphan_control_history_count;
  u8 orphan_control_history_next;
  pppoeclient_control_event_t orphan_control_history[PPPOECLIENT_CONTROL_HISTORY_LEN];

  /* Auth-fail backoff jitter fraction in [0, 0.5]. 0 disables jitter and
   * keeps the schedule deterministic (30/60/120/240/300 s); non-zero spreads
   * each cooldown by +/- fraction * cooldown so fleets of clients kicked by
   * the same BAS don't retry in lockstep. */
  f64 auth_backoff_jitter_fraction;
  u32 rng_seed;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

} pppoeclient_main_t;

#define EVENT_PPPOE_CLIENT_WAKEUP 1

/* last_disconnect_reason values */
#define PPPOECLIENT_DISCONNECT_NONE	    0
#define PPPOECLIENT_DISCONNECT_PADT	    1
#define PPPOECLIENT_DISCONNECT_ECHO_TIMEOUT 2
#define PPPOECLIENT_DISCONNECT_ADMIN	    3
#define PPPOECLIENT_DISCONNECT_PPP_DEAD	    4
#define PPPOECLIENT_DISCONNECT_AUTH_FAIL    5

/* Exponential auth-failure backoff: 30s base, double each consecutive denial,
 * cap at 300s. Kicks in only when pppox signals an authentication teardown;
 * all other reasons fall back to the regular PPPOECLIENT_REDISCOVERY_COOLDOWN. */
#define PPPOECLIENT_AUTH_BACKOFF_BASE_SEC 30.0
#define PPPOECLIENT_AUTH_BACKOFF_CAP_SEC  300.0

extern pppoeclient_main_t pppoeclient_main;

extern vlib_node_registration_t pppoeclient_discovery_input_node;
extern vlib_node_registration_t pppoeclient_session_input_node;
extern vlib_node_registration_t pppoeclient_session_output_node;

typedef struct
{
  u8 is_add;
  u32 sw_if_index;
  u32 host_uniq;
  /* Vector fields below are caller-owned: vnet_pppoeclient_add_del never
   * steals or frees them.  The callee vec_dup's whatever it needs to keep. */
  u8 *ac_name_filter;
  u8 *service_name;
  /* Optional operator-supplied name for the PPPoX virtual interface
   * (e.g. "wan0", "ppp0"). Empty / NULL falls back to "pppoxN". */
  u8 *custom_ifname;
} vnet_pppoeclient_add_del_args_t;

int vnet_pppoeclient_add_del (vnet_pppoeclient_add_del_args_t *, u32 *);

int consume_pppoe_discovery_pkt (u32, vlib_buffer_t *, pppoe_header_t *);
void pppoeclient_save_session_to_file (pppoeclient_t *c);

void pppoeclient_open_session (u32 client_index);
void pppoeclient_restart_session (u32 client_index);
void pppoeclient_restart_session_with_reason (u32 client_index, u8 disconnect_reason);
void pppoeclient_stop_session (u32 client_index);
int sync_pppoe_client_live_auth (pppoeclient_t *c);
int sync_pppoe_client_live_default_route4 (pppoeclient_t *c);
int sync_pppoe_client_live_default_route6 (pppoeclient_t *c);
int sync_pppoe_client_live_use_peer_dns (pppoeclient_t *c);

always_inline u64
pppoeclient_make_key (u32 sw_if_index, u32 host_uniq)
{
  u64 temp;

  temp = ((u64) sw_if_index) << 32 | host_uniq;

  return temp;
}

static_always_inline void
pppoeclient_lookup_1 (clib_bihash_8_8_t *client_table, u32 sw_if_index, u32 host_uniq,
		      pppoeclient_result_t *result0)
{
  pppoeclient_key_t key0;
  /* set up key */
  key0.raw = pppoeclient_make_key (sw_if_index, host_uniq);

  /* Do a regular client table lookup */
  clib_bihash_kv_8_8_t kv;

  kv.key = key0.raw;
  kv.value = ~0ULL;
  clib_bihash_search_inline_8_8 (client_table, &kv);
  result0->raw = kv.value;
}

static_always_inline void
pppoeclient_update_1 (clib_bihash_8_8_t *client_table, u32 sw_if_index, u32 host_uniq,
		      pppoeclient_result_t *result0)
{
  pppoeclient_key_t key0;
  /* set up key */
  key0.raw = pppoeclient_make_key (sw_if_index, host_uniq);

  /* Update the entry */
  clib_bihash_kv_8_8_t kv;

  kv.key = key0.raw;
  kv.value = result0->raw;
  clib_bihash_add_del_8_8 (client_table, &kv, 1 /* is_add */);
}

static_always_inline void
pppoeclient_delete_1 (clib_bihash_8_8_t *client_table, u32 sw_if_index, u32 host_uniq)
{
  pppoeclient_key_t key0;
  /* set up key */
  key0.raw = pppoeclient_make_key (sw_if_index, host_uniq);

  /* Update the entry */
  clib_bihash_kv_8_8_t kv;

  kv.key = key0.raw;
  clib_bihash_add_del_8_8 (client_table, &kv, 0 /* is_add */);
}

static_always_inline void
pppoeclient_make_session_key (pppoeclient_session_key_t *key0, u32 sw_if_index, const u8 *ac_mac,
			      u16 session_id)
{
  clib_memset (key0, 0, sizeof (*key0));
  key0->fields.session_id = session_id;
  key0->fields.sw_if_index = sw_if_index;
  clib_memcpy_fast (key0->fields.ac_mac, ac_mac, sizeof (key0->fields.ac_mac));
}

static_always_inline void
pppoeclient_lookup_session_1 (clib_bihash_16_8_t *session_table, u32 sw_if_index, const u8 *ac_mac,
			      u16 session_id, pppoeclient_result_t *result0)
{
  pppoeclient_session_key_t key0;
  /* set up key */
  pppoeclient_make_session_key (&key0, sw_if_index, ac_mac, session_id);

  /* Do a regular client table lookup */
  clib_bihash_kv_16_8_t kv;

  kv.key[0] = key0.raw[0];
  kv.key[1] = key0.raw[1];
  kv.value = ~0ULL;
  clib_bihash_search_inline_16_8 (session_table, &kv);
  result0->raw = kv.value;
}

static_always_inline void
pppoeclient_update_session_1 (clib_bihash_16_8_t *session_table, u32 sw_if_index, const u8 *ac_mac,
			      u16 session_id, pppoeclient_result_t *result0)
{
  pppoeclient_session_key_t key0;
  /* set up key */
  pppoeclient_make_session_key (&key0, sw_if_index, ac_mac, session_id);

  /* Update the entry */
  clib_bihash_kv_16_8_t kv;

  kv.key[0] = key0.raw[0];
  kv.key[1] = key0.raw[1];
  kv.value = result0->raw;
  clib_bihash_add_del_16_8 (session_table, &kv, 1 /* is_add */);
}

static_always_inline void
pppoeclient_delete_session_1 (clib_bihash_16_8_t *session_table, u32 sw_if_index, const u8 *ac_mac,
			      u16 session_id)
{
  pppoeclient_session_key_t key0;
  /* set up key */
  pppoeclient_make_session_key (&key0, sw_if_index, ac_mac, session_id);

  /* Update the entry */
  clib_bihash_kv_16_8_t kv;

  kv.key[0] = key0.raw[0];
  kv.key[1] = key0.raw[1];
  clib_bihash_add_del_16_8 (session_table, &kv, 0 /* is_add */);
}

static_always_inline pppoeclient_t *
pppoeclient_get_client_by_pppox_sw_if_index (pppoeclient_main_t *pem, u32 pppox_sw_if_index,
					     u32 *client_index)
{
  u32 index;

  if (client_index)
    *client_index = ~0;

  if (pppox_sw_if_index == ~0 ||
      pppox_sw_if_index >= vec_len (pem->client_index_by_pppox_sw_if_index))
    return 0;

  index = pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index];
  if (index == ~0 || pool_is_free_index (pem->clients, index))
    return 0;

  if (client_index)
    *client_index = index;

  return pool_elt_at_index (pem->clients, index);
}

static_always_inline u16
pppoeclient_get_l2_encap_len (vnet_main_t *vnm, u32 sw_if_index)
{
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);

  if (sw->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      if (sw->sub.eth.flags.two_tags == 1)
	return sizeof (ethernet_header_t) + 2 * sizeof (ethernet_vlan_header_t);
      if (sw->sub.eth.flags.one_tag == 1)
	return sizeof (ethernet_header_t) + sizeof (ethernet_vlan_header_t);
    }

  return sizeof (ethernet_header_t);
}

static_always_inline pppoe_header_t *
pppoeclient_push_l2_header (vnet_main_t *vnm, u32 sw_if_index, vlib_buffer_t *b, u16 ethertype,
			    const u8 *src_address, const u8 *dst_address)
{
  ethernet_header_t *eth;
  ethernet_vlan_header_t *vlan;
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);

  vlib_buffer_advance (b, -((word) pppoeclient_get_l2_encap_len (vnm, sw_if_index)));
  eth = vlib_buffer_get_current (b);

  clib_memcpy (eth->src_address, src_address, sizeof (eth->src_address));
  clib_memcpy (eth->dst_address, dst_address, sizeof (eth->dst_address));

  if (sw->type == VNET_SW_INTERFACE_TYPE_SUB && sw->sub.eth.flags.two_tags == 1)
    {
      ethernet_vlan_header_t *outer, *inner;
      outer = (ethernet_vlan_header_t *) (eth + 1);
      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      outer->priority_cfi_and_id = clib_host_to_net_u16 (sw->sub.eth.outer_vlan_id);
      outer->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      inner = outer + 1;
      inner->priority_cfi_and_id = clib_host_to_net_u16 (sw->sub.eth.inner_vlan_id);
      inner->type = clib_host_to_net_u16 (ethertype);
      return (pppoe_header_t *) (inner + 1);
    }

  if (sw->type == VNET_SW_INTERFACE_TYPE_SUB && sw->sub.eth.flags.one_tag == 1)
    {
      vlan = (ethernet_vlan_header_t *) (eth + 1);
      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      vlan->priority_cfi_and_id = clib_host_to_net_u16 (sw->sub.eth.outer_vlan_id);
      vlan->type = clib_host_to_net_u16 (ethertype);
      return (pppoe_header_t *) (vlan + 1);
    }

  eth->type = clib_host_to_net_u16 (ethertype);
  return (pppoe_header_t *) (eth + 1);
}

static_always_inline u8
pppoeclient_get_l2_info (vlib_buffer_t *b, ethernet_header_t **eth_hdr, pppoe_header_t **pppoe_hdr,
			 u16 *ethertype, u16 *l2_hdr_len)
{
  ethernet_header_t *eth = vlib_buffer_get_current (b);
  u16 type, hdr_len;

  if (b->current_length < sizeof (ethernet_header_t))
    return 0;

  type = clib_net_to_host_u16 (eth->type);
  hdr_len = sizeof (*eth);

  if (ethernet_frame_is_tagged (type))
    {
      if (b->current_length < hdr_len + sizeof (ethernet_vlan_header_t))
	return 0;
      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eth + 1);
      type = clib_net_to_host_u16 (vlan->type);
      hdr_len += sizeof (*vlan);
      /* QinQ: second VLAN tag */
      if (ethernet_frame_is_tagged (type))
	{
	  if (b->current_length < hdr_len + sizeof (ethernet_vlan_header_t))
	    return 0;
	  vlan = (ethernet_vlan_header_t *) (((u8 *) eth) + hdr_len);
	  type = clib_net_to_host_u16 (vlan->type);
	  hdr_len += sizeof (*vlan);
	}
    }

  if (eth_hdr)
    *eth_hdr = eth;
  if (pppoe_hdr)
    *pppoe_hdr = (pppoe_header_t *) (((u8 *) eth) + hdr_len);
  if (ethertype)
    *ethertype = type;
  if (l2_hdr_len)
    *l2_hdr_len = hdr_len;

  return type == ETHERNET_TYPE_PPPOE_DISCOVERY || type == ETHERNET_TYPE_PPPOE_SESSION;
}

#endif /* _PPPOECLIENT_H */

/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
