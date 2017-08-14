/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef VNET_CONTROL_H_
#define VNET_CONTROL_H_

#include <vnet/vnet.h>
#include <vnet/lisp-cp/gid_dictionary.h>
#include <vnet/lisp-cp/lisp_types.h>
#include <vppinfra/timing_wheel.h>

#define NUMBER_OF_RETRIES                   1
#define PENDING_MREQ_EXPIRATION_TIME        3.0	/* seconds */
#define PENDING_MREQ_QUEUE_LEN              5

#define RLOC_PROBING_INTERVAL               60.0

/* when map-registration is enabled "quick registration" takes place first.
   In this mode ETR sends map-register messages at an increased frequency
   until specified message count is reached */
#define QUICK_MAP_REGISTER_MSG_COUNT        5
#define QUICK_MAP_REGISTER_INTERVAL         3.0

/* normal map-register period */
#define MAP_REGISTER_INTERVAL               60.0

/* how many tries until next map-server election */
#define MAX_EXPIRED_MAP_REGISTERS_DEFAULT   3

#define PENDING_MREG_EXPIRATION_TIME        3.0	/* seconds */

/* 24 hours */
#define MAP_REGISTER_DEFAULT_TTL            86400

typedef struct
{
  gid_address_t src;
  gid_address_t dst;
  u32 retries_num;
  f64 time_to_expire;
  u8 is_smr_invoked;
  u64 *nonces;
  u8 to_be_removed;
} pending_map_request_t;

typedef struct
{
  f64 time_to_expire;
} pending_map_register_t;

typedef struct
{
  gid_address_t leid;
  gid_address_t reid;
  u8 is_src_dst;
  locator_pair_t *locator_pairs;
} fwd_entry_t;

typedef struct
{
  gid_address_t leid;
  gid_address_t reid;
} lisp_adjacency_t;

typedef enum
{
  IP4_MISS_PACKET,
  IP6_MISS_PACKET
} miss_packet_type_t;

/* map-server/map-resolver structure */
typedef struct
{
  u8 is_down;
  f64 last_update;
  ip_address_t address;
  char *key;
} lisp_msmr_t;

typedef struct
{
  /* headers */
  u8 data[100];
  u32 length;
  miss_packet_type_t type;
} miss_packet_t;

typedef struct
{
  u8 mac[6];
  u32 ip4;
} lisp_api_l2_arp_entry_t;

typedef enum
{
  MR_MODE_DST_ONLY = 0,
  MR_MODE_SRC_DST,
  _MR_MODE_MAX
} map_request_mode_t;

#define foreach_lisp_flag_bit       \
  _(USE_PETR, "Use Proxy-ETR")                  \
  _(STATS_ENABLED, "Statistics enabled")

typedef enum lisp_flag_bits
{
#define _(sym, str) LISP_FLAG_BIT_##sym,
  foreach_lisp_flag_bit
#undef _
} lisp_flag_bits_e;

typedef enum lisp_flags
{
#define _(sym, str) LISP_FLAG_##sym = 1 << LISP_FLAG_BIT_##sym,
  foreach_lisp_flag_bit
#undef _
} lisp_flags_e;

typedef struct
{
  ip_address_t addr;
  u32 bd;
} lisp_l2_arp_key_t;

typedef struct
{
  u64 nonce;
  u8 is_rloc_probe;
  mapping_t *mappings;
  volatile u8 is_free;
} map_records_arg_t;

typedef struct
{
  u32 flags;

  /* LISP feature status */
  u8 is_enabled;

  /* eid table */
  gid_dictionary_t mapping_index_by_gid;

  /* pool of mappings */
  mapping_t *mapping_pool;

  /* hash map of secret keys by mapping index */
  u8 *key_by_mapping_index;

  /* pool of locators */
  locator_t *locator_pool;

  /* pool of locator-sets */
  locator_set_t *locator_set_pool;

  /* vector of locator-set vectors composed of and indexed by locator index */
  u32 **locator_to_locator_sets;

  /* hash map of locators by name */
  uword *locator_set_index_by_name;

  /* vector of eid index vectors supported and indexed by locator-set index */
  u32 **locator_set_to_eids;

  /* vectors of indexes for local locator-sets and mappings */
  u32 *local_mappings_indexes;
  u32 *local_locator_set_indexes;

  /* hash map of forwarding entries by mapping index */
  u32 *fwd_entry_by_mapping_index;

  /* forwarding entries pool */
  fwd_entry_t *fwd_entry_pool;

  /* hash map keyed by nonce of pending map-requests */
  uword *pending_map_requests_by_nonce;

  /* pool of pending map requests */
  pending_map_request_t *pending_map_requests_pool;

  /* pool of pending map registers */
  pending_map_register_t *pending_map_registers_pool;

  /* hash map of sent map register messages */
  uword *map_register_messages_by_nonce;

  /* vector of map-resolvers */
  lisp_msmr_t *map_resolvers;

  /* vector of map-servers */
  lisp_msmr_t *map_servers;

  /* map resolver address currently being used for sending requests.
   * This has to be an actual address and not an index to map_resolvers vector
   * since the vector may be modified during request resend/retry procedure
   * and break things :-) */
  ip_address_t active_map_resolver;
  ip_address_t active_map_server;

  u8 do_map_resolver_election;
  u8 do_map_server_election;

  /* map-request  locator set index */
  u32 mreq_itr_rlocs;

  /* vni to vrf hash tables */
  uword *table_id_by_vni;
  uword *vni_by_table_id;

  /* vni to bd-index hash tables */
  uword *bd_id_by_vni;
  uword *vni_by_bd_id;

  /* track l2 and l3 interfaces that have been created for vni */
  uword *l2_dp_intf_by_vni;

  /* Proxy ITR map index */
  u32 pitr_map_index;

  /** Proxy ETR map index */
  u32 petr_map_index;

  /* LISP PITR mode */
  u8 lisp_pitr;

  /* mapping index for NSH */
  u32 nsh_map_index;

  /* map request mode */
  u8 map_request_mode;

  /* enable/disable map registering */
  u8 map_registering;

  /* enable/disable rloc-probing */
  u8 rloc_probing;

  /* timing wheel for mappping timeouts */
  timing_wheel_t wheel;

  /** Per thread pool of records shared with thread0 */
  map_records_arg_t **map_records_args_pool;

  /* TTL used for all mappings when registering */
  u32 map_register_ttl;

  /* control variables for map server election */
  u32 max_expired_map_registers;
  u32 expired_map_registers;

  /* commodity */
  ip4_main_t *im4;
  ip6_main_t *im6;
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} lisp_cp_main_t;

/* lisp-gpe control plane */
extern lisp_cp_main_t lisp_control_main;

extern vlib_node_registration_t lisp_cp_input_node;
extern vlib_node_registration_t lisp_cp_lookup_ip4_node;
extern vlib_node_registration_t lisp_cp_lookup_ip6_node;

clib_error_t *lisp_cp_init ();

always_inline lisp_cp_main_t *
vnet_lisp_cp_get_main ()
{
  return &lisp_control_main;
}

void
get_src_and_dst_eids_from_buffer (lisp_cp_main_t * lcm, vlib_buffer_t * b,
				  gid_address_t * src, gid_address_t * dst,
				  u16 type);

typedef struct
{
  u8 is_add;
  union
  {
    u8 *name;
    u32 index;
  };
  locator_t *locators;
  u8 local;
} vnet_lisp_add_del_locator_set_args_t;

int
vnet_lisp_add_del_locator_set (vnet_lisp_add_del_locator_set_args_t * a,
			       u32 * ls_index);
int
vnet_lisp_add_del_locator (vnet_lisp_add_del_locator_set_args_t * a,
			   locator_set_t * ls, u32 * ls_index);

typedef struct
{
  u8 is_add;
  gid_address_t eid;
  u32 locator_set_index;

  u32 ttl;
  u8 action;
  u8 authoritative;

  u8 local;
  u8 is_static;
  u8 *key;
  u8 key_id;
} vnet_lisp_add_del_mapping_args_t;

int
vnet_lisp_map_cache_add_del (vnet_lisp_add_del_mapping_args_t * a,
			     u32 * map_index);
int
vnet_lisp_add_del_local_mapping (vnet_lisp_add_del_mapping_args_t * a,
				 u32 * map_index_result);

int
vnet_lisp_add_mapping (vnet_lisp_add_del_mapping_args_t * a,
		       locator_t * rlocs, u32 * res_map_index,
		       u8 * is_changed);

int vnet_lisp_del_mapping (gid_address_t * eid, u32 * res_map_index);

typedef struct
{
  gid_address_t reid;
  gid_address_t leid;
  u8 is_add;
} vnet_lisp_add_del_adjacency_args_t;

int vnet_lisp_add_del_adjacency (vnet_lisp_add_del_adjacency_args_t * a);

typedef struct
{
  u8 is_add;
  ip_address_t address;
} vnet_lisp_add_del_map_resolver_args_t;

int
vnet_lisp_add_del_map_resolver (vnet_lisp_add_del_map_resolver_args_t * a);
int vnet_lisp_add_del_map_server (ip_address_t * addr, u8 is_add);

clib_error_t *vnet_lisp_enable_disable (u8 is_enabled);
u8 vnet_lisp_enable_disable_status (void);

int vnet_lisp_pitr_set_locator_set (u8 * locator_set_name, u8 is_add);
int vnet_lisp_use_petr (ip_address_t * ip, u8 is_add);

typedef struct
{
  u8 is_add;
  u8 *locator_set_name;
} vnet_lisp_add_del_mreq_itr_rloc_args_t;

int
vnet_lisp_add_del_mreq_itr_rlocs (vnet_lisp_add_del_mreq_itr_rloc_args_t * a);

int vnet_lisp_clear_all_remote_adjacencies (void);

int vnet_lisp_eid_table_map (u32 vni, u32 vrf, u8 is_l2, u8 is_add);
int vnet_lisp_add_del_map_table_key (gid_address_t * eid, char *key,
				     u8 is_add);
int vnet_lisp_set_map_request_mode (u8 mode);
u8 vnet_lisp_get_map_request_mode (void);
lisp_adjacency_t *vnet_lisp_adjacencies_get_by_vni (u32 vni);
int vnet_lisp_rloc_probe_enable_disable (u8 is_enable);
int vnet_lisp_map_register_enable_disable (u8 is_enable);
u8 vnet_lisp_map_register_state_get (void);
u8 vnet_lisp_rloc_probe_state_get (void);
int vnet_lisp_add_del_l2_arp_entry (gid_address_t * key, u8 * mac, u8 is_add);
u32 *vnet_lisp_l2_arp_bds_get (void);
lisp_api_l2_arp_entry_t *vnet_lisp_l2_arp_entries_get_by_bd (u32 bd);
int vnet_lisp_nsh_set_locator_set (u8 * locator_set_name, u8 is_add);
int vnet_lisp_map_register_set_ttl (u32 ttl);
u32 vnet_lisp_map_register_get_ttl (void);
int vnet_lisp_map_register_fallback_threshold_set (u32 value);
u32 vnet_lisp_map_register_fallback_threshold_get (void);

map_records_arg_t *parse_map_reply (vlib_buffer_t * b);

always_inline mapping_t *
lisp_get_petr_mapping (lisp_cp_main_t * lcm)
{
  return pool_elt_at_index (lcm->mapping_pool, lcm->petr_map_index);
}

#endif /* VNET_CONTROL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
