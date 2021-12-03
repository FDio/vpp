/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#ifndef __included_vnet_bonding_node_h__
#define __included_vnet_bonding_node_h__

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface.h>
#include <vnet/hash/hash.h>

#define LACP_FAST_PERIODIC_TIMER        1.0
#define LACP_SHORT_TIMOUT_TIME          (LACP_FAST_PERIODIC_TIMER * 3)
#define LACP_SLOW_PERIODIC_TIMER        30.0
#define LACP_LONG_TIMOUT_TIME           (LACP_SLOW_PERIODIC_TIMER * 3)

#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif

#define BOND_MODULO_SHORTCUT(a) \
  (is_pow2 (a))

#define foreach_bond_mode	    \
  _ (1, ROUND_ROBIN, "round-robin") \
  _ (2, ACTIVE_BACKUP, "active-backup") \
  _ (3, XOR, "xor") \
  _ (4, BROADCAST, "broadcast") \
  _ (5, LACP, "lacp")

typedef enum
{
#define _(v, f, s) BOND_MODE_##f = v,
  foreach_bond_mode
#undef _
} bond_mode_t;

/* configurable load-balances */
#define foreach_bond_lb	  \
  _ (2, L23, "l23", l23)  \
  _ (1, L34 , "l34", l34) \
  _ (0, L2, "l2", l2)

/* load-balance functions implemented in bond-output */
#define foreach_bond_lb_algo			 \
  _ (0, L2, "l2", l2)                            \
  _ (1, L34 , "l34", l34)                        \
  _ (2, L23, "l23", l23)                         \
  _ (3, RR, "round-robin", round_robin)          \
  _ (4, BC, "broadcast", broadcast)              \
  _ (5, AB, "active-backup", active_backup)

typedef enum
{
#define _(v, f, s, p) BOND_LB_##f = v,
  foreach_bond_lb_algo
#undef _
} bond_load_balance_t;

typedef enum
{
  BOND_SEND_GARP_NA = 1,
} bond_send_garp_na_process_event_t;

typedef struct
{
  u32 id;
  u8 hw_addr_set;
  u8 hw_addr[6];
  u8 mode;
  u8 lb;
  u8 numa_only;
  u8 gso;
  /* return */
  u32 sw_if_index;
  int rv;
  clib_error_t *error;
} bond_create_if_args_t;

typedef struct
{
  /* member's sw_if_index */
  u32 member;
  /* bond's sw_if_index */
  u32 group;
  u8 is_passive;
  u8 is_long_timeout;
  /* return */
  int rv;
  clib_error_t *error;
} bond_add_member_args_t;

typedef struct
{
  u32 member;
  /* return */
  int rv;
  clib_error_t *error;
} bond_detach_member_args_t;

typedef struct
{
  u32 sw_if_index;
  u32 weight;
  /* return */
  int rv;
  clib_error_t *error;
} bond_set_intf_weight_args_t;

/** BOND interface details struct */
typedef struct
{
  u32 sw_if_index;
  u32 id;
  u8 interface_name[64];
  u32 mode;
  u32 lb;
  u8 numa_only;
  u32 active_members;
  u32 members;
} bond_interface_details_t;

/** member interface details struct */
typedef struct
{
  u32 sw_if_index;
  u8 interface_name[64];
  u8 is_passive;
  u8 is_long_timeout;
  u8 is_local_numa;
  u32 weight;
  u32 active_members;
} member_interface_details_t;

typedef CLIB_PACKED (struct
		     {
		     u16 system_priority;
		     u8 system[6];
		     u16 key; u16 port_priority; u16 port_number;
		     u8 state;
		     }) lacp_port_info_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 buffers[VLIB_FRAME_SIZE];
  u32 n_buffers;
} bond_per_port_queue_t;

typedef struct
{
  bond_per_port_queue_t *per_port_queue;
  void **data;
} bond_per_thread_data_t;

typedef struct
{
  u8 admin_up;
  u8 mode;
  u8 lb;

  /* the last member index for the rr lb */
  u32 lb_rr_last_index;

  /* Real device instance in interface vector */
  u32 dev_instance;

  /* Interface ID being shown to user */
  u32 id;

  u32 hw_if_index;
  u32 sw_if_index;

  /* Configured members */
  u32 *members;

  /* Members that are in DISTRIBUTING state */
  u32 *active_members;

  lacp_port_info_t partner;
  lacp_port_info_t actor;
  u8 individual_aggregator;

  /* If the flag numa_only is set, it means that only members
     on local numa node works for lacp mode if have at least one,
     otherwise it works as usual. */
  u8 numa_only;
  u8 gso;

  /* How many members on local numa node are there in lacp mode? */
  word n_numa_members;

  u32 group;
  uword *port_number_bitmap;
  u8 use_custom_mac;
  u8 hw_address[6];

  clib_spinlock_t lockp;
  vnet_hash_fn_t hash_func;
} bond_if_t;

typedef struct
{
  u8 persistent_hw_address[6];

  /* neighbor's vlib software interface index */
  u32 sw_if_index;

  /* Neighbor time-to-live (usually 3s) */
  f32 ttl_in_seconds;

  /* 1 = interface is configured with long timeout (60s) */
  u8 is_long_timeout;

  /* 1 = debug is on; 0 = debug is off */
  u8 debug;

  /* tx packet template id for this neighbor */
  u8 packet_template_index;

  /* Info we actually keep about each neighbor */

  /* Jenkins hash optimization: avoid tlv scan, send short keepalive msg */
  u8 last_packet_signature_valid;
  uword last_packet_signature;

  /* last received lacp packet, for the J-hash optimization */
  u8 *last_rx_pkt;

  /* last marker packet */
  u8 *last_marker_pkt;

  /* neighbor vlib hw_if_index */
  u32 hw_if_index;

  /* weight -- valid only for active backup */
  u32 weight;

  /* actor does not initiate the protocol exchange */
  u8 is_passive;

  /* Partner port information */
  lacp_port_info_t partner;
  lacp_port_info_t partner_admin;;

  /* Actor port information */
  lacp_port_info_t actor;
  lacp_port_info_t actor_admin;

  /* Need To Transmit flag */
  u8 ntt;

  /* Link has been established and Aggregate Port is operable */
  u8 port_enabled;

  /* Initialization or reinitialization of the lacp protocol entity */
  u8 begin;

  /* Aggregation Port is operating the lacp */
  u8 lacp_enabled;

  /* MUX to indicate to the Selection Logic wait_while_timer expired */
  u8 ready_n;

  /* Selection Logic indicates al Aggregation Ports attached */
  u8 ready;

  /* Selection Logic selected an Aggregator */
  int selected;

  /* RX machine indicates an Aggregation Port in PORT_DISABLED state */
  u8 port_moved;

  /* timer used to detect whether received protocol information has expired */
  f64 current_while_timer;

  /* timer used to detect actor churn states */
  f64 actor_churn_timer;

  /* time last lacpdu was sent */
  f64 last_lacpdu_sent_time;

  /* time last lacpdu was received */
  f64 last_lacpdu_recd_time;

  /* time last marker pdu was sent */
  f64 last_marker_pdu_sent_time;

  /* time last marker pdu was received */
  f64 last_marker_pdu_recd_time;

  /* timer used to generate periodic transmission */
  f64 periodic_timer;

  /* timer used to detect partner churn states */
  f64 partner_churn_timer;

  /* provides hysteresis before performing an aggregation change */
  f64 wait_while_timer;

  /* Implemention variables, not in the spec */
  int rx_state;
  int tx_state;
  int mux_state;
  int ptx_state;

  /* actor admin key */
  u32 group;

  u32 marker_tx_id;

  u32 bif_dev_instance;

  u8 loopback_port;

  /* bond mode */
  u8 mode;

  /* good lacp pdu received */
  u64 pdu_received;

  /* bad lacp pdu received */
  u64 bad_pdu_received;

  /* pdu sent */
  u64 pdu_sent;

  /* good marker pdu received */
  u64 marker_pdu_received;

  /* bad marker pdu received */
  u64 marker_bad_pdu_received;

  /* pdu sent */
  u64 marker_pdu_sent;

  /* member is numa node */
  u8 is_local_numa;
} member_if_t;

typedef void (*lacp_enable_disable_func) (vlib_main_t * vm, bond_if_t * bif,
					  member_if_t * mif, u8 enable);

typedef struct
{
  u32 partner_state;
  u32 actor_state;
} lacp_stats_t;

typedef struct
{
  /* pool of bonding interfaces */
  bond_if_t *interfaces;

  /* record used interface IDs */
  uword *id_used;

  /* pool of member interfaces */
  member_if_t *neighbors;

  /* rapidly find a bond by vlib software interface index */
  uword *bond_by_sw_if_index;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* lacp plugin is loaded */
  u8 lacp_plugin_loaded;

  lacp_enable_disable_func lacp_enable_disable;

  uword *member_by_sw_if_index;

  bond_per_thread_data_t *per_thread_data;

  lacp_stats_t **stats;
} bond_main_t;

/* bond packet trace capture */
typedef struct
{
  ethernet_header_t ethernet;
  u32 sw_if_index;
  u32 bond_sw_if_index;
} bond_packet_trace_t;

typedef u32 (*load_balance_func) (vlib_main_t * vm,
				  vlib_node_runtime_t * node, bond_if_t * bif,
				  vlib_buffer_t * b0, uword member_count);

typedef struct
{
  load_balance_func load_balance;
} bond_load_balance_func_t;

extern vlib_node_registration_t bond_input_node;
extern vlib_node_registration_t bond_process_node;
extern vnet_device_class_t bond_dev_class;
extern bond_main_t bond_main;

void bond_disable_collecting_distributing (vlib_main_t * vm,
					   member_if_t * mif);
void bond_enable_collecting_distributing (vlib_main_t * vm,
					  member_if_t * mif);
u8 *format_bond_interface_name (u8 * s, va_list * args);

void bond_set_intf_weight (vlib_main_t * vm,
			   bond_set_intf_weight_args_t * args);
void bond_create_if (vlib_main_t * vm, bond_create_if_args_t * args);
int bond_delete_if (vlib_main_t * vm, u32 sw_if_index);
void bond_add_member (vlib_main_t * vm, bond_add_member_args_t * args);
void bond_detach_member (vlib_main_t * vm, bond_detach_member_args_t * args);
int bond_dump_ifs (bond_interface_details_t ** out_bondids);
int bond_dump_member_ifs (member_interface_details_t ** out_memberids,
			  u32 bond_sw_if_index);

static inline uword
unformat_bond_mode (unformat_input_t * input, va_list * args)
{
  u8 *r = va_arg (*args, u8 *);

  if (0);
#define _(v, f, s) else if (unformat (input, s)) *r = BOND_MODE_##f;
  foreach_bond_mode
#undef _
    else
    return 0;

  return 1;
}

static inline u8 *
format_bond_mode (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, f, s) case BOND_MODE_##f: t = (u8 *) s; break;
      foreach_bond_mode
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
}

static inline uword
unformat_bond_load_balance (unformat_input_t * input, va_list * args)
{
  u8 *r = va_arg (*args, u8 *);

  if (0);
#define _(v, f, s, p) else if (unformat (input, s)) *r = BOND_LB_##f;
  foreach_bond_lb
#undef _
    else
    return 0;

  return 1;
}

static inline u8 *
format_bond_load_balance (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, f, s, p) case BOND_LB_##f: t = (u8 *) s; break;
      foreach_bond_lb_algo
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
}

static inline void
bond_register_callback (lacp_enable_disable_func func)
{
  bond_main_t *bm = &bond_main;

  bm->lacp_plugin_loaded = 1;
  bm->lacp_enable_disable = func;
}

static inline bond_if_t *
bond_get_bond_if_by_sw_if_index (u32 sw_if_index)
{
  bond_main_t *bm = &bond_main;
  uword *p;

  p = hash_get (bm->bond_by_sw_if_index, sw_if_index);
  if (!p)
    {
      return 0;
    }
  return pool_elt_at_index (bm->interfaces, p[0]);
}

static inline bond_if_t *
bond_get_bond_if_by_dev_instance (u32 dev_instance)
{
  bond_main_t *bm = &bond_main;

  return pool_elt_at_index (bm->interfaces, dev_instance);
}

static inline member_if_t *
bond_get_member_by_sw_if_index (u32 sw_if_index)
{
  bond_main_t *bm = &bond_main;
  member_if_t *mif = 0;
  uword p;

  if (sw_if_index < vec_len (bm->member_by_sw_if_index))
    {
      p = bm->member_by_sw_if_index[sw_if_index];
      if (p)
	mif = pool_elt_at_index (bm->neighbors, p >> 1);
    }

  return mif;
}

#endif /* __included_vnet_bonding_node_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
