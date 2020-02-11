
/*
 * vrrp.h - vrrp plug-in header file
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef __included_vrrp_h__
#define __included_vrrp_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

/* VRRP configuration */
typedef enum vrrp_vr_flags
{
  VRRP_VR_PREEMPT = 0x1,
  VRRP_VR_ACCEPT = 0x2,
  VRRP_VR_UNICAST = 0x4,
  VRRP_VR_IPV6 = 0x8,
} vrrp_vr_flags_t;

typedef struct vrrp_vr_key
{
  u32 sw_if_index;
  u8 vr_id;
  u8 is_ipv6;
} vrrp_vr_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct vrrp4_arp_key {
  union {
    struct {
      u32 sw_if_index;
      ip4_address_t addr;
    };
    u64 as_u64;
  };
}) vrrp4_arp_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct vrrp6_nd_key {
  u32 sw_if_index;
  ip6_address_t addr;
}) vrrp6_nd_key_t;
/* *INDENT-ON* */

typedef struct vrrp_vr_tracking_if
{
  u32 sw_if_index;
  u8 priority;
} vrrp_vr_tracking_if_t;

typedef struct vrrp_vr_tracking
{
  vrrp_vr_tracking_if_t *interfaces;
  u32 interfaces_dec;
} vrrp_vr_tracking_t;

typedef struct vrrp_vr_config
{
  u32 sw_if_index;
  u8 vr_id;
  u8 priority;
  u16 adv_interval;
  vrrp_vr_flags_t flags;
  ip46_address_t *vr_addrs;
  ip46_address_t *peer_addrs;
} vrrp_vr_config_t;

#define foreach_vrrp_vr_state		\
_(0, INIT, "Initialize")		\
_(1, BACKUP, "Backup")			\
_(2, MASTER, "Master")			\
_(3, INTF_DOWN, "Interface Down")

/* VRRP runtime data */
typedef enum vrrp_vr_state
{
#define _(v,f,n) VRRP_VR_STATE_##f = v,
  foreach_vrrp_vr_state
#undef _
} vrrp_vr_state_t;

typedef struct vrrp_vr_runtime
{
  vrrp_vr_state_t state;
  u16 master_adv_int;
  u16 skew;
  u16 master_down_int;
  mac_address_t mac;
  f64 last_sent;
  u32 timer_index;
} vrrp_vr_runtime_t;

/* Per-VR data */
typedef struct vrrp_vr
{
  vrrp_vr_config_t config;
  vrrp_vr_runtime_t runtime;
  vrrp_vr_tracking_t tracking;
} vrrp_vr_t;

/* Timers */
typedef enum vrrp_vr_timer_type
{
  VRRP_VR_TIMER_ADV,
  VRRP_VR_TIMER_MASTER_DOWN,
} vrrp_vr_timer_type_t;

typedef struct vrrp_vr_timer
{
  u32 vr_index;
  f64 expire_time;		/* monotonic, relative to vlib_time_now() */
  vrrp_vr_timer_type_t type;
} vrrp_vr_timer_t;

typedef struct
{
  /* vectors of vr indices which are configured on this interface
   * 0 -> ipv4, 1 -> ipv6 */
  u32 *vr_indices[2];

  /* vector of VR indices which track the state of this interface
   * 0 -> ipv4, 1*/
  u32 *tracking_vrs[2];

  /* multicast adjacency indices. 0 -> ipv4, 1 -> ipv6 */
  adj_index_t mcast_adj_index[2];

  /* number of VRs in master state on sw intf. 0 -> ipv4, 1 -> ipv6 */
  u8 n_master_vrs[2];

} vrrp_intf_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* pool of VRs */
  vrrp_vr_t *vrs;

  /* pool of timers and ordered vector of pool indices */
  vrrp_vr_timer_t *vr_timers;
  u32 *pending_timers;

  /* number of running VRs - don't register for VRRP proto if not running */
  u16 n_vrs_started;

  /* hash mapping a VR key to a pool entry */
  mhash_t vr_index_by_key;

  /* hashes mapping sw_if_index and address to a vr index */
  uword *vrrp4_arp_lookup;
  uword *vrrp6_nd_lookup;

  /* vector of interface data indexed by sw_if_index */
  vrrp_intf_t *vrrp_intfs;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;

  u32 intf_output_node_idx;
} vrrp_main_t;

extern vrrp_main_t vrrp_main;

extern vlib_node_registration_t vrrp_node;
extern vlib_node_registration_t vrrp_periodic_node;

/* Periodic function events */
#define VRRP_EVENT_VR_TIMER_UPDATE 1
#define VRRP_EVENT_VR_STOP 2
#define VRRP_EVENT_PERIODIC_ENABLE_DISABLE 3

clib_error_t *vrrp_plugin_api_hookup (vlib_main_t * vm);

int vrrp_vr_add_del (u8 is_add, vrrp_vr_config_t * conf);
int vrrp_vr_start_stop (u8 is_start, vrrp_vr_key_t * vr_key);
extern u8 *format_vrrp_vr (u8 * s, va_list * args);
extern u8 *format_vrrp_vr_key (u8 * s, va_list * args);
extern u8 *format_vrrp_vr_state (u8 * s, va_list * args);
extern u8 *format_vrrp_packet_hdr (u8 * s, va_list * args);
void vrrp_vr_timer_set (vrrp_vr_t * vr, vrrp_vr_timer_type_t type);
void vrrp_vr_timer_cancel (vrrp_vr_t * vr);
void vrrp_vr_transition (vrrp_vr_t * vr, vrrp_vr_state_t new_state,
			 void *data);
int vrrp_vr_set_peers (vrrp_vr_key_t * key, ip46_address_t * peers);
int vrrp_vr_multicast_group_join (vrrp_vr_t * vr);
int vrrp_adv_send (vrrp_vr_t * vr, int shutdown);
int vrrp_garp_or_na_send (vrrp_vr_t * vr);
u16 vrrp_adv_csum (void *l3_hdr, void *payload, u8 is_ipv6, u16 len);
int vrrp_vr_tracking_if_add_del (vrrp_vr_t * vr, u32 sw_if_index,
				 u8 priority, u8 is_add);
int vrrp_vr_tracking_ifs_add_del (vrrp_vr_t * vr,
				  vrrp_vr_tracking_if_t * track_ifs,
				  u8 is_add);


always_inline void
vrrp_vr_skew_compute (vrrp_vr_t * vr)
{
  vrrp_vr_config_t *vrc = &vr->config;
  vrrp_vr_runtime_t *vrt = &vr->runtime;

  vrt->skew = (((256 - vrc->priority) * vrt->master_adv_int) / 256);
}

always_inline void
vrrp_vr_master_down_compute (vrrp_vr_t * vr)
{
  vrrp_vr_runtime_t *vrt = &vr->runtime;

  vrt->master_down_int = (3 * vrt->master_adv_int) + vrt->skew;
}

always_inline vrrp_vr_t *
vrrp_vr_lookup (u32 sw_if_index, u8 vr_id, u8 is_ipv6)
{
  vrrp_main_t *vmp = &vrrp_main;
  vrrp_vr_key_t key = {
    .sw_if_index = sw_if_index,
    .vr_id = vr_id,
    .is_ipv6 = (is_ipv6 != 0),
  };
  uword *p;

  p = mhash_get (&vmp->vr_index_by_key, &key);
  if (p)
    return pool_elt_at_index (vmp->vrs, p[0]);

  return 0;
}

always_inline vrrp_vr_t *
vrrp_vr_lookup_index (u32 vr_index)
{
  vrrp_main_t *vmp = &vrrp_main;

  if (pool_is_free_index (vmp->vrs, vr_index))
    return 0;

  return pool_elt_at_index (vmp->vrs, vr_index);
}

always_inline u32
vrrp_vr_lookup_address (u32 sw_if_index, u8 is_ipv6, void *addr)
{
  vrrp_main_t *vmp = &vrrp_main;
  uword *p;
  vrrp4_arp_key_t key4;
  vrrp6_nd_key_t key6;

  if (is_ipv6)
    {
      key6.sw_if_index = sw_if_index;
      key6.addr = ((ip6_address_t *) addr)[0];
      p = hash_get_mem (vmp->vrrp6_nd_lookup, &key6);
    }
  else
    {
      key4.sw_if_index = sw_if_index;
      key4.addr = ((ip4_address_t *) addr)[0];
      p = hash_get (vmp->vrrp4_arp_lookup, key4.as_u64);
    }

  if (p)
    return p[0];

  return ~0;
}

always_inline vrrp_intf_t *
vrrp_intf_get (u32 sw_if_index)
{
  vrrp_main_t *vrm = &vrrp_main;

  if (sw_if_index == ~0)
    return NULL;

  vec_validate (vrm->vrrp_intfs, sw_if_index);
  return vec_elt_at_index (vrm->vrrp_intfs, sw_if_index);
}

always_inline int
vrrp_intf_num_vrs (u32 sw_if_index, u8 is_ipv6)
{
  vrrp_intf_t *intf = vrrp_intf_get (sw_if_index);

  if (intf)
    return vec_len (intf->vr_indices[is_ipv6]);

  return 0;
}

always_inline u8
vrrp_vr_is_ipv6 (vrrp_vr_t * vr)
{
  return ((vr->config.flags & VRRP_VR_IPV6) != 0);
}

always_inline u8
vrrp_vr_is_unicast (vrrp_vr_t * vr)
{
  return ((vr->config.flags & VRRP_VR_UNICAST) != 0);
}

always_inline u8
vrrp_vr_is_owner (vrrp_vr_t * vr)
{
  return (vr->config.priority == 255);
}

always_inline u8
vrrp_vr_n_vr_addrs (vrrp_vr_t * vr)
{
  return vec_len (vr->config.vr_addrs);
}

always_inline u8
vrrp_vr_n_peer_addrs (vrrp_vr_t * vr)
{
  return vec_len (vr->config.peer_addrs);
}

always_inline u8
vrrp_vr_accept_mode_enabled (vrrp_vr_t * vr)
{
  return ((vr->config.flags & VRRP_VR_ACCEPT) != 0);
}

always_inline u32
vrrp_vr_index (vrrp_vr_t * vr)
{
  vrrp_main_t *vmp = &vrrp_main;

  return vr - vmp->vrs;
}

always_inline u8
vrrp_vr_priority (vrrp_vr_t * vr)
{
  u8 rv;

  if (vr->tracking.interfaces_dec < (u32) vr->config.priority)
    rv = vr->config.priority - vr->tracking.interfaces_dec;
  else
    rv = 1;

  return rv;
}

#endif /* __included_vrrp_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
