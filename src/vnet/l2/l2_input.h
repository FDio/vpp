/*
 * l2_input.h : layer 2 input packet processing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef included_vnet_l2_input_h
#define included_vnet_l2_input_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip.h>

/* Per-subinterface L2 feature configuration */

typedef struct
{

  union
  {
    u16 bd_index;		/* bridge domain id */
    u32 output_sw_if_index;	/* for xconnect */
  };

  /* config for which input features are configured on this interface */
  u32 feature_bitmap;

  /* split horizon group */
  u8 shg;

  /* Interface mode. If both are 0, this interface is in L3 mode */
  u8 xconnect;
  u8 bridge;

  /* this is the bvi interface for the bridge-domain */
  u8 bvi;

} l2_input_config_t;


typedef struct
{

  /* Next nodes for the feature bitmap */
  u32 feat_next_node_index[32];

  /* config vector indexed by sw_if_index */
  l2_input_config_t *configs;

  /* bridge domain config vector indexed by bd_index */
  l2_bridge_domain_t *bd_configs;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2input_main_t;

extern l2input_main_t l2input_main;

extern vlib_node_registration_t l2input_node;

static_always_inline l2_bridge_domain_t *
l2input_bd_config_from_index (l2input_main_t * l2im, u32 bd_index)
{
  l2_bridge_domain_t *bd_config;

  bd_config = vec_elt_at_index (l2im->bd_configs, bd_index);
  return bd_is_valid (bd_config) ? bd_config : NULL;
}

static_always_inline l2_bridge_domain_t *
l2input_bd_config (u32 bd_index)
{
  l2input_main_t *mp = &l2input_main;
  l2_bridge_domain_t *bd_config;

  vec_validate (mp->bd_configs, bd_index);
  bd_config = vec_elt_at_index (mp->bd_configs, bd_index);
  return bd_config;
}

/* L2 input indication packet is from BVI, using -2 */
#define L2INPUT_BVI ((u32) (~0-1))

/* L2 input features */

/* Mappings from feature ID to graph node name in reverse order */
#define foreach_l2input_feat                    \
 _(DROP,          "feature-bitmap-drop")        \
 _(XCONNECT,      "l2-output")                  \
 _(FLOOD,         "l2-flood")                   \
 _(ARP_UFWD,      "l2-uu-fwd")                  \
 _(ARP_TERM,      "arp-term-l2bd")              \
 _(UU_FLOOD,      "l2-flood")                   \
 _(GBP_FWD,       "gbp-fwd")                    \
 _(UU_FWD,        "l2-uu-fwd")                  \
 _(FWD,           "l2-fwd")                     \
 _(RW,            "l2-rw")                      \
 _(LEARN,         "l2-learn")                   \
 _(L2_EMULATION,  "l2-emulation")               \
 _(GBP_LEARN,     "gbp-learn-l2")               \
 _(GBP_LPM_ANON_CLASSIFY, "l2-gbp-lpm-anon-classify") \
 _(GBP_NULL_CLASSIFY, "gbp-null-classify")      \
 _(GBP_SRC_CLASSIFY,  "gbp-src-classify")       \
 _(GBP_LPM_CLASSIFY,  "l2-gbp-lpm-classify")    \
 _(VTR,           "l2-input-vtr")               \
 _(L2_IP_QOS_RECORD, "l2-ip-qos-record")        \
 _(VPATH,         "vpath-input-l2")             \
 _(ACL,           "l2-input-acl")               \
 _(POLICER_CLAS,  "l2-policer-classify")	\
 _(INPUT_FEAT_ARC, "l2-input-feat-arc")         \
 _(INPUT_CLASSIFY, "l2-input-classify")         \
 _(SPAN,          "span-l2-input")

/* Feature bitmap positions */
typedef enum
{
#define _(sym,str) L2INPUT_FEAT_##sym##_BIT,
  foreach_l2input_feat
#undef _
  L2INPUT_N_FEAT
} l2input_feat_t;

STATIC_ASSERT (L2INPUT_N_FEAT <= 32, "too many l2 input features");

/* Feature bit masks */
typedef enum
{
  L2INPUT_FEAT_NONE = 0,
#define _(sym,str) L2INPUT_FEAT_##sym = (1<<L2INPUT_FEAT_##sym##_BIT),
  foreach_l2input_feat
#undef _
    L2INPUT_VALID_MASK =
#define _(sym,str) L2INPUT_FEAT_##sym |
    foreach_l2input_feat
#undef _
  0
} l2input_feat_masks_t;

STATIC_ASSERT ((u64) L2INPUT_VALID_MASK == (1ull << L2INPUT_N_FEAT) - 1, "");

/** Return an array of strings containing graph node names of each feature */
char **l2input_get_feat_names (void);

/* arg0 - u32 feature_bitmap, arg1 - u32 verbose */
u8 *format_l2_input_features (u8 * s, va_list * args);

static_always_inline u8
bd_feature_flood (l2_bridge_domain_t * bd_config)
{
  return ((bd_config->feature_bitmap & L2INPUT_FEAT_FLOOD) ==
	  L2INPUT_FEAT_FLOOD);
}

static_always_inline u8
bd_feature_uu_flood (l2_bridge_domain_t * bd_config)
{
  return ((bd_config->feature_bitmap & L2INPUT_FEAT_UU_FLOOD) ==
	  L2INPUT_FEAT_UU_FLOOD);
}

static_always_inline u8
bd_feature_forward (l2_bridge_domain_t * bd_config)
{
  return ((bd_config->feature_bitmap & L2INPUT_FEAT_FWD) == L2INPUT_FEAT_FWD);
}

static_always_inline u8
bd_feature_learn (l2_bridge_domain_t * bd_config)
{
  return ((bd_config->feature_bitmap & L2INPUT_FEAT_LEARN) ==
	  L2INPUT_FEAT_LEARN);
}

static_always_inline u8
bd_feature_arp_term (l2_bridge_domain_t * bd_config)
{
  return ((bd_config->feature_bitmap & L2INPUT_FEAT_ARP_TERM) ==
	  L2INPUT_FEAT_ARP_TERM);
}

static_always_inline u8
bd_feature_arp_ufwd (l2_bridge_domain_t * bd_config)
{
  return ((bd_config->feature_bitmap & L2INPUT_FEAT_ARP_UFWD) ==
	  L2INPUT_FEAT_ARP_UFWD);
}

/** Masks for eliminating features that do not apply to a packet */

/** Get a pointer to the config for the given interface */
l2_input_config_t *l2input_intf_config (u32 sw_if_index);

/* Enable (or disable) the feature in the bitmap for the given interface */
u32 l2input_intf_bitmap_enable (u32 sw_if_index,
				l2input_feat_masks_t feature_bitmap,
				u32 enable);

/* Sets modifies flags from a bridge domain */
u32 l2input_set_bridge_features (u32 bd_index, u32 feat_mask, u32 feat_value);

void l2input_interface_mac_change (u32 sw_if_index,
				   const u8 * old_address,
				   const u8 * new_address);

#define MODE_L3        0
#define MODE_L2_BRIDGE 1
#define MODE_L2_XC     2
#define MODE_L2_CLASSIFY 3

#define MODE_ERROR_ETH        1
#define MODE_ERROR_BVI_DEF    2

u32 set_int_l2_mode (vlib_main_t * vm,
		     vnet_main_t * vnet_main,
		     u32 mode,
		     u32 sw_if_index,
		     u32 bd_index, l2_bd_port_type_t port_type,
		     u32 shg, u32 xc_sw_if_index);

static inline void
vnet_update_l2_len (vlib_buffer_t * b)
{
  ethernet_header_t *eth;
  u16 ethertype;
  u8 vlan_count = 0;

  /* point at current l2 hdr */
  eth = vlib_buffer_get_current (b);

  /*
   * l2-output pays no attention to this
   * but the tag push/pop code on an l2 subif needs it.
   *
   * Determine l2 header len, check for up to 2 vlans
   */
  vnet_buffer (b)->l2.l2_len = sizeof (ethernet_header_t);
  ethertype = clib_net_to_host_u16 (eth->type);
  if (ethernet_frame_is_tagged (ethertype))
    {
      ethernet_vlan_header_t *vlan;
      vnet_buffer (b)->l2.l2_len += sizeof (*vlan);
      vlan_count = 1;
      vlan = (void *) (eth + 1);
      ethertype = clib_net_to_host_u16 (vlan->type);
      if (ethertype == ETHERNET_TYPE_VLAN)
	{
	  vnet_buffer (b)->l2.l2_len += sizeof (*vlan);
	  vlan_count = 2;
	}
    }
  ethernet_buffer_set_vlan_count (b, vlan_count);
}

/*
 * Compute flow hash of an ethernet packet, use 5-tuple hash if L3 packet
 * is ip4 or ip6. Otherwise hash on smac/dmac/etype.
 * The vlib buffer current pointer is expected to be at ethernet header
 * and vnet l2.l2_len is expected to be setup already.
 */
static inline u32
vnet_l2_compute_flow_hash (vlib_buffer_t * b)
{
  ethernet_header_t *eh = vlib_buffer_get_current (b);
  u8 *l3h = (u8 *) eh + vnet_buffer (b)->l2.l2_len;
  u16 ethertype = clib_net_to_host_u16 (*(u16 *) (l3h - 2));

  if (ethertype == ETHERNET_TYPE_IP4)
    return ip4_compute_flow_hash ((ip4_header_t *) l3h, IP_FLOW_HASH_DEFAULT);
  else if (ethertype == ETHERNET_TYPE_IP6)
    return ip6_compute_flow_hash ((ip6_header_t *) l3h, IP_FLOW_HASH_DEFAULT);
  else
    {
      u32 a, b, c;
      u32 *ap = (u32 *) & eh->dst_address[2];
      u32 *bp = (u32 *) & eh->src_address[2];
      a = *ap;
      b = *bp;
      c = ethertype;
      hash_v3_mix32 (a, b, c);
      hash_v3_finalize32 (a, b, c);
      return c;
    }
}

#endif


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
