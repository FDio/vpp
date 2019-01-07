/*
 * l2_bd.h : layer 2 bridge domain
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

#ifndef included_l2bd_h
#define included_l2bd_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ethernet/mac_address.h>

typedef enum l2_bd_port_type_t_
{
  L2_BD_PORT_TYPE_NORMAL = 0,
  L2_BD_PORT_TYPE_BVI = 1,
  L2_BD_PORT_TYPE_UU_FWD = 2,
} l2_bd_port_type_t;

typedef struct
{
  /* hash bd_id -> bd_index */
  uword *bd_index_by_bd_id;

  /* Busy bd_index bitmap */
  uword *bd_index_bitmap;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} bd_main_t;

extern bd_main_t bd_main;

/* Bridge domain member  */

#define L2_FLOOD_MEMBER_NORMAL 0
#define L2_FLOOD_MEMBER_BVI    1

typedef struct
{
  u32 sw_if_index;		/* the output L2 interface */
  u8 flags;			/* 0=normal, 1=bvi */
  u8 shg;			/* split horizon group number  */
  u16 spare;
} l2_flood_member_t;

/* Per-bridge domain configuration */

typedef struct
{
  /*
   * Contains bit enables for flooding, learning, and forwarding.
   * All other feature bits should always be set.
   */
  u32 feature_bitmap;
  /*
   * identity of the bridge-domain's BVI interface
   * set to ~0 if there is no BVI
   */
  u32 bvi_sw_if_index;

  /*
   * identity of the bridge-domain's UU flood interface
   * set to ~0 if there is no such configuration
   */
  u32 uu_fwd_sw_if_index;

  /* bridge domain id, not to be confused with bd_index */
  u32 bd_id;

  /* Vector of member ports */
  l2_flood_member_t *members;

  /* First flood_count member ports are flooded */
  u32 flood_count;

  /* Tunnel Master (Multicast vxlan) are always flooded */
  u32 tun_master_count;

  /* Tunnels (Unicast vxlan) are flooded if there are no masters */
  u32 tun_normal_count;

  /* Interface on which packets are not flooded */
  u32 no_flood_count;

  /* hash ip4/ip6 -> mac for arp/nd termination */
  uword *mac_by_ip4;
  uword *mac_by_ip6;

  /* mac aging */
  u8 mac_age;

  /* sequence number for bridge domain based flush of MACs */
  u8 seq_num;

  /* Bridge domain tag (C string NULL terminated) */
  u8 *bd_tag;

} l2_bridge_domain_t;

/* Limit Bridge Domain ID to 24 bits to match 24-bit VNI range */
#define L2_BD_ID_MAX ((1<<24)-1)

typedef struct
{
  u32 bd_id;
  u8 flood;
  u8 uu_flood;
  u8 forward;
  u8 learn;
  u8 arp_term;
  u8 mac_age;
  u8 *bd_tag;
  u8 is_add;
} l2_bridge_domain_add_del_args_t;

/* Return 1 if bridge domain has been initialized */
always_inline u32
bd_is_valid (l2_bridge_domain_t * bd_config)
{
  return (bd_config->feature_bitmap != 0);
}

/* Init bridge domain if not done already */
void bd_validate (l2_bridge_domain_t * bd_config);


void
bd_add_member (l2_bridge_domain_t * bd_config, l2_flood_member_t * member);

u32 bd_remove_member (l2_bridge_domain_t * bd_config, u32 sw_if_index);

typedef enum bd_flags_t_
{
  L2_NONE = 0,
  L2_LEARN = (1 << 0),
  L2_FWD = (1 << 1),
  L2_FLOOD = (1 << 2),
  L2_UU_FLOOD = (1 << 3),
  L2_ARP_TERM = (1 << 4),
} bd_flags_t;

u32 bd_set_flags (vlib_main_t * vm, u32 bd_index, bd_flags_t flags,
		  u32 enable);
void bd_set_mac_age (vlib_main_t * vm, u32 bd_index, u8 age);
int bd_add_del (l2_bridge_domain_add_del_args_t * args);

/**
 * \brief Get a bridge domain.
 *
 * Get a bridge domain with the given bridge domain ID.
 *
 * \param bdm bd_main pointer.
 * \param bd_id The bridge domain ID
 * \return The bridge domain index in \c l2input_main->l2_bridge_domain_t vector.
 */
u32 bd_find_index (bd_main_t * bdm, u32 bd_id);

/**
 * \brief Create a bridge domain.
 *
 * Create a bridge domain with the given bridge domain ID
 *
 * \param bdm bd_main pointer.
 * \return The bridge domain index in \c l2input_main->l2_bridge_domain_t vector.
 */
u32 bd_add_bd_index (bd_main_t * bdm, u32 bd_id);

/**
 * \brief Get or create a bridge domain.
 *
 * Get a bridge domain with the given bridge domain ID, if one exists, otherwise
 * create one with the given ID, or the first unused ID if the given ID is ~0..
 *
 * \param bdm bd_main pointer.
 * \param bd_id The bridge domain ID
 * \return The bridge domain index in \c l2input_main->l2_bridge_domain_t vector.
 */
static inline u32
bd_find_or_add_bd_index (bd_main_t * bdm, u32 bd_id)
{
  u32 bd_index = bd_find_index (bdm, bd_id);
  if (bd_index == ~0)
    return bd_add_bd_index (bdm, bd_id);
  return bd_index;
}

u32 bd_add_del_ip_mac (u32 bd_index,
		       ip46_type_t type,
		       const ip46_address_t * ip_addr,
		       const mac_address_t * mac, u8 is_add);

void bd_flush_ip_mac (u32 bd_index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
