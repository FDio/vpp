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

bd_main_t bd_main;

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
  u32 feature_bitmap;
  /*
   * Contains bit enables for flooding, learning, and forwarding.
   * All other feature bits should always be set.
   *
   * identity of the bridge-domain's BVI interface
   * set to ~0 if there is no BVI
   */
  u32 bvi_sw_if_index;

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

  /* hash ip4/ip6 -> mac for arp/nd termination */
  uword *mac_by_ip4;
  uword *mac_by_ip6;

  /* mac aging */
  u8 mac_age;

  /* sequence number for bridge domain based flush of MACs */
  u8 seq_num;

} l2_bridge_domain_t;

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


#define L2_LEARN   (1<<0)
#define L2_FWD     (1<<1)
#define L2_FLOOD   (1<<2)
#define L2_UU_FLOOD (1<<3)
#define L2_ARP_TERM (1<<4)

u32 bd_set_flags (vlib_main_t * vm, u32 bd_index, u32 flags, u32 enable);
void bd_set_mac_age (vlib_main_t * vm, u32 bd_index, u8 age);

/**
 * \brief Get or create a bridge domain.
 *
 * Get or create a bridge domain with the given bridge domain ID.
 *
 * \param bdm bd_main pointer.
 * \param bd_id The bridge domain ID or ~0 if an arbitrary unused bridge domain should be used.
 * \return The bridge domain index in \c l2input_main->l2_bridge_domain_t vector.
 */
u32 bd_find_or_add_bd_index (bd_main_t * bdm, u32 bd_id);

/**
 * \brief Delete a bridge domain.
 *
 * Delete an existing bridge domain with the given bridge domain ID.
 *
 * \param bdm bd_main pointer.
 * \param bd_id The bridge domain ID.
 * \return 0 on success and -1 if the bridge domain does not exist.
 */
int bd_delete_bd_index (bd_main_t * bdm, u32 bd_id);

u32 bd_add_del_ip_mac (u32 bd_index,
		       u8 * ip_addr, u8 * mac_addr, u8 is_ip6, u8 is_add);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
