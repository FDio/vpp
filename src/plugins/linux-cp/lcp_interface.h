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
#ifndef __LCP_ITF_PAIR_H__
#define __LCP_ITF_PAIR_H__

#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj.h>
#include <vnet/ip/ip_types.h>

#define LCP_ITF_PAIR_PLUGIN_VERSION_MAJOR 1
#define LCP_ITF_PAIR_PLUGIN_VERSION_MINOR 0

#define LCP_NS_LEN		32

typedef enum
{
  LCP_ITF_HOST_TAP = 0,
  LCP_ITF_HOST_TUN = 1,
  N_LCP_ITF_HOST
} lip_host_type_t;

typedef struct lcp_itf_phy_adj
{
  adj_index_t adj_index[N_AF];
} lcp_itf_phy_adj_t;

/**
 * A pair of interfaces
 */
typedef struct lcp_itf_pair_t_
{
  u32 lip_host_sw_if_index;	/* VPP's sw_if_index for the host tap */
  u32 lip_phy_sw_if_index;	/* VPP's sw_if_index for the phy */
  u8 *lip_host_name;		/* linux's name for the tap */
  u32 lip_vif_index;		/* linux's index for the tap */
  u8 lip_namespace[LCP_NS_LEN];	/* namespace in which the tap lives */
  lip_host_type_t lip_host_type;	/* type of host interface */
  lcp_itf_phy_adj_t lip_phy_adjs;	/* adjacencies for phy l3 interface */
  u8 lip_rewrite_len; /* The length of an L2 MAC rewrite */
} lcp_itf_pair_t;

extern vlib_node_registration_t lcp_ethernet_node;

/**
 * Get/Set the default namespace for LCP host taps.
 */
int lcp_set_default_ns (u8 * ns);
u8 *lcp_get_default_ns (void);	/* Returns NULL or shared string */
int lcp_get_default_ns_fd (void);

u8 *format_lcp_itf_pair (u8 * s, va_list * args);
void lcp_itf_pair_show (u32 phy_sw_if_index);
u32 lcp_itf_num_pairs (void);

/**
 * Get an interface-pair object from its VPP index
 */
extern lcp_itf_pair_t *lcp_itf_pair_get (index_t index);

/**
 * Find a interface-pair object from the host interface
 *
 * @param host_sw_if_index host interface
 * @return VPP's object index
 */
extern index_t lcp_itf_pair_find_by_vif (u32 vif_index);

/**
 * Create an interface-pair
 *
 * @return error code
 */
extern int lcp_itf_pair_add (u32 host_sw_if_index,
			     u32 phy_sw_if_index,
			     u8 * host_name,
			     u32 host_index,
			     lip_host_type_t host_type, u8 * ns);
extern int lcp_itf_pair_add_sub (u32 vif,
				 u8 * host_name,
				 u32 sub_sw_if_index,
				 u32 phy_sw_if_index, u8 * ns);

/**
 * Create an interface-pair from PHY sw_if_index and tap name.
 *
 * @return error code
 */
int lcp_itf_pair_create (u32 phy_sw_if_index, u8 * host_if_name,
			 lip_host_type_t host_if_type, u8 * ns);

/**
 * Delete a LCP_ITF_PAIR
 */
extern int lcp_itf_pair_delete (u32 phy_sw_if_index);

/**
 * Callback function invoked during a walk of all interface-pairs
 */
typedef walk_rc_t (*lcp_itf_pair_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the interface pairs
 */
extern void lcp_itf_pair_walk (lcp_itf_pair_walk_cb_t cb, void *ctx);

/**
 * Retreive the pair in the DP
 */
extern index_t *lip_db_by_phy;
extern  u32 *lip_db_by_host;

always_inline index_t
lcp_itf_pair_find_by_phy (u32 phy_sw_if_index)
{
  if (phy_sw_if_index >= vec_len (lip_db_by_phy))
    return INDEX_INVALID;
  return (lip_db_by_phy[phy_sw_if_index]);
}

always_inline index_t
lcp_itf_pair_find_by_host (u32 host_sw_if_index)
{
  if (host_sw_if_index >= vec_len (lip_db_by_host))
    return INDEX_INVALID;
  return (lip_db_by_host[host_sw_if_index]);
}

/**
 * manage interface auto creation
 */
void lcp_set_auto_intf (u8 is_auto);
int lcp_auto_intf (void);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
