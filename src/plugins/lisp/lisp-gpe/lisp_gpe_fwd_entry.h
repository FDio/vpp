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
/**
 * @file
 * @brief LISP-GPE definitions.
 */

#ifndef __LISP_GPE_FWD_ENTRY_H__
#define __LISP_GPE_FWD_ENTRY_H__

#include <lisp/lisp-gpe/lisp_gpe.h>

/**
 * @brief A path on which to forward lisp traffic
 */
typedef struct lisp_fwd_path_t_
{
  /**
   * The adjacency constructed for the locator pair
   */
  index_t lisp_adj;

  /**
   * Priority. Only the paths with the best priority will be installed in FIB
   */
  u8 priority;

  /**
   * [UE]CMP weigt for the path
   */
  u8 weight;

} lisp_fwd_path_t;

/**
 * @brief A Forwarding entry can be 'normal' or 'negative'
 * Negative implies we deliberately want to add a FIB entry for an EID
 * that results in 'special' behaviour determined by an 'action'.
 * @normal means send it down some tunnels.
 */
typedef enum lisp_gpe_fwd_entry_type_t_
{
  LISP_GPE_FWD_ENTRY_TYPE_NORMAL,
  LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE,
} lisp_gpe_fwd_entry_type_t;


/**
 * LISP-GPE fwd entry key
 */
typedef struct lisp_gpe_fwd_entry_key_t_
{
  dp_address_t rmt;
  dp_address_t lcl;
  u32 vni;
} lisp_gpe_fwd_entry_key_t;

/**
 * @brief A LISP Forwarding Entry
 *
 * A forwarding entry is from a locai EID to a remote EID over a set of rloc pairs
 */
typedef struct lisp_gpe_fwd_entry_t_
{
  /**
   * Follows src/dst or dst only forwarding policy
   */
  u8 is_src_dst;

  /**
   * This object joins the FIB control plane graph to receive updates to
   * for changes to the graph.
   */
  fib_node_t node;

  /**
   * The Entry's key: {lEID,rEID,vni}
   */
  lisp_gpe_fwd_entry_key_t *key;

  /**
   * The forwarding entry type
   */
  lisp_gpe_fwd_entry_type_t type;

  /**
   * The tenant the entry belongs to
   */
  u32 tenant;

  /**
   * The VRF (in the case of L3) or Bridge-Domain (for L2) index
   */
  union
  {
    /**
     * Fields relevant to an L2 entry
     */
    struct
    {
      /**
       * The VRF ID
       */
      u32 eid_table_id;

      /**
       * The FIB index for the overlay, i.e. the FIB in which the EIDs
       * are present
       */
      u32 eid_fib_index;
      /**
       * The SRC-FIB index for created for anding source-route entries
       */
      u32 src_fib_index;
    };
    /**
     * Fields relevant to an L2 entry
     */
    struct
    {
      /**
       * The Bridge-Domain (for L2) index
       */
      u32 eid_bd_id;

      /**
       * The Bridge-domain index for the overlay EIDs
       */
      u32 eid_bd_index;

      /**
       * The path-list created for the forwarding
       */
      fib_node_index_t path_list_index;

      /**
       * Child index of this entry on the path-list
       */
      u32 child_index;

      /**
       * The DPO used to forward
       */
      dpo_id_t dpo;
    } l2;

    /**
     * Fields relevant to an NSH entry
     */
    struct
    {
      /**
       * The path-list created for the forwarding
       */
      fib_node_index_t path_list_index;

      /**
       * Child index of this entry on the path-list
       */
      u32 child_index;

      /**
       * The DPO contributed by NSH
       */
      dpo_id_t dpo;

      /**
       * The DPO used for forwarding. Obtained after stacking tx node
       * onto lb choice
       */
      dpo_id_t choice;
    } nsh;
  };

  union
  {
    /**
     * @brief When the type is 'normal'
     *        The RLOC pair that form the route's paths. i.e. where to send
     *        packets for this route.
     */
    lisp_fwd_path_t *paths;

    /**
     * @brief When the type is negative. The action to take.
     */
    negative_fwd_actions_e action;
  };

  /**
   * used for getting load balance statistics
   */
  index_t dpoi_index;

} lisp_gpe_fwd_entry_t;

extern int
vnet_lisp_gpe_add_del_fwd_entry (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
				 u32 * hw_if_indexp);

extern void vnet_lisp_gpe_fwd_entry_flush (void);

extern u32 lisp_l2_fib_lookup (lisp_gpe_main_t *lgm, u16 bd_index,
			       u8 src_mac[6], u8 dst_mac[6]);

extern const dpo_id_t *lisp_nsh_fib_lookup (lisp_gpe_main_t * lgm,
					    u32 spi_si);
extern void
vnet_lisp_gpe_del_fwd_counters (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
				u32 fwd_entry_index);
extern void
vnet_lisp_gpe_add_fwd_counters (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
				u32 fwd_entry_index);
extern u32 *vnet_lisp_gpe_get_fwd_entry_vnis (void);

int
vnet_lisp_gpe_get_fwd_stats (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
			     vlib_counter_t * c);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
