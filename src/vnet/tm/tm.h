/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef _TM_H_
#define _TM_H_

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vnet/dev/types.h>
#include <vppinfra/hash.h>

/* Global mapping of flow_name to flow_id */
extern uword *flow_name_to_id_hash;
extern u32 next_flow_id;

typedef struct tm_node_params_
{
  /** Shaper profile for the node. */
  i32 shaper_profile_id;

  union
  {
    struct
    {
      /** The ingress queue buffer length */
      u32 ingress_q_len;
    } leaf;

    struct
    {
      /** Number of SP priorities. */
      u32 num_sp_priorities;
      /* Is scheduling done with pkt mode(1) or byte mode(0). defined per sp
       * priority */
      u8 *sched_pkt_mode;
    } nonleaf;
  };

  /** Level Identifier of the node in the tm hierarchy */
  u32 level;

  /** Store Node specific data */
  void *data;

  /** TM Node id */
  u32 id;
} tm_node_params_t;

typedef struct tm_shaper_params_
{
  struct
  {
    /** Committed Information Rate. */
    u64 rate;
    /** Max burst size for Committed information rate*/
    u64 burst_size;
  } commit;

  struct
  {
    /** Peak Information Rate. */
    u64 rate;
    /** Max burst size for Peak information rate. */
    u64 burst_size;
  } peak;

  /** Value to be added to the length of each packet for the
   * purpose of shaping. */
  i32 pkt_len_adj;

  /** Byte mode of Packet mode */
  u8 pkt_mode;

  /** Shaper profile ID */
  u32 shaper_id;
} tm_shaper_params_t;

typedef enum
{
  TM_BYTE_BASED_WEIGHTS,
  TM_FRAME_BASED_WEIGHTS
} tm_sched_mode_t;

/**
 * TM Color
 */
enum tm_color
{
  TM_COLOR_GREEN = 0, /**< Green */
  TM_COLOR_YELLOW,    /**< Yellow */
  TM_COLOR_RED,	      /**< Red */
  TM_COLORS	      /**< Number of colors */
};

/**
 * The tm_node_stats_type enumeration lists possible packet or octet
 * statistics at a tm node.
 */
typedef enum tm_node_stats_type_t
{
  /** Packets dropped by this node after scheduling/shaping at this node */
  TM_NODE_STATS_PKTS_DROPPED,
  /** Octets dropped after scheduling/shaping at this node */
  TM_NODE_STATS_OCTETS_DROPPED,
  /** Green packets that are sent through this tm node */
  TM_NODE_STATS_GREEN_PKTS,
  /** Green octets that are sent through this tm node */
  TM_NODE_STATS_GREEN_OCTETS,
  /** Yellow packets that are sent through this tm node */
  TM_NODE_STATS_YELLOW_PKTS,
  /** Yellow octets that are sent through this tm node */
  TM_NODE_STATS_YELLOW_OCTETS,
  /** Red packets that are sent through this tm node */
  TM_NODE_STATS_RED_PKTS,
  /** Red octets that are sent through this tm node */
  TM_NODE_STATS_RED_OCTETS,
  /** Node stats max */
  TM_NODE_STATS_MAX,
} tm_node_stats_type_t;

/**
 * Node Capabilities Params
 */
typedef struct tm_capa_params_
{
  /** Maximum number of nodes. */
  uint32_t n_nodes_max;

  /** Maximum number of levels (i.e. number of nodes connecting the root
   * node with any leaf node, including the root and the leaf).
   */
  uint32_t n_levels_max;

  /** When non-zero, this flag indicates that all the non-leaf nodes
   * (with the exception of the root node) have identical capability set.
   */
  int non_leaf_nodes_identical;

  /** When non-zero, this flag indicates that all the leaf nodes have
   * identical capability set.
   */
  int leaf_nodes_identical;

  /** Maximum number of shapers, either private or shared. In case the
   * implementation does not share any resources between private and
   * shared shapers, it is typically equal to the sum of
   * *shaper_private_n_max* and *shaper_shared_n_max*. The
   * value of zero indicates that traffic shaping is not supported.
   */
  uint32_t shaper_n_max;
  /** Maximum number of private shapers. Indicates the maximum number of
   * nodes that can concurrently have their private shaper enabled. The
   * value of zero indicates that private shapers are not supported.
   */
  uint32_t shaper_private_n_max;

  /** Maximum number of private shapers that support dual rate shaping.
   * Indicates the maximum number of nodes that can concurrently have
   * their private shaper enabled with dual rate support. Only valid when
   * private shapers are supported. The value of zero indicates that dual
   * rate shaping is not available for private shapers. The maximum value
   * is *shaper_private_n_max*.
   */
  int shaper_private_dual_rate_n_max;

  /** Minimum committed/peak rate (bytes per second) for any private
   * shaper. Valid only when private shapers are supported.
   */
  uint64_t shaper_private_rate_min;
  /** Maximum committed/peak rate (bytes per second) for any private
   * shaper. Valid only when private shapers are supported.
   */
  uint64_t shaper_private_rate_max;

  /** Shaper private packet mode supported. When non-zero, this parameter
   * indicates that there is at least one node that can be configured
   * with packet mode in its private shaper. When shaper is configured
   * in packet mode, committed/peak rate provided is interpreted
   * in packets per second.
   */
  int shaper_private_packet_mode_supported;

  /** Shaper private byte mode supported. When non-zero, this parameter
   * indicates that there is at least one node that can be configured
   * with byte mode in its private shaper. When shaper is configured
   * in byte mode, committed/peak rate provided is interpreted in
   * bytes per second.
   */
  int shaper_private_byte_mode_supported;
  /** Minimum value allowed for packet length adjustment for any private
   * or shared shaper.
   */
  int shaper_pkt_length_adjust_min;

  /** Maximum value allowed for packet length adjustment for any private
   * or shared shaper.
   */
  int shaper_pkt_length_adjust_max;

  /** Maximum number of children nodes. This parameter indicates that
   * there is at least one non-leaf node that can be configured with this
   * many children nodes, which might not be true for all the non-leaf
   * nodes.
   */
  uint32_t sched_n_children_max;

  /** Maximum number of supported priority levels. This parameter
   * indicates that there is at least one non-leaf node that can be
   * configured with this many priority levels for managing its children
   * nodes, which might not be true for all the non-leaf nodes. The value
   * of zero is invalid. The value of 1 indicates that only priority 0 is
   * supported, which essentially means that Strict Priority (SP)
   * algorithm is not supported.
   */
  uint32_t sched_sp_n_priorities_max;
  /** Maximum number of sibling nodes that can have the same priority at
   * any given time, i.e. maximum size of the WFQ sibling node group. This
   * parameter indicates there is at least one non-leaf node that meets
   * this condition, which might not be true for all the non-leaf nodes.
   * The value of zero is invalid. The value of 1 indicates that WFQ
   * algorithm is not supported. The maximum value is
   * *sched_n_children_max*.
   */
  uint32_t sched_wfq_n_children_per_group_max;

  /** Maximum number of priority levels that can have more than one child
   * node at any given time, i.e. maximum number of WFQ sibling node
   * groups that have two or more members. This parameter indicates there
   * is at least one non-leaf node that meets this condition, which might
   * not be true for all the non-leaf nodes. The value of zero states that
   * WFQ algorithm is not supported. The value of 1 indicates that
   * (*sched_sp_n_priorities_max* - 1) priority levels have at most one
   * child node, so there can be only one priority level with two or
   * more sibling nodes making up a WFQ group. The maximum value is:
   * min(floor(*sched_n_children_max* / 2), *sched_sp_n_priorities_max*).
   */
  uint32_t sched_wfq_n_groups_max;

  /** Maximum WFQ weight. The value of 1 indicates that all sibling nodes
   * with same priority have the same WFQ weight, so WFQ is reduced to FQ.
   */
  uint32_t sched_wfq_weight_max;

  /** WFQ packet mode supported. When non-zero, this parameter indicates
   * that there is at least one non-leaf node that supports packet mode
   * for WFQ among its children. WFQ weights will be applied against
   * packet count for scheduling children when a non-leaf node
   * is configured appropriately.
   */
  int sched_wfq_packet_mode_supported;

  /** WFQ byte mode supported. When non-zero, this parameter indicates
   * that there is at least one non-leaf node that supports byte mode
   * for WFQ among its children. WFQ weights will be applied against
   * bytes for scheduling children when a non-leaf node is configured
   * appropriately.
   */
  int sched_wfq_byte_mode_supported;

} tm_capa_params_t;

/**
 * Traffic manager level capabilities
 */
typedef struct tm_level_capa_params_
{
  /** Maximum number of nodes for the current hierarchy level. */
  uint32_t n_nodes_max;

  /** Maximum number of non-leaf nodes for the current hierarchy level.
   * The value of 0 indicates that current level only supports leaf
   * nodes. The maximum value is *n_nodes_max*.
   */
  uint32_t n_nodes_nonleaf_max;

  /** Maximum number of leaf nodes for the current hierarchy level. The
   * value of 0 indicates that current level only supports non-leaf
   * nodes. The maximum value is *n_nodes_max*.
   */
  uint32_t n_nodes_leaf_max;

  /** When non-zero, this flag indicates that all the non-leaf nodes on
   * this level have identical capability set. Valid only when
   * *n_nodes_nonleaf_max* is non-zero.
   */
  int non_leaf_nodes_identical;

  /** When non-zero, this flag indicates that all the leaf nodes on this
   * level have identical capability set. Valid only when
   * *n_nodes_leaf_max* is non-zero.
   */
  int leaf_nodes_identical;
  union
  {
    /** Items valid only for the non-leaf nodes on this level. */
    struct
    {
      /** Private shaper support. When non-zero, it indicates
       * there is at least one non-leaf node on this level
       * with private shaper support, which may not be the
       * case for all the non-leaf nodes on this level.
       */
      int shaper_private_supported;

      /** Dual rate support for private shaper. Valid only
       * when private shaper is supported for the non-leaf
       * nodes on the current level. When non-zero, it
       * indicates there is at least one non-leaf node on this
       * level with dual rate private shaper support, which
       * may not be the case for all the non-leaf nodes on
       * this level.
       */
      int shaper_private_dual_rate_supported;

      /** Minimum committed/peak rate (bytes per second) for
       * private shapers of the non-leaf nodes of this level.
       * Valid only when private shaper is supported on this
       * level.
       */
      uint64_t shaper_private_rate_min;

      /** Maximum committed/peak rate (bytes per second) for
       * private shapers of the non-leaf nodes on this level.
       * Valid only when private shaper is supported on this
       * level.
       */
      uint64_t shaper_private_rate_max;

      /** Shaper private packet mode supported. When non-zero,
       * this parameter indicates there is at least one
       * non-leaf node at this level that can be configured
       * with packet mode in its private shaper. When private
       * shaper is configured in packet mode, committed/peak
       * rate provided is interpreted in packets per second.
       */
      int shaper_private_packet_mode_supported;

      /** Shaper private byte mode supported. When non-zero,
       * this parameter indicates there is at least one
       * non-leaf node at this level that can be configured
       * with byte mode in its private shaper. When private
       * shaper is configured in byte mode, committed/peak
       * rate provided is interpreted in bytes per second.
       */
      int shaper_private_byte_mode_supported;

      /** Maximum number of children nodes. This parameter
       * indicates that there is at least one non-leaf node on
       * this level that can be configured with this many
       * children nodes, which might not be true for all the
       * non-leaf nodes on this level.
       */
      uint32_t sched_n_children_max;
      /** Maximum number of supported priority levels. This
       * parameter indicates that there is at least one
       * non-leaf node on this level that can be configured
       * with this many priority levels for managing its
       * children nodes, which might not be true for all the
       * non-leaf nodes on this level. The value of zero is
       * invalid. The value of 1 indicates that only priority
       * 0 is supported, which essentially means that Strict
       * Priority (SP) algorithm is not supported on this
       * level.
       */
      uint32_t sched_sp_n_priorities_max;

      /** Maximum number of sibling nodes that can have the
       * same priority at any given time, i.e. maximum size of
       * the WFQ sibling node group. This parameter indicates
       * there is at least one non-leaf node on this level
       * that meets this condition, which may not be true for
       * all the non-leaf nodes on this level. The value of
       * zero is invalid. The value of 1 indicates that WFQ
       * algorithm is not supported on this level. The maximum
       * value is *sched_n_children_max*.
       */
      uint32_t sched_wfq_n_children_per_group_max;

      /** Maximum number of priority levels that can have
       * more than one child node at any given time, i.e.
       * maximum number of WFQ sibling node groups that
       * have two or more members. This parameter indicates
       * there is at least one non-leaf node on this level
       * that meets this condition, which might not be true
       * for all the non-leaf nodes. The value of zero states
       * that WFQ algorithm is not supported on this level.
       * The value of 1 indicates that
       * (*sched_sp_n_priorities_max* - 1) priority levels on
       * this level have at most one child node, so there can
       * be only one priority level with two or more sibling
       * nodes making up a WFQ group on this level. The
       * maximum value is:
       * min(floor(*sched_n_children_max* / 2),
       * *sched_sp_n_priorities_max*).
       */
      uint32_t sched_wfq_n_groups_max;
      /** Maximum WFQ weight. The value of 1 indicates that
       * all sibling nodes on this level with same priority
       * have the same WFQ weight, so on this level WFQ is
       * reduced to FQ.
       */
      uint32_t sched_wfq_weight_max;

      /** WFQ packet mode supported. When non-zero, this
       * parameter indicates that there is at least one
       * non-leaf node at this level that supports packet
       * mode for WFQ among its children. WFQ weights will
       * be applied against packet count for scheduling
       * children when a non-leaf node is configured
       * appropriately.
       */
      int sched_wfq_packet_mode_supported;

      /** WFQ byte mode supported. When non-zero, this
       * parameter indicates that there is at least one
       * non-leaf node at this level that supports byte
       * mode for WFQ among its children. WFQ weights will
       * be applied against bytes for scheduling children
       * when a non-leaf node is configured appropriately.
       */
      int sched_wfq_byte_mode_supported;

      /** Mask of statistics counter types supported by the
       * non-leaf nodes on this level. Every supported
       * statistics counter type is supported by at least one
       * non-leaf node on this level, which may not be true
       * for all the non-leaf nodes on this level.
       * @see enum rte_tm_stats_type
       */
      uint64_t stats_mask;
    } nonleaf;

    /** Items valid only for the leaf nodes on this level. */
    struct
    {
      /** Private shaper support. When non-zero, it indicates
       * there is at least one leaf node on this level with
       * private shaper support, which may not be the case for
       * all the leaf nodes on this level.
       */
      int shaper_private_supported;

      /** Dual rate support for private shaper. Valid only
       * when private shaper is supported for the leaf nodes
       * on this level. When non-zero, it indicates there is
       * at least one leaf node on this level with dual rate
       * private shaper support, which may not be the case for
       * all the leaf nodes on this level.
       */
      int shaper_private_dual_rate_supported;

      /** Minimum committed/peak rate (bytes per second) for
       * private shapers of the leaf nodes of this level.
       * Valid only when private shaper is supported for the
       * leaf nodes on this level.
       */
      uint64_t shaper_private_rate_min;

      /** Maximum committed/peak rate (bytes per second) for
       * private shapers of the leaf nodes on this level.
       * Valid only when private shaper is supported for the
       * leaf nodes on this level.
       */
      uint64_t shaper_private_rate_max;

      /** Shaper private packet mode supported. When non-zero,
       * this parameter indicates there is at least one leaf
       * node at this level that can be configured with
       * packet mode in its private shaper. When private
       * shaper is configured in packet mode, committed/peak
       * rate provided is interpreted in packets per second.
       */
      int shaper_private_packet_mode_supported;
      /** Shaper private byte mode supported. When non-zero,
       * this parameter indicates there is at least one leaf
       * node at this level that can be configured with
       * byte mode in its private shaper. When private shaper
       * is configured in byte mode, committed/peak rate
       * provided is interpreted in bytes per second.
       */
      int shaper_private_byte_mode_supported;

    } leaf;
  };
} tm_level_capa_params_t;

/**
 * Node statistics counters
 */
typedef struct tm_stats_params_
{
  /** Number of packets scheduled from current node. */
  uint64_t n_pkts;

  /** Number of bytes scheduled from current node. */
  uint64_t n_bytes;

  /** Statistics counters for leaf nodes only. */
  struct
  {
    /** Number of packets dropped by current leaf node per each
     * color.
     */
    uint64_t n_pkts_dropped[TM_COLORS];

    /** Number of bytes dropped by current leaf node per each
     * color.
     */
    uint64_t n_bytes_dropped[TM_COLORS];

    /** Number of packets currently waiting in the packet queue of
     * current leaf node.
     */
    uint64_t n_pkts_queued;
    /** Number of bytes currently waiting in the packet queue of
     * current leaf node.
     */
    uint64_t n_bytes_queued;
  } leaf;
} tm_stats_params_t;

typedef struct tm_system_t_
{
  u32 hw_if_idx;
  int (*node_add) (u32 hw_if_idx, u32 node_id, i32 parent_node_id,
		   u32 priority, u32 weight, u32 lvl, tm_node_params_t *params,
		   char *flow_name);
  int (*node_suspend) (u32 hw_if_idx, u32 node_idx);
  int (*node_resume) (u32 hw_if_idx, u32 node_idx);
  int (*node_delete) (u32 hw_if_idx, u32 node_idx);
  int (*shaper_profile_create) (u32 hw_if_idx, tm_shaper_params_t *param);
  int (*shaper_profile_delete) (u32 hw_if_idx, u32 shaper_id);
  int (*node_shaper_update) (u32 hw_if_idx, u32 node_id,
			     u32 shaper_profile_id);
  int (*node_sched_weight_update) (u32 hw_if_idx, u32 node_id, u32 weight);
  int (*node_read_stats) (u32 hw_if_idx, u32 node_idx,
			  tm_stats_params_t *param);
  int (*tm_get_capabilities) (u32 hw_if_idx, tm_capa_params_t *capa_param);
  int (*tm_level_get_capabilities) (u32 hw_if_idx, tm_level_capa_params_t *cap,
				    u32 lvl);
  int (*start_tm) (u32 hw_if_idx);
  int (*stop_tm) (u32 hw_if_idx);
} tm_system_t;

/**
 * @brief Add global flow_name to flow_id mapping
 *
 * @param flow_name - Global flow name .
 *
 * @return 0 on success.
 */
u32 tm_create_flow_id (const char *flow_name);

/**
 * @brief Fetch the global flow_id mapped to the given flow_name
 *
 * @param flow_name - Global flow name .
 *
 * @return 0 on success.
 */
u32 tm_get_flow_id (const char *flow_name);

/**
 * @brief Add a new traffic management node and connect it to an
 * existing parent node.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param node_id - Identifier for the new TM node to be created.
 * @param parent_node_id - Identifier of the existing parent node.
 * @param priority - Priority level of the new node.
 * @param weight - Weight assigned to the new node.
 * @param lvl - Level of the new node in the hierarchy.
 * @param params - Pointer to the structure containing additional parameters
 * for the TM node.
 * @param flow_id - Identifier of the flow associated with the node.
 *
 * @return 0 on success.
 */
int tm_sys_node_add (u32 hw_if_idx, u32 node_id, i32 parent_node_id,
		     u32 priority, u32 weight, u32 lvl,
		     tm_node_params_t *params, char *flow_name);

/**
 * @brief Suspend an existing traffic management node.
 *
 * @param hw_if_idx - Hardware interface index
 * @param node_idx - Index of the TM node to be suspended.
 *
 * @return 0 on success.
 */
int tm_sys_node_suspend (u32 hw_if_idx, u32 node_idx);

/**
 * @brief Resume a suspended traffic management node.
 *
 * @param hw_if_idx - Hardware interface index
 * @param node_idx - Index of the TM node to be resumed.
 *
 * @return 0 on success.
 */
int tm_sys_node_resume (u32 hw_if_idx, u32 node_idx);

/**
 * @brief Delete an existing traffic management node.
 * A node can only be deleted if it has no child nodes
 * connected to it.
 *
 * @param hw_if_idx - Hardware interface index
 * @param node_idx - Index of the TM node to be deleted.
 *
 * @return 0 on success.
 */
int tm_sys_node_delete (u32 hw_if_idx, u32 node_idx);

/**
 * @brief Create a new shaper profile for traffic management.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param param - Pointer to the structure containing the shaper parameters.
 *
 * @return 0 on success.
 */
int tm_sys_shaper_profile_create (u32 hw_if_idx, tm_shaper_params_t *param);

/**
 * @brief Update the shaper profile id of a TM node.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param node_id - Identifier of the TM node to be updated.
 * @param shaper_profile_id - Identifier of the new shaper profile to be
 * applied.
 *
 * @return 0 on success.
 */
int tm_sys_node_shaper_update (u32 hw_if_idx, u32 node_id,
			       u32 shaper_profile_id);

/**
 * @brief Delete an existing shaper profile.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param shaper_id - Identifier of the shaper profile to be deleted.
 *
 * @return 0 on success.
 */
int tm_sys_shaper_profile_delete (u32 hw_if_idx, u32 shaper_id);

/**
 * @brief Update the scheduling weight of a TM node.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param node_id - Identifier of the TM node to be updated.
 * @param weight - New scheduling weight to be assigned to the node.
 *
 * @return 0 on success.
 */
int tm_sys_node_sched_weight_update (u32 hw_if_idx, u32 node_id, u32 weight);

/**
 * @brief Read statistics for a specific traffic management node.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param node_idx - Index of the TM node whose statistics are to be read.
 * @param param - Pointer to the structure where the statistics will be stored.
 *
 * @return 0 on success.
 */
int tm_sys_node_read_stats (u32 hw_if_idx, u32 node_idx,
			    tm_stats_params_t *param);
/**
 * @brief Read Capabilities for a specific traffic management system.
 */
int tm_sys_get_capabilities (u32 hw_if_idx, tm_capa_params_t *capa_param);

/**
 * @brief Read level Capabilities for a specific traffic management system.
 */
int tm_sys_level_get_capabilities (u32 hw_if_idx, tm_level_capa_params_t *cap,
				   u32 lvl);

/**
 * @brief Start the traffic management system.
 *
 * @param hw_if_idx - Hardware interface index.
 *
 * @return 0 on success.
 */
int tm_sys_start_tm (u32 hw_if_idx);

/**
 * @brief Stop the traffic management system.
 *
 * @param hw_if_idx - Hardware interface index.
 *
 * @return 0 on success.
 */
int tm_sys_stop_tm (u32 hw_if_idx);

/**
 * @brief Register the traffic management (TM) system.
 *
 * @param tm_sys - Pointer to the TM system structure to be registered.
 * @param hw_if_idx - Hardware interface index.
 *
 * @return 0 on success.
 */
int tm_system_register (tm_system_t *tm_sys, u32 hw_if_idx);
#endif // _TM_H_
