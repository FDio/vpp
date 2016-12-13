/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 * @brief Segment Routing data structures definitions
 *
 */

#ifndef included_vnet_sr_h
#define included_vnet_sr_h

#include <vnet/vnet.h>
#include <vnet/sr/sr_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ethernet/ethernet.h>

#include <stdlib.h>
#include <string.h>

#define IPv6_DEFAULT_HEADER_LENGTH 40
#define IPv6_DEFAULT_HOP_LIMIT 64
#define IPv6_DEFAULT_MAX_MASK_WIDTH 128

#define SR_BEHAVIOR_END 1
#define SR_BEHAVIOR_Xv6 2
#define SR_BEHAVIOR_Xv4 3
#define SR_BEHAVIOR_T 4
#define SR_BEHAVIOR_XL2 5 
#define SR_BEHAVIOR_LAST 6		/* Must always be the last one */

#define SR_STEER_L2 2
#define SR_STEER_IPV4 4
#define SR_STEER_IPV6 6

#define SR_FUNCTION_SIZE 4
#define SR_ARGUMENT_SIZE 4

#define SR_SEGMENT_LIST_WEIGHT_DEFAULT 1

/**
 * @brief SR Segment List (SID list)
 */
typedef struct {
	ip6_address_t *segments;	/**< SIDs (key) */

	u32 weight;					/**< SID list weight (wECMP / UCMP) */

	u8 * rewrite;				/**< Precomputed rewrite header */
	u8 * rewrite_bsid;			/**< Precomputed rewrite header for bindingSID */

	dpo_id_t dpo;				/**< FIB DPO index for this SID list */
} ip6_sr_sl_t;

/* SR policy types */
#define SR_POLICY_TYPE_DEFAULT 0
#define SR_POLICY_TYPE_SPRAY 1

/**
 * @brief SR Policy
 */
typedef struct {
	u32 *segments_lists;	/**< SID lists indexes (vector) */

	ip6_address_t bsid;		/**< BindingSID (key) */

	u8 type;				/**< Type (default is 0) */

	/* SR Policy specific DPO 										*/
	/* IF Type = DEFAULT Then Load Balancer DPO among SID lists 	*/
	/* IF Type = SPRAY then Spray DPO with all SID lists 			*/
	dpo_id_t dpo;			/**< SR Policy specific DPO */

	u32 fib_table;			/**< FIB table */

	u8 is_encap;				/**< Mode (0 is SRH insert, 1 Encaps) */
} ip6_sr_policy_t;

/**
 * @brief SR LocalSID
 */
typedef struct {
	ip6_address_t localsid;  	/**< LocalSID IPv6 address */

	char decap_allowed;			/**< Decapsulation allowed boolean */

	char cleanup;				/**< Cleanup allowed boolean */

	u16 behavior;				/**< Behavior associated to this localsid */

	union {
		u32 sw_if_index;		/**< xconnect only */
		u32 vrf_index;			/**< vrf only */
	};

	u32 fib_table; 				/**< FIB table where localsid is registered */

	u32 vlan_index;				/**< VLAN tag (not an index) */

	ip46_address_t next_hop;	/**< Next_hop for xconnect usage only */

	u32 nh_adj;					/**< Next_adj for xconnect usage only */

	void *plugin_mem;			/**< Memory to be used by the plugin callback functions */
} ip6_sr_localsid_t;


typedef void (sr_plugin_callback_t) (ip6_sr_localsid_t *localsid);

/** 
 * @brief SR LocalSID behavior registration 
 */
typedef struct {
	u16 sr_localsid_function_number;		/**< SR LocalSID plugin function (>SR_BEHAVIOR_LAST) */
	
	u8 *function_name;					/**< Function name. (key). */
	
	dpo_type_t dpo;							/**< DPO type registration */
	
	format_function_t *ls_format;			/**< LocalSID format function */
	
	unformat_function_t *ls_unformat;		/**< LocalSID unformat function */
	
	sr_plugin_callback_t * creation;		/**< Function within plugin that will be called after localsid creation*/
	
	sr_plugin_callback_t * removal; 		/**< Function within plugin that will be called before localsid removal */
} sr_localsid_fn_registration_t;

/**
 * @brief Steering db key
 *
 * L3 is IPv4/IPv6 + mask
 * L2 is sf_if_index + vlan
 */
typedef struct {
	union {
		struct {
			ip46_address_t prefix;	/**< IP address of the prefix */
			u32 mask_width;			/**< Mask width of the prefix */
			u32 fib_table;			/**< VRF of the prefix */
		} l3;
		struct {
			u32 sw_if_index;		/**< Incoming software interface */
		} l2;
	};
	u8 traffic_type;				/**< Traffic type (IPv4, IPv6, L2) */
} sr_steering_key_t;

typedef struct {
	sr_steering_key_t classify; 	/**< Traffic classification */
	u32 sr_policy;					/**< SR Policy index */
} ip6_sr_steering_policy_t;

/**
 * @brief Segment Routing main datastructure
 */
typedef struct {
	/* ip6-lookup next index for imposition FIB entries */
	u32 ip6_lookup_sr_next_index;

	/* ip6-replicate next index for multicast tunnel */
	u32 ip6_lookup_sr_spray_index;

	/* IP4-lookup -> SR rewrite next index */
	u32 ip4_lookup_sr_policy_rewrite_encaps_index;
	u32 ip4_lookup_sr_policy_rewrite_insert_index;

	/* IP6-lookup -> SR rewrite next index */
	u32 ip6_lookup_sr_policy_rewrite_encaps_index;
	u32 ip6_lookup_sr_policy_rewrite_insert_index;

	/* L2-input -> SR rewrite next index */
	u32 l2_sr_policy_rewrite_index;

	/* IP6-lookup -> SR LocalSID (SR End processing) index */
	u32 ip6_lookup_sr_localsid_index;

	/* SR SID lists */
	ip6_sr_sl_t *sid_lists;

	/* SR policies */
	ip6_sr_policy_t *sr_policies;

	/* Find an SR policy by its BindingSID */
	ip6_address_t *sr_policy_index_by_key;

	/* Pool of SR localsid instances */
	ip6_sr_localsid_t *localsids;

	/* Find a SR localsid instance based on its functionID */
	ip6_address_t *localsids_index_by_key;

	/* Pool of SR steer policies instances */
	ip6_sr_steering_policy_t *steer_policies;

	/* Find a steer policy based on its classifier */
	sr_steering_key_t *steer_policies_index_by_key;

	/* Spray DPO */
	dpo_type_t sr_pr_spray_dpo_type;

	/* Plugin functions */
	sr_localsid_fn_registration_t *plugin_functions;

	/* Find plugin function by name */
	uword *plugin_functions_by_key;

	/* convenience */
	vlib_main_t * vlib_main;
	vnet_main_t * vnet_main;
} ip6_sr_main_t;

ip6_sr_main_t sr_main;

extern vlib_node_registration_t sr_policy_rewrite_encaps_node;
extern vlib_node_registration_t sr_policy_rewrite_insert_node;
extern vlib_node_registration_t sr_localsid_node;
#if DPDK > 0
extern vlib_node_registration_t sr_spray_node;
#endif /* DPDK */

void sr_dpo_lock (dpo_id_t * dpo);
void sr_dpo_unlock (dpo_id_t * dpo);

#endif /* included_vnet_sr_h */
