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
/*
 * ethernet.h: types/functions for ethernet.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_ethernet_h
#define included_ethernet_h

#include <vnet/vnet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/pg/pg.h>
#include <vnet/feature/feature.h>

always_inline u64
ethernet_mac_address_u64 (u8 * a)
{
  return (((u64) a[0] << (u64) (5 * 8))
	  | ((u64) a[1] << (u64) (4 * 8))
	  | ((u64) a[2] << (u64) (3 * 8))
	  | ((u64) a[3] << (u64) (2 * 8))
	  | ((u64) a[4] << (u64) (1 * 8)) | ((u64) a[5] << (u64) (0 * 8)));
}

static inline int
ethernet_mac_address_is_multicast_u64 (u64 a)
{
  return (a & (1ULL << (5 * 8))) != 0;
}

static_always_inline int
ethernet_frame_is_tagged (u16 type)
{
#if __SSE4_2__
  const __m128i ethertype_mask = _mm_set_epi16 (ETHERNET_TYPE_VLAN,
						ETHERNET_TYPE_DOT1AD,
						ETHERNET_TYPE_VLAN_9100,
						ETHERNET_TYPE_VLAN_9200,
						/* duplicate last one to
						   fill register */
						ETHERNET_TYPE_VLAN_9200,
						ETHERNET_TYPE_VLAN_9200,
						ETHERNET_TYPE_VLAN_9200,
						ETHERNET_TYPE_VLAN_9200);

  __m128i r = _mm_set1_epi16 (type);
  r = _mm_cmpeq_epi16 (ethertype_mask, r);
  return !_mm_test_all_zeros (r, r);
#else
  if ((type == ETHERNET_TYPE_VLAN) ||
      (type == ETHERNET_TYPE_DOT1AD) ||
      (type == ETHERNET_TYPE_VLAN_9100) || (type == ETHERNET_TYPE_VLAN_9200))
    return 1;
#endif
  return 0;
}

/* Max. sized ethernet/vlan header for parsing. */
typedef struct
{
  ethernet_header_t ethernet;

  /* Allow up to 2 stacked vlan headers. */
  ethernet_vlan_header_t vlan[2];
} ethernet_max_header_t;

struct vnet_hw_interface_t;
/* Ethernet flag change callback. */
typedef u32 (ethernet_flag_change_function_t)
  (vnet_main_t * vnm, struct vnet_hw_interface_t * hi, u32 flags);

#define ETHERNET_MIN_PACKET_BYTES  64
#define ETHERNET_MAX_PACKET_BYTES  9216

/* Ethernet interface instance. */
typedef struct ethernet_interface
{

  /* Accept all packets (promiscuous mode). */
#define ETHERNET_INTERFACE_FLAG_ACCEPT_ALL (1 << 0)
#define ETHERNET_INTERFACE_FLAG_CONFIG_PROMISC(flags) \
  (((flags) & ~ETHERNET_INTERFACE_FLAG_ACCEPT_ALL) == 0)

  /* Change MTU on interface from hw interface structure */
#define ETHERNET_INTERFACE_FLAG_MTU (1 << 1)
#define ETHERNET_INTERFACE_FLAG_CONFIG_MTU(flags) \
  ((flags) & ETHERNET_INTERFACE_FLAG_MTU)

  /* Callback, e.g. to turn on/off promiscuous mode */
  ethernet_flag_change_function_t *flag_change;

  u32 driver_instance;

  /* Ethernet (MAC) address for this interface. */
  u8 address[6];
} ethernet_interface_t;

extern vnet_hw_interface_class_t ethernet_hw_interface_class;

typedef struct
{
  /* Name (a c string). */
  char *name;

  /* Ethernet type in host byte order. */
  ethernet_type_t type;

  /* Node which handles this type. */
  u32 node_index;

  /* Next index for this type. */
  u32 next_index;
} ethernet_type_info_t;

typedef enum
{
#define ethernet_error(n,c,s) ETHERNET_ERROR_##n,
#include <vnet/ethernet/error.def>
#undef ethernet_error
  ETHERNET_N_ERROR,
} ethernet_error_t;


// Structs used when parsing packet to find sw_if_index

typedef struct
{
  u32 sw_if_index;
  u32 flags;
  // config entry is-valid flag
  // exact match flags (valid if packet has 0/1/2/3 tags)
  // L2 vs L3 forwarding mode
#define SUBINT_CONFIG_MATCH_0_TAG (1<<0)
#define SUBINT_CONFIG_MATCH_1_TAG (1<<1)
#define SUBINT_CONFIG_MATCH_2_TAG (1<<2)
#define SUBINT_CONFIG_MATCH_3_TAG (1<<3)
#define SUBINT_CONFIG_VALID       (1<<4)
#define SUBINT_CONFIG_L2          (1<<5)
#define SUBINT_CONFIG_P2P         (1<<6)

} subint_config_t;

always_inline u32
eth_create_valid_subint_match_flags (u32 num_tags)
{
  return SUBINT_CONFIG_VALID | (1 << num_tags);
}


typedef struct
{
  subint_config_t untagged_subint;
  subint_config_t default_subint;
  u16 dot1q_vlans;		// pool id for vlan table
  u16 dot1ad_vlans;		// pool id for vlan table
} main_intf_t;

typedef struct
{
  subint_config_t single_tag_subint;
  subint_config_t inner_any_subint;
  u32 qinqs;			// pool id for qinq table
} vlan_intf_t;

typedef struct
{
  vlan_intf_t vlans[ETHERNET_N_VLAN];
} vlan_table_t;

typedef struct
{
  subint_config_t subint;
} qinq_intf_t;

typedef struct
{
  qinq_intf_t vlans[ETHERNET_N_VLAN];
} qinq_table_t;

// Structure mapping to a next index based on ethertype.
// Common ethertypes are stored explicitly, others are
// stored in a sparse table.
typedef struct
{
  /* Sparse vector mapping ethernet type in network byte order
     to next index. */
  u16 *input_next_by_type;
  u32 *sparse_index_by_input_next_index;

  /* cached next indexes for common ethertypes */
  u32 input_next_ip4;
  u32 input_next_ip6;
  u32 input_next_mpls;
} next_by_ethertype_t;

typedef struct
{
  vlib_main_t *vlib_main;

  /* next node index for the L3 input node of each ethertype */
  next_by_ethertype_t l3_next;

  /* next node index for L2 interfaces */
  u32 l2_next;

  /* flag and next node index for L3 redirect */
  u32 redirect_l3;
  u32 redirect_l3_next;

  /* Pool of ethernet interface instances. */
  ethernet_interface_t *interfaces;

  ethernet_type_info_t *type_infos;

  /* Hash tables mapping name/type to type info index. */
  uword *type_info_by_name, *type_info_by_type;

  // The root of the vlan parsing tables. A vector with one element
  // for each main interface, indexed by hw_if_index.
  main_intf_t *main_intfs;

  // Pool of vlan tables
  vlan_table_t *vlan_pool;

  // Pool of qinq tables;
  qinq_table_t *qinq_pool;

  /* Set to one to use AB.CD.EF instead of A:B:C:D:E:F as ethernet format. */
  int format_ethernet_address_16bit;

  /* debug: make sure we don't wipe out an ethernet registration by mistake */
  u8 next_by_ethertype_register_called;

  /* Feature arc index */
  u8 output_feature_arc_index;

  /* Allocated loopback instances */
  uword *bm_loopback_instances;
} ethernet_main_t;

ethernet_main_t ethernet_main;

always_inline ethernet_type_info_t *
ethernet_get_type_info (ethernet_main_t * em, ethernet_type_t type)
{
  uword *p = hash_get (em->type_info_by_type, type);
  return p ? vec_elt_at_index (em->type_infos, p[0]) : 0;
}

ethernet_interface_t *ethernet_get_interface (ethernet_main_t * em,
					      u32 hw_if_index);

clib_error_t *ethernet_register_interface (vnet_main_t * vnm,
					   u32 dev_class_index,
					   u32 dev_instance,
					   u8 * address,
					   u32 * hw_if_index_return,
					   ethernet_flag_change_function_t
					   flag_change);

void ethernet_delete_interface (vnet_main_t * vnm, u32 hw_if_index);

/* Register given node index to take input for given ethernet type. */
void
ethernet_register_input_type (vlib_main_t * vm,
			      ethernet_type_t type, u32 node_index);

/* Register given node index to take input for packet from L2 interfaces. */
void ethernet_register_l2_input (vlib_main_t * vm, u32 node_index);

/* Register given node index to take redirected L3 traffic, and enable L3 redirect */
void ethernet_register_l3_redirect (vlib_main_t * vm, u32 node_index);

/* Formats ethernet address X:X:X:X:X:X */
u8 *format_ethernet_address (u8 * s, va_list * args);
u8 *format_ethernet_type (u8 * s, va_list * args);
u8 *format_ethernet_vlan_tci (u8 * s, va_list * va);
u8 *format_ethernet_header (u8 * s, va_list * args);
u8 *format_ethernet_header_with_length (u8 * s, va_list * args);

/* Parse ethernet address in either X:X:X:X:X:X unix or X.X.X cisco format. */
uword unformat_ethernet_address (unformat_input_t * input, va_list * args);

/* Parse ethernet type as 0xXXXX or type name from ethernet/types.def.
   In either host or network byte order. */
uword
unformat_ethernet_type_host_byte_order (unformat_input_t * input,
					va_list * args);
uword
unformat_ethernet_type_net_byte_order (unformat_input_t * input,
				       va_list * args);

/* Parse ethernet header. */
uword unformat_ethernet_header (unformat_input_t * input, va_list * args);

/* Parse ethernet interface name; return hw_if_index. */
uword unformat_ethernet_interface (unformat_input_t * input, va_list * args);

uword unformat_pg_ethernet_header (unformat_input_t * input, va_list * args);

always_inline void
ethernet_setup_node (vlib_main_t * vm, u32 node_index)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  pg_node_t *pn = pg_get_node (node_index);

  n->format_buffer = format_ethernet_header_with_length;
  n->unformat_buffer = unformat_ethernet_header;
  pn->unformat_edit = unformat_pg_ethernet_header;
}

always_inline ethernet_header_t *
ethernet_buffer_get_header (vlib_buffer_t * b)
{
  return (void *) (b->data + vnet_buffer (b)->l2_hdr_offset);
}

/** Returns the number of VLAN headers in the current Ethernet frame in the
 * buffer. Returns 0, 1, 2 for the known header count. The value 3 indicates
 * the number of headers is not known.
 */
#define ethernet_buffer_get_vlan_count(b) ( \
    ((b)->flags & VNET_BUFFER_FLAGS_VLAN_BITS) >> VNET_BUFFER_F_LOG2_VLAN_1_DEEP \
)

/** Sets the number of VLAN headers in the current Ethernet frame in the
 * buffer. Values 0, 1, 2 indicate  the header count. The value 3 indicates
 * the number of headers is not known.
 */
#define ethernet_buffer_set_vlan_count(b, v) ( \
    (b)->flags = ((b)->flags & ~VNET_BUFFER_FLAGS_VLAN_BITS) | \
        (((v) << VNET_BUFFER_F_LOG2_VLAN_1_DEEP) & VNET_BUFFER_FLAGS_VLAN_BITS) \
)

/** Adjusts the vlan count by the delta in 'v' */
#define ethernet_buffer_adjust_vlan_count(b, v) ( \
  ethernet_buffer_set_vlan_count(b,  \
      (word)ethernet_buffer_get_vlan_count(b) + (word)(v)) \
)

/** Adjusts the vlan count by the header size byte delta in 'v' */
#define ethernet_buffer_adjust_vlan_count_by_bytes(b, v) ( \
    (b)->flags = ((b)->flags & ~VNET_BUFFER_FLAGS_VLAN_BITS) | (( \
        ((b)->flags & VNET_BUFFER_FLAGS_VLAN_BITS) + \
        ((v) << (VNET_BUFFER_F_LOG2_VLAN_1_DEEP - 2)) \
    ) & VNET_BUFFER_FLAGS_VLAN_BITS) \
)

/**
 * Determine the size of the Ethernet headers of the current frame in
 * the buffer. This uses the VLAN depth flags that are set by
 * ethernet-input. Because these flags are stored in the vlib_buffer_t
 * "flags" field this count is valid regardless of the node so long as it's
 * checked downstream of ethernet-input; That is, the value is not stored in
 * the opaque space.
 */
#define ethernet_buffer_header_size(b) ( \
        ethernet_buffer_get_vlan_count((b)) * sizeof(ethernet_vlan_header_t) + \
        sizeof(ethernet_header_t) \
)

ethernet_main_t *ethernet_get_main (vlib_main_t * vm);
u32 ethernet_set_flags (vnet_main_t * vnm, u32 hw_if_index, u32 flags);
void ethernet_sw_interface_set_l2_mode (vnet_main_t * vnm, u32 sw_if_index,
					u32 l2);
void ethernet_sw_interface_set_l2_mode_noport (vnet_main_t * vnm,
					       u32 sw_if_index, u32 l2);
void ethernet_set_rx_redirect (vnet_main_t * vnm, vnet_hw_interface_t * hi,
			       u32 enable);

int
vnet_arp_set_ip4_over_ethernet (vnet_main_t * vnm,
				u32 sw_if_index, void *a_arg,
				int is_static, int is_no_fib_entry);

int
vnet_arp_unset_ip4_over_ethernet (vnet_main_t * vnm,
				  u32 sw_if_index, void *a_arg);

int vnet_proxy_arp_fib_reset (u32 fib_id);

clib_error_t *next_by_ethertype_init (next_by_ethertype_t * l3_next);
clib_error_t *next_by_ethertype_register (next_by_ethertype_t * l3_next,
					  u32 ethertype, u32 next_index);

int vnet_create_loopback_interface (u32 * sw_if_indexp, u8 * mac_address,
				    u8 is_specified, u32 user_instance);
int vnet_delete_loopback_interface (u32 sw_if_index);
int vnet_delete_sub_interface (u32 sw_if_index);

// Perform ethernet subinterface classification table lookups given
// the ports's sw_if_index and fields extracted from the ethernet header.
// The resulting tables are used by identify_subint().
always_inline void
eth_vlan_table_lookups (ethernet_main_t * em,
			vnet_main_t * vnm,
			u32 port_sw_if_index0,
			u16 first_ethertype,
			u16 outer_id,
			u16 inner_id,
			vnet_hw_interface_t ** hi,
			main_intf_t ** main_intf,
			vlan_intf_t ** vlan_intf, qinq_intf_t ** qinq_intf)
{
  vlan_table_t *vlan_table;
  qinq_table_t *qinq_table;
  u32 vlan_table_id;

  // Read the main, vlan, and qinq interface table entries
  // TODO: Consider if/how to prefetch tables. Also consider
  // single-entry cache to skip table lookups and identify_subint()
  // processing.
  *hi = vnet_get_sup_hw_interface (vnm, port_sw_if_index0);
  *main_intf = vec_elt_at_index (em->main_intfs, (*hi)->hw_if_index);

  // Always read the vlan and qinq tables, even if there are not that
  // many tags on the packet. This makes the lookups and comparisons
  // easier (and less branchy).
  vlan_table_id = (first_ethertype == ETHERNET_TYPE_DOT1AD) ?
    (*main_intf)->dot1ad_vlans : (*main_intf)->dot1q_vlans;
  vlan_table = vec_elt_at_index (em->vlan_pool, vlan_table_id);
  *vlan_intf = &vlan_table->vlans[outer_id];

  qinq_table = vec_elt_at_index (em->qinq_pool, (*vlan_intf)->qinqs);
  *qinq_intf = &qinq_table->vlans[inner_id];
}


// Determine the subinterface for this packet, given the result of the
// vlan table lookups and vlan header parsing. Check the most specific
// matches first.
// Returns 1 if a matching subinterface was found, otherwise returns 0.
always_inline u32
eth_identify_subint (vnet_hw_interface_t * hi,
		     vlib_buffer_t * b0,
		     u32 match_flags,
		     main_intf_t * main_intf,
		     vlan_intf_t * vlan_intf,
		     qinq_intf_t * qinq_intf,
		     u32 * new_sw_if_index, u8 * error0, u32 * is_l2)
{
  subint_config_t *subint;

  // Each comparison is checking both the valid flag and the number of tags
  // (incorporating exact-match/non-exact-match).

  // check for specific double tag
  subint = &qinq_intf->subint;
  if ((subint->flags & match_flags) == match_flags)
    goto matched;

  // check for specific outer and 'any' inner
  subint = &vlan_intf->inner_any_subint;
  if ((subint->flags & match_flags) == match_flags)
    goto matched;

  // check for specific single tag
  subint = &vlan_intf->single_tag_subint;
  if ((subint->flags & match_flags) == match_flags)
    goto matched;

  // check for untagged interface
  subint = &main_intf->untagged_subint;
  if ((subint->flags & match_flags) == match_flags)
    goto matched;

  // check for default interface
  subint = &main_intf->default_subint;
  if ((subint->flags & match_flags) == match_flags)
    goto matched;

  // No matching subinterface
  *new_sw_if_index = ~0;
  *error0 = ETHERNET_ERROR_UNKNOWN_VLAN;
  *is_l2 = 0;
  return 0;

matched:
  *new_sw_if_index = subint->sw_if_index;
  *is_l2 = subint->flags & SUBINT_CONFIG_L2;
  return 1;
}

// Compare two ethernet macs. Return 1 if they are the same, 0 if different
always_inline u32
eth_mac_equal (u8 * mac1, u8 * mac2)
{
  return (*((u32 *) (mac1 + 0)) == *((u32 *) (mac2 + 0)) &&
	  *((u32 *) (mac1 + 2)) == *((u32 *) (mac2 + 2)));
}


always_inline ethernet_main_t *
vnet_get_ethernet_main (void)
{
  return &ethernet_main;
}

void vnet_register_ip4_arp_resolution_event (vnet_main_t * vnm,
					     void *address_arg,
					     uword node_index,
					     uword type_opaque, uword data);


int vnet_add_del_ip4_arp_change_event (vnet_main_t * vnm,
				       void *data_callback,
				       u32 pid,
				       void *address_arg,
				       uword node_index,
				       uword type_opaque,
				       uword data, int is_add);

void wc_arp_set_publisher_node (uword inode_index, uword event_type);

void ethernet_arp_change_mac (u32 sw_if_index);
void ethernet_ndp_change_mac (u32 sw_if_index);

void arp_update_adjacency (vnet_main_t * vnm, u32 sw_if_index, u32 ai);

void ethernet_update_adjacency (vnet_main_t * vnm, u32 sw_if_index, u32 ai);
u8 *ethernet_build_rewrite (vnet_main_t * vnm,
			    u32 sw_if_index,
			    vnet_link_t link_type, const void *dst_address);
const u8 *ethernet_ip4_mcast_dst_addr (void);
const u8 *ethernet_ip6_mcast_dst_addr (void);

extern vlib_node_registration_t ethernet_input_node;

typedef struct
{
  u32 sw_if_index;
  u32 ip4;
  u8 mac[6];
} wc_arp_report_t;

#endif /* included_ethernet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
