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
 * interface.h: VNET interfaces/sub-interfaces
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

#ifndef included_vnet_interface_h
#define included_vnet_interface_h

#include <vnet/unix/pcap.h>
#include <vnet/l3_types.h>

struct vnet_main_t;
struct vnet_hw_interface_t;
struct vnet_sw_interface_t;
struct ip46_address_t;

/* Interface up/down callback. */
typedef clib_error_t *(vnet_interface_function_t)
  (struct vnet_main_t * vnm, u32 if_index, u32 flags);

/* Sub-interface add/del callback. */
typedef clib_error_t *(vnet_subif_add_del_function_t)
  (struct vnet_main_t * vnm, u32 if_index,
   struct vnet_sw_interface_t * template, int is_add);

/* Interface set mac address callback. */
typedef clib_error_t *(vnet_interface_set_mac_address_function_t)
  (struct vnet_hw_interface_t * hi, char *address);

typedef enum vnet_interface_function_priority_t_
{
  VNET_ITF_FUNC_PRIORITY_LOW,
  VNET_ITF_FUNC_PRIORITY_HIGH,
} vnet_interface_function_priority_t;
#define VNET_ITF_FUNC_N_PRIO ((vnet_interface_function_priority_t)VNET_ITF_FUNC_PRIORITY_HIGH+1)

typedef struct _vnet_interface_function_list_elt
{
  struct _vnet_interface_function_list_elt *next_interface_function;
  clib_error_t *(*fp) (struct vnet_main_t * vnm, u32 if_index, u32 flags);
} _vnet_interface_function_list_elt_t;

#define _VNET_INTERFACE_FUNCTION_DECL(f,tag)                            \
                                                                        \
static void __vnet_interface_function_init_##tag##_##f (void)           \
    __attribute__((__constructor__)) ;                                  \
                                                                        \
static void __vnet_interface_function_init_##tag##_##f (void)           \
{                                                                       \
 vnet_main_t * vnm = vnet_get_main();                                   \
 static _vnet_interface_function_list_elt_t init_function;              \
 init_function.next_interface_function =                                \
   vnm->tag##_functions[VNET_ITF_FUNC_PRIORITY_LOW];                    \
 vnm->tag##_functions[VNET_ITF_FUNC_PRIORITY_LOW] = &init_function;     \
 init_function.fp = (void *) &f;                                        \
}

#define _VNET_INTERFACE_FUNCTION_DECL_PRIO(f,tag,p)                    \
                                                                        \
static void __vnet_interface_function_init_##tag##_##f (void)           \
    __attribute__((__constructor__)) ;                                  \
                                                                        \
static void __vnet_interface_function_init_##tag##_##f (void)           \
{                                                                       \
 vnet_main_t * vnm = vnet_get_main();                                   \
 static _vnet_interface_function_list_elt_t init_function;              \
 init_function.next_interface_function = vnm->tag##_functions[p];       \
 vnm->tag##_functions[p] = &init_function;                              \
 init_function.fp = (void *) &f;                                        \
}

#define VNET_HW_INTERFACE_ADD_DEL_FUNCTION(f)			\
  _VNET_INTERFACE_FUNCTION_DECL(f,hw_interface_add_del)
#define VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION(f)		\
  _VNET_INTERFACE_FUNCTION_DECL(f,hw_interface_link_up_down)
#define VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION_PRIO(f,p)        \
  _VNET_INTERFACE_FUNCTION_DECL_PRIO(f,hw_interface_link_up_down,p)
#define VNET_SW_INTERFACE_ADD_DEL_FUNCTION(f)			\
  _VNET_INTERFACE_FUNCTION_DECL(f,sw_interface_add_del)
#define VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(f)		\
  _VNET_INTERFACE_FUNCTION_DECL(f,sw_interface_admin_up_down)
#define VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION_PRIO(f,p)     	\
  _VNET_INTERFACE_FUNCTION_DECL_PRIO(f,sw_interface_admin_up_down, p)

/* A class of hardware interface devices. */
typedef struct _vnet_device_class
{
  /* Index into main vector. */
  u32 index;

  /* Device name (e.g. "FOOBAR 1234a"). */
  char *name;

  /* Function to call when hardware interface is added/deleted. */
  vnet_interface_function_t *interface_add_del_function;

  /* Function to bring device administratively up/down. */
  vnet_interface_function_t *admin_up_down_function;

  /* Function to call when sub-interface is added/deleted */
  vnet_subif_add_del_function_t *subif_add_del_function;

  /* Redistribute flag changes/existence of this interface class. */
  u32 redistribute;

  /* Transmit function. */
  vlib_node_function_t *tx_function;

  /* Error strings indexed by error code for this node. */
  char **tx_function_error_strings;

  /* Number of error codes used by this node. */
  u32 tx_function_n_errors;

  /* Renumber device name [only!] support, a control-plane kludge */
  int (*name_renumber) (struct vnet_hw_interface_t * hi,
			u32 new_dev_instance);

  /* Format device instance as name. */
  format_function_t *format_device_name;

  /* Parse function for device name. */
  unformat_function_t *unformat_device_name;

  /* Format device verbosely for this class. */
  format_function_t *format_device;

  /* Trace buffer format for TX function. */
  format_function_t *format_tx_trace;

  /* Function to clear hardware counters for device. */
  void (*clear_counters) (u32 dev_class_instance);

    uword (*is_valid_class_for_interface) (struct vnet_main_t * vnm,
					   u32 hw_if_index,
					   u32 hw_class_index);

  /* Called when hardware class of an interface changes. */
  void (*hw_class_change) (struct vnet_main_t * vnm,
			   u32 hw_if_index, u32 new_hw_class_index);

  /* Called to redirect traffic from a specific interface instance */
  void (*rx_redirect_to_node) (struct vnet_main_t * vnm,
			       u32 hw_if_index, u32 node_index);

  /* Link-list of all device classes set up by constructors created below */
  struct _vnet_device_class *next_class_registration;

  /* Splice vnet_interface_output_node into TX path */
  u8 flatten_output_chains;

  /* Function to set mac address. */
  vnet_interface_set_mac_address_function_t *mac_addr_change_function;
} vnet_device_class_t;

#define VNET_DEVICE_CLASS(x,...)                                        \
  __VA_ARGS__ vnet_device_class_t x;                                    \
static void __vnet_add_device_class_registration_##x (void)             \
    __attribute__((__constructor__)) ;                                  \
static void __vnet_add_device_class_registration_##x (void)             \
{                                                                       \
    vnet_main_t * vnm = vnet_get_main();                                \
    x.next_class_registration = vnm->device_class_registrations;        \
    vnm->device_class_registrations = &x;                               \
}                                                                       \
__VA_ARGS__ vnet_device_class_t x

#define VLIB_DEVICE_TX_FUNCTION_CLONE_TEMPLATE(arch, fn, tgt)		\
  uword									\
  __attribute__ ((flatten))						\
  __attribute__ ((target (tgt)))					\
  CLIB_CPU_OPTIMIZED							\
  fn ## _ ## arch ( vlib_main_t * vm,					\
                   vlib_node_runtime_t * node,				\
                   vlib_frame_t * frame)				\
  { return fn (vm, node, frame); }

#define VLIB_DEVICE_TX_FUNCTION_MULTIARCH_CLONE(fn)			\
  foreach_march_variant(VLIB_DEVICE_TX_FUNCTION_CLONE_TEMPLATE, fn)

#if CLIB_DEBUG > 0
#define VLIB_MULTIARCH_CLONE_AND_SELECT_FN(fn,...)
#define VLIB_DEVICE_TX_FUNCTION_MULTIARCH(dev, fn)
#else
#define VLIB_DEVICE_TX_FUNCTION_MULTIARCH(dev, fn)			\
  VLIB_DEVICE_TX_FUNCTION_MULTIARCH_CLONE(fn)				\
  CLIB_MULTIARCH_SELECT_FN(fn, static inline)				\
  static void __attribute__((__constructor__))				\
  __vlib_device_tx_function_multiarch_select_##dev (void)		\
  { dev.tx_function = fn ## _multiarch_select(); }
#endif

/**
 * Link Type: A description of the protocol of packets on the link.
 * On an ethernet link this maps directly into the ethertype. On a GRE tunnel
 * it maps to the GRE-proto, etc for other lnk types.
 */
typedef enum vnet_link_t_
{
#if CLIB_DEBUG > 0
  VNET_LINK_IP4 = 1,
#else
  VNET_LINK_IP4 = 0,
#endif
  VNET_LINK_IP6,
  VNET_LINK_MPLS,
  VNET_LINK_ETHERNET,
  VNET_LINK_ARP,
  VNET_LINK_NSH,
} __attribute__ ((packed)) vnet_link_t;

#define VNET_LINKS {                   \
    [VNET_LINK_ETHERNET] = "ethernet", \
    [VNET_LINK_IP4] = "ipv4",          \
    [VNET_LINK_IP6] = "ipv6",          \
    [VNET_LINK_MPLS] = "mpls",         \
    [VNET_LINK_ARP] = "arp",	       \
    [VNET_LINK_NSH] = "nsh",           \
}

/**
 * @brief Number of link types. Not part of the enum so it does not have to be included in
 * switch statements
 */
#define VNET_LINK_NUM (VNET_LINK_NSH+1)

/**
 * @brief Convert a link to to an Ethertype
 */
extern vnet_l3_packet_type_t vnet_link_to_l3_proto (vnet_link_t link);

/**
 * @brief Attributes assignable to a HW interface Class.
 */
typedef enum vnet_hw_interface_class_flags_t_
{
  /**
   * @brief a point 2 point interface
   */
  VNET_HW_INTERFACE_CLASS_FLAG_P2P = (1 << 0),
} vnet_hw_interface_class_flags_t;

/* Layer-2 (e.g. Ethernet) interface class. */
typedef struct _vnet_hw_interface_class
{
  /* Index into main vector. */
  u32 index;

  /* Class name (e.g. "Ethernet"). */
  char *name;

  /* Flags */
  vnet_hw_interface_class_flags_t flags;

  /* Function to call when hardware interface is added/deleted. */
  vnet_interface_function_t *interface_add_del_function;

  /* Function to bring interface administratively up/down. */
  vnet_interface_function_t *admin_up_down_function;

  /* Function to call when link state changes. */
  vnet_interface_function_t *link_up_down_function;

  /* Function to call when link MAC changes. */
  vnet_interface_set_mac_address_function_t *mac_addr_change_function;

  /* Format function to display interface name. */
  format_function_t *format_interface_name;

  /* Format function to display interface address. */
  format_function_t *format_address;

  /* Format packet header for this interface class. */
  format_function_t *format_header;

  /* Format device verbosely for this class. */
  format_function_t *format_device;

  /* Parser for hardware (e.g. ethernet) address. */
  unformat_function_t *unformat_hw_address;

  /* Parser for packet header for e.g. rewrite string. */
  unformat_function_t *unformat_header;

  /* Builds a rewrite string for the interface to the destination
   * for the payload/link type. */
  u8 *(*build_rewrite) (struct vnet_main_t * vnm,
			u32 sw_if_index,
			vnet_link_t link_type, const void *dst_hw_address);

  /* Update an adjacecny added by FIB (as opposed to via the
   * neighbour resolution protocol). */
  void (*update_adjacency) (struct vnet_main_t * vnm,
			    u32 sw_if_index, u32 adj_index);

    uword (*is_valid_class_for_interface) (struct vnet_main_t * vnm,
					   u32 hw_if_index,
					   u32 hw_class_index);

  /* Called when hw interface class is changed and old hardware instance
     may want to be deleted. */
  void (*hw_class_change) (struct vnet_main_t * vnm, u32 hw_if_index,
			   u32 old_class_index, u32 new_class_index);

  /* List of hw interface classes, built by constructors */
  struct _vnet_hw_interface_class *next_class_registration;

} vnet_hw_interface_class_t;

/**
 * @brief Return a complete, zero-length (aka dummy) rewrite
 */
extern u8 *default_build_rewrite (struct vnet_main_t *vnm,
				  u32 sw_if_index,
				  vnet_link_t link_type,
				  const void *dst_hw_address);

/**
 * @brief Default adjacency update function
 */
extern void default_update_adjacency (struct vnet_main_t *vnm,
				      u32 sw_if_index, u32 adj_index);

#define VNET_HW_INTERFACE_CLASS(x,...)                                  \
  __VA_ARGS__ vnet_hw_interface_class_t x;                              \
static void __vnet_add_hw_interface_class_registration_##x (void)       \
    __attribute__((__constructor__)) ;                                  \
static void __vnet_add_hw_interface_class_registration_##x (void)       \
{                                                                       \
    vnet_main_t * vnm = vnet_get_main();                                \
    x.next_class_registration = vnm->hw_interface_class_registrations;  \
    vnm->hw_interface_class_registrations = &x;                         \
}                                                                       \
__VA_ARGS__ vnet_hw_interface_class_t x

/* Hardware-interface.  This corresponds to a physical wire
   that packets flow over. */
typedef struct vnet_hw_interface_t
{
  /* Interface name. */
  u8 *name;

  u32 flags;
  /* Hardware link state is up. */
#define VNET_HW_INTERFACE_FLAG_LINK_UP		(1 << 0)
  /* Hardware duplex state */
#define VNET_HW_INTERFACE_FLAG_DUPLEX_SHIFT	1
#define VNET_HW_INTERFACE_FLAG_HALF_DUPLEX	(1 << 1)
#define VNET_HW_INTERFACE_FLAG_FULL_DUPLEX	(1 << 2)
#define VNET_HW_INTERFACE_FLAG_DUPLEX_MASK	\
  (VNET_HW_INTERFACE_FLAG_HALF_DUPLEX |		\
   VNET_HW_INTERFACE_FLAG_FULL_DUPLEX)

  /* Hardware link speed */
#define VNET_HW_INTERFACE_FLAG_SPEED_SHIFT	3
#define VNET_HW_INTERFACE_FLAG_SPEED_10M	(1 << 3)
#define VNET_HW_INTERFACE_FLAG_SPEED_100M	(1 << 4)
#define VNET_HW_INTERFACE_FLAG_SPEED_1G		(1 << 5)
#define VNET_HW_INTERFACE_FLAG_SPEED_10G	(1 << 6)
#define VNET_HW_INTERFACE_FLAG_SPEED_40G	(1 << 7)
#define VNET_HW_INTERFACE_FLAG_SPEED_100G	(1 << 8)
#define VNET_HW_INTERFACE_FLAG_SPEED_MASK	\
  (VNET_HW_INTERFACE_FLAG_SPEED_10M |		\
   VNET_HW_INTERFACE_FLAG_SPEED_100M |		\
   VNET_HW_INTERFACE_FLAG_SPEED_1G |		\
   VNET_HW_INTERFACE_FLAG_SPEED_10G |		\
   VNET_HW_INTERFACE_FLAG_SPEED_40G |		\
   VNET_HW_INTERFACE_FLAG_SPEED_100G)

  /* l2output node flags */
#define VNET_HW_INTERFACE_FLAG_L2OUTPUT_SHIFT	9
#define VNET_HW_INTERFACE_FLAG_L2OUTPUT_MAPPED	(1 << 9)

  /* Hardware address as vector.  Zero (e.g. zero-length vector) if no
     address for this class (e.g. PPP). */
  u8 *hw_address;

  /* Interface is up as far as software is concerned. */
  /* NAME.{output,tx} nodes for this interface. */
  u32 output_node_index, tx_node_index;

  /* (dev_class, dev_instance) uniquely identifies hw interface. */
  u32 dev_class_index;
  u32 dev_instance;

  /* (hw_class, hw_instance) uniquely identifies hw interface. */
  u32 hw_class_index;
  u32 hw_instance;

  /* Hardware index for this hardware interface. */
  u32 hw_if_index;

  /* Software index for this hardware interface. */
  u32 sw_if_index;

  /* Maximum transmit rate for this interface in bits/sec. */
  f64 max_rate_bits_per_sec;

  /* Smallest packet size supported by this interface. */
  u32 min_supported_packet_bytes;

  /* Largest packet size supported by this interface. */
  u32 max_supported_packet_bytes;

  /* Smallest packet size for this interface. */
  u32 min_packet_bytes;

  /* Largest packet size for this interface. */
  u32 max_packet_bytes;

  /* Number of extra bytes that go on the wire.
     Packet length on wire
     = max (length + per_packet_overhead_bytes, min_packet_bytes). */
  u32 per_packet_overhead_bytes;

  /* Receive and transmit layer 3 packet size limits (MRU/MTU). */
  u32 max_l3_packet_bytes[VLIB_N_RX_TX];

  /* Hash table mapping sub interface id to sw_if_index. */
  uword *sub_interface_sw_if_index_by_id;

  /* Count of number of L2 subinterfaces */
  u32 l2_if_count;

  /* Bonded interface info -
     0       - not a bonded interface nor a slave
     ~0      - slave to a bonded interface
     others  - A bonded interface with a pointer to bitmap for all slaves */
  uword *bond_info;
#define VNET_HW_INTERFACE_BOND_INFO_NONE ((uword *) 0)
#define VNET_HW_INTERFACE_BOND_INFO_SLAVE ((uword *) ~0)

  /* Input node */
  u32 input_node_index;

  /* input node cpu index by queue */
  u32 *input_node_cpu_index_by_queue;

} vnet_hw_interface_t;

extern vnet_device_class_t vnet_local_interface_device_class;

typedef enum
{
  /* A hw interface. */
  VNET_SW_INTERFACE_TYPE_HARDWARE,

  /* A sub-interface. */
  VNET_SW_INTERFACE_TYPE_SUB,
} vnet_sw_interface_type_t;

typedef struct
{
  /*
   * Subinterface ID. A number 0-N to uniquely identify
   * this subinterface under the main (parent?) interface
   */
  u32 id;

  /* Classification data. Used to associate packet header with subinterface. */
  struct
  {
    u16 outer_vlan_id;
    u16 inner_vlan_id;
    union
    {
      u16 raw_flags;
      struct
      {
	u16 no_tags:1;
	u16 one_tag:1;
	u16 two_tags:1;
	u16 dot1ad:1;		/* 0 = dot1q, 1=dot1ad */
	u16 exact_match:1;
	u16 default_sub:1;
	u16 outer_vlan_id_any:1;
	u16 inner_vlan_id_any:1;
      } flags;
    };
  } eth;
} vnet_sub_interface_t;

typedef enum
{
  /* Always flood */
  VNET_FLOOD_CLASS_NORMAL,
  VNET_FLOOD_CLASS_TUNNEL_MASTER,
  /* Does not flood when tunnel master is in the same L2 BD */
  VNET_FLOOD_CLASS_TUNNEL_NORMAL
} vnet_flood_class_t;

/* Software-interface.  This corresponds to a Ethernet VLAN, ATM vc, a
   tunnel, etc.  Configuration (e.g. IP address) gets attached to
   software interface. */
typedef struct
{
  vnet_sw_interface_type_t type:16;

  u16 flags;
  /* Interface is "up" meaning adminstratively up.
     Up in the sense of link state being up is maintained by hardware interface. */
#define VNET_SW_INTERFACE_FLAG_ADMIN_UP (1 << 0)

  /* Interface is disabled for forwarding: punt all traffic to slow-path. */
#define VNET_SW_INTERFACE_FLAG_PUNT (1 << 1)

#define VNET_SW_INTERFACE_FLAG_PROXY_ARP (1 << 2)

#define VNET_SW_INTERFACE_FLAG_UNNUMBERED (1 << 3)

#define VNET_SW_INTERFACE_FLAG_BOND_SLAVE (1 << 4)

/* Interface does not appear in CLI/API */
#define VNET_SW_INTERFACE_FLAG_HIDDEN (1 << 5)

  /* Index for this interface. */
  u32 sw_if_index;

  /* Software interface index of super-interface;
     equal to sw_if_index if this interface is not a
     sub-interface. */
  u32 sup_sw_if_index;

  /* this swif is unnumbered, use addresses on unnumbered_sw_if_index... */
  u32 unnumbered_sw_if_index;

  u32 link_speed;

  union
  {
    /* VNET_SW_INTERFACE_TYPE_HARDWARE. */
    u32 hw_if_index;

    /* VNET_SW_INTERFACE_TYPE_SUB. */
    vnet_sub_interface_t sub;
  };

  vnet_flood_class_t flood_class;
} vnet_sw_interface_t;

typedef enum
{
  /* Simple counters. */
  VNET_INTERFACE_COUNTER_DROP = 0,
  VNET_INTERFACE_COUNTER_PUNT = 1,
  VNET_INTERFACE_COUNTER_IP4 = 2,
  VNET_INTERFACE_COUNTER_IP6 = 3,
  VNET_INTERFACE_COUNTER_RX_NO_BUF = 4,
  VNET_INTERFACE_COUNTER_RX_MISS = 5,
  VNET_INTERFACE_COUNTER_RX_ERROR = 6,
  VNET_INTERFACE_COUNTER_TX_ERROR = 7,
  VNET_INTERFACE_COUNTER_MPLS = 8,
  VNET_N_SIMPLE_INTERFACE_COUNTER = 9,
  /* Combined counters. */
  VNET_INTERFACE_COUNTER_RX = 0,
  VNET_INTERFACE_COUNTER_TX = 1,
  VNET_N_COMBINED_INTERFACE_COUNTER = 2,
} vnet_interface_counter_type_t;

typedef struct
{
  u32 output_node_index;
  u32 tx_node_index;
} vnet_hw_interface_nodes_t;

typedef struct
{
  /* Hardware interfaces. */
  vnet_hw_interface_t *hw_interfaces;

  /* Hash table mapping HW interface name to index. */
  uword *hw_interface_by_name;

  /* Vectors if hardware interface classes and device classes. */
  vnet_hw_interface_class_t *hw_interface_classes;
  vnet_device_class_t *device_classes;

  /* Hash table mapping name to hw interface/device class. */
  uword *hw_interface_class_by_name;
  uword *device_class_by_name;

  /* Software interfaces. */
  vnet_sw_interface_t *sw_interfaces;

  /* Hash table mapping sub intfc sw_if_index by sup sw_if_index and sub id */
  uword *sw_if_index_by_sup_and_sub;

  /* Software interface counters both simple and combined
     packet and byte counters. */
  volatile u32 *sw_if_counter_lock;
  vlib_simple_counter_main_t *sw_if_counters;
  vlib_combined_counter_main_t *combined_sw_if_counters;

  vnet_hw_interface_nodes_t *deleted_hw_interface_nodes;

  /* pcap drop tracing */
  int drop_pcap_enable;
  pcap_main_t pcap_main;
  u8 *pcap_filename;
  u32 pcap_sw_if_index;
  u32 pcap_pkts_to_capture;
  uword *pcap_drop_filter_hash;

  /* feature_arc_index */
  u8 output_feature_arc_index;
} vnet_interface_main_t;

static inline void
vnet_interface_counter_lock (vnet_interface_main_t * im)
{
  if (im->sw_if_counter_lock)
    while (__sync_lock_test_and_set (im->sw_if_counter_lock, 1))
      /* zzzz */ ;
}

static inline void
vnet_interface_counter_unlock (vnet_interface_main_t * im)
{
  if (im->sw_if_counter_lock)
    *im->sw_if_counter_lock = 0;
}

void vnet_pcap_drop_trace_filter_add_del (u32 error_index, int is_add);

int vnet_interface_name_renumber (u32 sw_if_index, u32 new_show_dev_instance);

#endif /* included_vnet_interface_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
