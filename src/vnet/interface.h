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

#include <vlib/vlib.h>
#include <vppinfra/pcap.h>
#include <vnet/l3_types.h>
#include <vppinfra/lock.h>

struct vnet_main_t;
struct vnet_hw_interface_t;
struct vnet_sw_interface_t;
union ip46_address_t_;

typedef enum
{
  VNET_HW_IF_RX_MODE_UNKNOWN,
  VNET_HW_IF_RX_MODE_POLLING,
  VNET_HW_IF_RX_MODE_INTERRUPT,
  VNET_HW_IF_RX_MODE_ADAPTIVE,
  VNET_HW_IF_RX_MODE_DEFAULT,
  VNET_HW_IF_NUM_RX_MODES,
} vnet_hw_if_rx_mode;

/* Interface up/down callback. */
typedef clib_error_t *(vnet_interface_function_t)
  (struct vnet_main_t * vnm, u32 if_index, u32 flags);

/* Sub-interface add/del callback. */
typedef clib_error_t *(vnet_subif_add_del_function_t)
  (struct vnet_main_t * vnm, u32 if_index,
   struct vnet_sw_interface_t * template, int is_add);

/* Interface set mac address callback. */
typedef clib_error_t *(vnet_interface_set_mac_address_function_t)
  (struct vnet_hw_interface_t * hi,
   const u8 * old_address, const u8 * new_address);

/* Interface add/del additional mac address callback */
typedef clib_error_t *(vnet_interface_add_del_mac_address_function_t)
  (struct vnet_hw_interface_t * hi, const u8 * address, u8 is_add);

/* Interface set rx mode callback. */
typedef clib_error_t *(vnet_interface_set_rx_mode_function_t)
  (struct vnet_main_t * vnm, u32 if_index, u32 queue_id,
   vnet_hw_if_rx_mode mode);

/* Interface set l2 mode callback. */
typedef clib_error_t *(vnet_interface_set_l2_mode_function_t)
  (struct vnet_main_t * vnm, struct vnet_hw_interface_t * hi,
   i32 l2_if_adjust);

/* Interface to set rss queues of the interface */
typedef clib_error_t *(vnet_interface_rss_queues_set_t)
  (struct vnet_main_t * vnm, struct vnet_hw_interface_t * hi,
   clib_bitmap_t * bitmap);

typedef enum
{
  VNET_FLOW_DEV_OP_ADD_FLOW,
  VNET_FLOW_DEV_OP_DEL_FLOW,
  VNET_FLOW_DEV_OP_GET_COUNTER,
  VNET_FLOW_DEV_OP_RESET_COUNTER,
} vnet_flow_dev_op_t;

/* Interface flow operations callback. */
typedef int (vnet_flow_dev_ops_function_t) (struct vnet_main_t * vnm,
					    vnet_flow_dev_op_t op,
					    u32 hw_if_index, u32 index,
					    uword * private_data);

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

#ifndef CLIB_MARCH_VARIANT
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
}                                                                       \
static void __vnet_interface_function_deinit_##tag##_##f (void)         \
    __attribute__((__destructor__)) ;                                   \
                                                                        \
static void __vnet_interface_function_deinit_##tag##_##f (void)         \
{                                                                       \
 vnet_main_t * vnm = vnet_get_main();                                   \
 _vnet_interface_function_list_elt_t *next;                             \
 if (vnm->tag##_functions[p]->fp == f)                                  \
    {                                                                   \
      vnm->tag##_functions[p] =                                         \
        vnm->tag##_functions[p]->next_interface_function;               \
      return;                                                           \
    }                                                                   \
  next = vnm->tag##_functions[p];                                       \
  while (next->next_interface_function)                                 \
    {                                                                   \
      if (next->next_interface_function->fp == f)                       \
        {                                                               \
          next->next_interface_function =                               \
            next->next_interface_function->next_interface_function;     \
          return;                                                       \
        }                                                               \
      next = next->next_interface_function;                             \
    }                                                                   \
}
#else
/* create unused pointer to silence compiler warnings and get whole
   function optimized out */
#define _VNET_INTERFACE_FUNCTION_DECL_PRIO(f,tag,p)                    \
static __clib_unused void * __clib_unused_##f = f;
#endif

#define _VNET_INTERFACE_FUNCTION_DECL(f,tag)                            \
  _VNET_INTERFACE_FUNCTION_DECL_PRIO(f,tag,VNET_ITF_FUNC_PRIORITY_LOW)

#define VNET_HW_INTERFACE_ADD_DEL_FUNCTION(f)			\
  _VNET_INTERFACE_FUNCTION_DECL(f,hw_interface_add_del)
#define VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION(f)		\
  _VNET_INTERFACE_FUNCTION_DECL(f,hw_interface_link_up_down)
#define VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION_PRIO(f,p)       \
  _VNET_INTERFACE_FUNCTION_DECL_PRIO(f,hw_interface_link_up_down,p)
#define VNET_SW_INTERFACE_MTU_CHANGE_FUNCTION(f)                \
  _VNET_INTERFACE_FUNCTION_DECL(f,sw_interface_mtu_change)
#define VNET_SW_INTERFACE_ADD_DEL_FUNCTION(f)			\
  _VNET_INTERFACE_FUNCTION_DECL(f,sw_interface_add_del)
#define VNET_SW_INTERFACE_ADD_DEL_FUNCTION_PRIO(f,p)		\
  _VNET_INTERFACE_FUNCTION_DECL_PRIO(f,sw_interface_add_del,p)
#define VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(f)		\
  _VNET_INTERFACE_FUNCTION_DECL(f,sw_interface_admin_up_down)
#define VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION_PRIO(f,p)     	\
  _VNET_INTERFACE_FUNCTION_DECL_PRIO(f,sw_interface_admin_up_down, p)

/**
 * Tunnel description parameters
 */
typedef int (*vnet_dev_class_ip_tunnel_desc_t) (u32 sw_if_index,
						union ip46_address_t_ * src,
						union ip46_address_t_ * dst,
						u8 * is_l2);

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

  /* Function to call interface rx mode is changed */
  vnet_interface_set_rx_mode_function_t *rx_mode_change_function;

  /* Function to call interface l2 mode is changed */
  vnet_interface_set_l2_mode_function_t *set_l2_mode_function;

  /* Redistribute flag changes/existence of this interface class. */
  u32 redistribute;

  /* Transmit function. */
  vlib_node_function_t *tx_function;

  /* Transmit function candidate registration with priority */
  vlib_node_fn_registration_t *tx_fn_registrations;

  /* Error strings indexed by error code for this node. */
  char **tx_function_error_strings;
  vl_counter_t *tx_function_error_counters;

  /* Number of error codes used by this node. */
  u32 tx_function_n_errors;

  /* Renumber device name [only!] support, a control-plane kludge */
  int (*name_renumber) (struct vnet_hw_interface_t * hi,
			u32 new_dev_instance);

  /* Interface flow offload operations */
  vnet_flow_dev_ops_function_t *flow_ops_function;

  /* Format device instance as name. */
  format_function_t *format_device_name;

  /* Parse function for device name. */
  unformat_function_t *unformat_device_name;

  /* Format device verbosely for this class. */
  format_function_t *format_device;

  /* Trace buffer format for TX function. */
  format_function_t *format_tx_trace;

  /* Format flow offload entry */
  format_function_t *format_flow;

  vnet_dev_class_ip_tunnel_desc_t ip_tun_desc;

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

  /* Function to set mac address. */
  vnet_interface_set_mac_address_function_t *mac_addr_change_function;

  /* Function to add/delete additional MAC addresses */
  vnet_interface_add_del_mac_address_function_t *mac_addr_add_del_function;

  /* Interface to set rss queues of the interface */
  vnet_interface_rss_queues_set_t *set_rss_queues_function;

} vnet_device_class_t;

#ifndef CLIB_MARCH_VARIANT
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
static void __vnet_rm_device_class_registration_##x (void)              \
    __attribute__((__destructor__)) ;                                   \
static void __vnet_rm_device_class_registration_##x (void)              \
{                                                                       \
    vnet_main_t * vnm = vnet_get_main();                                \
    VLIB_REMOVE_FROM_LINKED_LIST (vnm->device_class_registrations,      \
                                  &x, next_class_registration);         \
}                                                                       \
__VA_ARGS__ vnet_device_class_t x
#else
/* create unused pointer to silence compiler warnings and get whole
   function optimized out */
#define VNET_DEVICE_CLASS(x,...)                                        \
static __clib_unused vnet_device_class_t __clib_unused_##x
#endif

#define VNET_DEVICE_CLASS_TX_FN(devclass)				\
uword CLIB_MARCH_SFX (devclass##_tx_fn)();				\
static vlib_node_fn_registration_t					\
  CLIB_MARCH_SFX(devclass##_tx_fn_registration) =			\
  { .function = &CLIB_MARCH_SFX (devclass##_tx_fn), };			\
									\
static void __clib_constructor						\
CLIB_MARCH_SFX (devclass##_tx_fn_multiarch_register) (void)		\
{									\
  extern vnet_device_class_t devclass;					\
  vlib_node_fn_registration_t *r;					\
  r = &CLIB_MARCH_SFX (devclass##_tx_fn_registration);			\
  r->priority = CLIB_MARCH_FN_PRIORITY();				\
  r->next_registration = devclass.tx_fn_registrations;			\
  devclass.tx_fn_registrations = r;					\
}									\
uword CLIB_CPU_OPTIMIZED CLIB_MARCH_SFX (devclass##_tx_fn)

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

#define FOR_EACH_VNET_LINK(_link)    \
  for (_link = VNET_LINK_IP4;        \
       _link <= VNET_LINK_NSH;       \
       _link++)

#define FOR_EACH_VNET_IP_LINK(_link)    \
  for (_link = VNET_LINK_IP4;           \
       _link <= VNET_LINK_IP6;          \
       _link++)

/**
 * @brief Number of link types. Not part of the enum so it does not have to be
 * included in switch statements
 */
#define VNET_LINK_NUM (VNET_LINK_NSH+1)
#define VNET_N_LINKS VNET_LINK_NUM

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
  /**
   * @brief a non-broadcast multiple access interface
   */
  VNET_HW_INTERFACE_CLASS_FLAG_NBMA = (1 << 1),
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

  /* Function to add/delete additional MAC addresses */
  vnet_interface_add_del_mac_address_function_t *mac_addr_add_del_function;

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

  /* Update an adjacency added by FIB (as opposed to via the
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
 * @brief Return a complete, zero-length (aka placeholder) rewrite
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
static void __vnet_rm_hw_interface_class_registration_##x (void)        \
    __attribute__((__destructor__)) ;                                   \
static void __vnet_rm_hw_interface_class_registration_##x (void)        \
{                                                                       \
    vnet_main_t * vnm = vnet_get_main();                                \
    VLIB_REMOVE_FROM_LINKED_LIST (vnm->hw_interface_class_registrations,\
                                  &x, next_class_registration);         \
}                                                                       \
__VA_ARGS__ vnet_hw_interface_class_t x

typedef enum vnet_hw_interface_flags_t_
{
  VNET_HW_INTERFACE_FLAG_NONE,
  /* Hardware link state is up. */
  VNET_HW_INTERFACE_FLAG_LINK_UP = (1 << 0),
  /* Hardware duplex state */
  VNET_HW_INTERFACE_FLAG_HALF_DUPLEX = (1 << 1),
  VNET_HW_INTERFACE_FLAG_FULL_DUPLEX = (1 << 2),

  /* rx mode flags */
  VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE = (1 << 16),

  /* tx checksum offload */
  VNET_HW_INTERFACE_FLAG_SUPPORTS_TX_L4_CKSUM_OFFLOAD = (1 << 17),

  /* gso */
  VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO = (1 << 18),

  /* non-broadcast multiple access */
  VNET_HW_INTERFACE_FLAG_NBMA = (1 << 19),

  /* hw/driver can switch between l2-promisc and l3-dmac-filter modes */
  VNET_HW_INTERFACE_FLAG_SUPPORTS_MAC_FILTER = (1 << 20),
} vnet_hw_interface_flags_t;

#define VNET_HW_INTERFACE_FLAG_DUPLEX_SHIFT 1
#define VNET_HW_INTERFACE_FLAG_SPEED_SHIFT  3
#define VNET_HW_INTERFACE_FLAG_DUPLEX_MASK	\
  (VNET_HW_INTERFACE_FLAG_HALF_DUPLEX |		\
   VNET_HW_INTERFACE_FLAG_FULL_DUPLEX)

typedef struct
{
  /* hw interface index */
  u32 hw_if_index;

  /* device instance */
  u32 dev_instance;

  /* index of thread pollling this queue */
  u32 thread_index;

  /* file index of queue interrupt line */
  u32 file_index;

  /* hardware queue identifier */
  u32 queue_id;

  /* mode */
  vnet_hw_if_rx_mode mode : 8;
#define VNET_HW_IF_RXQ_THREAD_ANY      ~0
#define VNET_HW_IF_RXQ_NO_RX_INTERRUPT ~0
} vnet_hw_if_rx_queue_t;

/* Hardware-interface.  This corresponds to a physical wire
   that packets flow over. */
typedef struct vnet_hw_interface_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* Interface name. */
  u8 *name;

  /* flags */
  vnet_hw_interface_flags_t flags;


  /* link speed in kbps */
  u32 link_speed;

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

  /* Next index in interface-output node for this interface
     used by node function vnet_per_buffer_interface_output() */
  u32 output_node_next_index;

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

  /* Hash table mapping sub interface id to sw_if_index. */
  uword *sub_interface_sw_if_index_by_id;

  /* Count of number of L2 and L3 subinterfaces */
  u32 l2_if_count;
  u32 l3_if_count;

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
  u32 *input_node_thread_index_by_queue;

  vnet_hw_if_rx_mode default_rx_mode;

  /* rx queues */
  u32 *rx_queue_indices;

  /* numa node that hardware device connects to */
  u8 numa_node;

  /* rss queues bitmap */
  clib_bitmap_t *rss_queues;

  /* trace */
  i32 n_trace;

  u32 trace_classify_table_index;
} vnet_hw_interface_t;

typedef struct
{
  u32 dev_instance;
  u32 queue_id;
} vnet_hw_if_rxq_poll_vector_t;

typedef struct
{
  vnet_hw_if_rxq_poll_vector_t *rxq_poll_vector;
  void *rxq_interrupts;
} vnet_hw_if_rx_node_runtime_t;

extern vnet_device_class_t vnet_local_interface_device_class;

typedef enum
{
  /* A hw interface. */
  VNET_SW_INTERFACE_TYPE_HARDWARE,

  /* A sub-interface. */
  VNET_SW_INTERFACE_TYPE_SUB,
  VNET_SW_INTERFACE_TYPE_P2P,
  VNET_SW_INTERFACE_TYPE_PIPE,
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

typedef struct
{
  /*
   * Subinterface ID. A number 0-N to uniquely identify
   * this subinterface under the main interface
   */
  u32 id;
  u32 pool_index;
  u8 client_mac[6];
} vnet_p2p_sub_interface_t;

typedef enum
{
  /* THe BVI interface */
  VNET_FLOOD_CLASS_BVI,
  /* Always flood */
  VNET_FLOOD_CLASS_NORMAL,
  VNET_FLOOD_CLASS_TUNNEL_MASTER,
  /* Does not flood when tunnel master is in the same L2 BD */
  VNET_FLOOD_CLASS_TUNNEL_NORMAL,
  /* Never flood to this type */
  VNET_FLOOD_CLASS_NO_FLOOD,
} vnet_flood_class_t;

/* Per protocol MTU */
typedef enum
{
  VNET_MTU_L3,			/* Default payload MTU (without L2 headers) */
  VNET_MTU_IP4,			/* Per-protocol MTUs overriding default */
  VNET_MTU_IP6,
  VNET_MTU_MPLS,
  VNET_N_MTU
} vnet_mtu_t;

extern vnet_mtu_t vnet_link_to_mtu (vnet_link_t link);

typedef enum vnet_sw_interface_flags_t_
{
  VNET_SW_INTERFACE_FLAG_NONE = 0,
  /* Interface is "up" meaning administratively up.
     Up in the sense of link state being up is maintained by hardware interface. */
  VNET_SW_INTERFACE_FLAG_ADMIN_UP = (1 << 0),

  /* Interface is disabled for forwarding: punt all traffic to slow-path. */
  VNET_SW_INTERFACE_FLAG_PUNT = (1 << 1),

  __VNET_SW_INTERFACE_FLAG_UNSUED = (1 << 2),

  VNET_SW_INTERFACE_FLAG_UNNUMBERED = (1 << 3),

  __VNET_SW_INTERFACE_FLAG_UNUSED2 = (1 << 4),

  /* Interface does not appear in CLI/API */
  VNET_SW_INTERFACE_FLAG_HIDDEN = (1 << 5),

  /* Interface in ERROR state */
  VNET_SW_INTERFACE_FLAG_ERROR = (1 << 6),

  /* Interface has IP configured directed broadcast */
  VNET_SW_INTERFACE_FLAG_DIRECTED_BCAST = (1 << 7),

} __attribute__ ((packed)) vnet_sw_interface_flags_t;

/* Software-interface.  This corresponds to a Ethernet VLAN, ATM vc, a
   tunnel, etc.  Configuration (e.g. IP address) gets attached to
   software interface. */
typedef struct
{
  vnet_sw_interface_type_t type:16;

  vnet_sw_interface_flags_t flags;

  /* Index for this interface. */
  u32 sw_if_index;

  /* Software interface index of super-interface;
     equal to sw_if_index if this interface is not a
     sub-interface. */
  u32 sup_sw_if_index;

  /* this swif is unnumbered, use addresses on unnumbered_sw_if_index... */
  u32 unnumbered_sw_if_index;

  /* VNET_SW_INTERFACE_TYPE_HARDWARE. */
  u32 hw_if_index;

  /* MTU for network layer (not including L2 headers) */
  u32 mtu[VNET_N_MTU];

  /* VNET_SW_INTERFACE_TYPE_SUB. */
  vnet_sub_interface_t sub;

  /* VNET_SW_INTERFACE_TYPE_P2P. */
  vnet_p2p_sub_interface_t p2p;

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
  VNET_INTERFACE_COUNTER_RX_UNICAST = 1,
  VNET_INTERFACE_COUNTER_RX_MULTICAST = 2,
  VNET_INTERFACE_COUNTER_RX_BROADCAST = 3,
  VNET_INTERFACE_COUNTER_TX = 4,
  VNET_INTERFACE_COUNTER_TX_UNICAST = 5,
  VNET_INTERFACE_COUNTER_TX_MULTICAST = 6,
  VNET_INTERFACE_COUNTER_TX_BROADCAST = 7,
  VNET_N_COMBINED_INTERFACE_COUNTER = 8,
} vnet_interface_counter_type_t;

#define foreach_rx_combined_interface_counter(_x)               \
  for (_x = VNET_INTERFACE_COUNTER_RX;                          \
       _x <= VNET_INTERFACE_COUNTER_RX_BROADCAST;               \
       _x++)

#define foreach_tx_combined_interface_counter(_x)               \
  for (_x = VNET_INTERFACE_COUNTER_TX;                          \
       _x <= VNET_INTERFACE_COUNTER_TX_BROADCAST;               \
       _x++)

#define foreach_simple_interface_counter_name	\
  _(DROP, drops, if)				\
  _(PUNT, punt, if)				\
  _(IP4, ip4, if)				\
  _(IP6, ip6, if)				\
  _(RX_NO_BUF, rx-no-buf, if)			\
  _(RX_MISS, rx-miss, if)			\
  _(RX_ERROR, rx-error, if)			\
  _(TX_ERROR, tx-error, if)         \
  _(MPLS, mpls, if)

#define foreach_combined_interface_counter_name	\
  _(RX, rx, if)					\
  _(RX_UNICAST, rx-unicast, if)			\
  _(RX_MULTICAST, rx-multicast, if)		\
  _(RX_BROADCAST, rx-broadcast, if)		\
  _(TX, tx, if)					\
  _(TX_UNICAST, tx-unicast, if)			\
  _(TX_MULTICAST, tx-multicast, if)		\
  _(TX_BROADCAST, tx-broadcast, if)

typedef enum
{
  COLLECT_SIMPLE_STATS = 0,
  COLLECT_DETAILED_STATS = 1,
} vnet_interface_stats_collection_mode_e;

extern int collect_detailed_interface_stats_flag;

static inline int
collect_detailed_interface_stats (void)
{
  return collect_detailed_interface_stats_flag;
}

void collect_detailed_interface_stats_flag_set (void);
void collect_detailed_interface_stats_flag_clear (void);


typedef struct
{
  u32 output_node_index;
  u32 tx_node_index;
} vnet_hw_interface_nodes_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 *split_buffers;
} vnet_interface_per_thread_data_t;

typedef u8 *(*vnet_buffer_opquae_formatter_t) (const vlib_buffer_t * b,
					       u8 * s);

typedef struct
{
  /* Hardware interfaces. */
  vnet_hw_interface_t *hw_interfaces;

  /* Hardware interface RX queues */
  vnet_hw_if_rx_queue_t *hw_if_rx_queues;
  uword *rxq_index_by_hw_if_index_and_queue_id;

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
  clib_spinlock_t sw_if_counter_lock;
  vlib_simple_counter_main_t *sw_if_counters;
  vlib_combined_counter_main_t *combined_sw_if_counters;

  vnet_hw_interface_nodes_t *deleted_hw_interface_nodes;

  /*
   * pcap drop tracing
   * Only the drop filter hash lives here. See ../src/vlib/main.h for
   * the rest of the variables.
   */
  uword *pcap_drop_filter_hash;

  /* Buffer metadata format helper functions */
  vnet_buffer_opquae_formatter_t *buffer_opaque_format_helpers;
  vnet_buffer_opquae_formatter_t *buffer_opaque2_format_helpers;

  /* per-thread data */
  vnet_interface_per_thread_data_t *per_thread_data;

  /* feature_arc_index */
  u8 output_feature_arc_index;
} vnet_interface_main_t;

static inline void
vnet_interface_counter_lock (vnet_interface_main_t * im)
{
  if (im->sw_if_counter_lock)
    clib_spinlock_lock (&im->sw_if_counter_lock);
}

static inline void
vnet_interface_counter_unlock (vnet_interface_main_t * im)
{
  if (im->sw_if_counter_lock)
    clib_spinlock_unlock (&im->sw_if_counter_lock);
}

void vnet_pcap_drop_trace_filter_add_del (u32 error_index, int is_add);

int vnet_interface_name_renumber (u32 sw_if_index, u32 new_show_dev_instance);

vlib_node_function_t *vnet_interface_output_node_get (void);

void vnet_register_format_buffer_opaque_helper
  (vnet_buffer_opquae_formatter_t fn);

void vnet_register_format_buffer_opaque2_helper
  (vnet_buffer_opquae_formatter_t fn);

typedef struct
{
  u8 *filename;
  int enable;
  int status;
  u32 packets_to_capture;
  u32 max_bytes_per_pkt;
  u8 rx_enable;
  u8 tx_enable;
  u8 drop_enable;
  u8 preallocate_data;
  u8 free_data;
  u32 sw_if_index;
  int filter;
} vnet_pcap_dispatch_trace_args_t;

int vnet_pcap_dispatch_trace_configure (vnet_pcap_dispatch_trace_args_t *);

#endif /* included_vnet_interface_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
