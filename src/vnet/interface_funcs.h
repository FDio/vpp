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
 * interface_funcs.h: VNET interfaces/sub-interfaces exported functions
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

#ifndef included_vnet_interface_funcs_h
#define included_vnet_interface_funcs_h

always_inline vnet_hw_interface_t *
vnet_get_hw_interface (vnet_main_t * vnm, u32 hw_if_index)
{
  return pool_elt_at_index (vnm->interface_main.hw_interfaces, hw_if_index);
}

always_inline vnet_hw_interface_t *
vnet_get_hw_interface_or_null (vnet_main_t * vnm, u32 hw_if_index)
{
  if (!pool_is_free_index (vnm->interface_main.hw_interfaces, hw_if_index))
    return pool_elt_at_index (vnm->interface_main.hw_interfaces, hw_if_index);
  return (NULL);
}

always_inline vnet_sw_interface_t *
vnet_get_sw_interface (vnet_main_t * vnm, u32 sw_if_index)
{
  return pool_elt_at_index (vnm->interface_main.sw_interfaces, sw_if_index);
}

always_inline vnet_sw_interface_t *
vnet_get_sw_interface_or_null (vnet_main_t * vnm, u32 sw_if_index)
{
  if (!pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return pool_elt_at_index (vnm->interface_main.sw_interfaces, sw_if_index);
  return (NULL);
}

always_inline vnet_sw_interface_t *
vnet_get_hw_sw_interface (vnet_main_t * vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, hw->sw_if_index);
  ASSERT (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
  return sw;
}

always_inline vnet_sw_interface_t *
vnet_get_sup_sw_interface (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);
  if (sw->type == VNET_SW_INTERFACE_TYPE_SUB ||
      sw->type == VNET_SW_INTERFACE_TYPE_PIPE ||
      sw->type == VNET_SW_INTERFACE_TYPE_P2P)
    sw = vnet_get_sw_interface (vnm, sw->sup_sw_if_index);
  return sw;
}

always_inline vnet_hw_interface_t *
vnet_get_sup_hw_interface (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, sw_if_index);
  ASSERT ((sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE) ||
	  (sw->type == VNET_SW_INTERFACE_TYPE_PIPE));
  return vnet_get_hw_interface (vnm, sw->hw_if_index);
}

always_inline vnet_hw_interface_t *
vnet_get_sup_hw_interface_api_visible_or_null (vnet_main_t * vnm,
					       u32 sw_if_index)
{
  vnet_sw_interface_t *si;
  if (PREDICT_FALSE (pool_is_free_index (vnm->interface_main.sw_interfaces,
					 sw_if_index)))
    return NULL;
  si = vnet_get_sup_sw_interface (vnm, sw_if_index);
  if (PREDICT_FALSE (si->flags & VNET_SW_INTERFACE_FLAG_HIDDEN))
    return NULL;
  ASSERT ((si->type == VNET_SW_INTERFACE_TYPE_HARDWARE) ||
	  (si->type == VNET_SW_INTERFACE_TYPE_PIPE));
  return vnet_get_hw_interface (vnm, si->hw_if_index);
}

always_inline vnet_hw_interface_class_t *
vnet_get_hw_interface_class (vnet_main_t * vnm, u32 hw_class_index)
{
  return vec_elt_at_index (vnm->interface_main.hw_interface_classes,
			   hw_class_index);
}

always_inline vnet_device_class_t *
vnet_get_device_class (vnet_main_t * vnm, u32 dev_class_index)
{
  return vec_elt_at_index (vnm->interface_main.device_classes,
			   dev_class_index);
}

static inline u8 *
vnet_get_sw_interface_tag (vnet_main_t * vnm, u32 sw_if_index)
{
  uword *p;
  p = hash_get (vnm->interface_tag_by_sw_if_index, sw_if_index);
  if (p)
    return ((u8 *) p[0]);
  return 0;
}

static inline void
vnet_set_sw_interface_tag (vnet_main_t * vnm, u8 * tag, u32 sw_if_index)
{
  uword *p;
  p = hash_get (vnm->interface_tag_by_sw_if_index, sw_if_index);
  if (p)
    {
      u8 *oldtag = (u8 *) p[0];
      hash_unset (vnm->interface_tag_by_sw_if_index, sw_if_index);
      vec_free (oldtag);
    }

  hash_set (vnm->interface_tag_by_sw_if_index, sw_if_index, tag);
}

static inline void
vnet_clear_sw_interface_tag (vnet_main_t * vnm, u32 sw_if_index)
{
  uword *p;
  p = hash_get (vnm->interface_tag_by_sw_if_index, sw_if_index);
  if (p)
    {
      u8 *oldtag = (u8 *) p[0];
      hash_unset (vnm->interface_tag_by_sw_if_index, sw_if_index);
      vec_free (oldtag);
    }
}

/**
 * Walk return code
 */
typedef enum walk_rc_t_
{
  WALK_STOP,
  WALK_CONTINUE,
} walk_rc_t;

/**
 * Call back walk type for walking SW indices on a HW interface
 */
typedef walk_rc_t (*vnet_hw_sw_interface_walk_t) (vnet_main_t * vnm,
						  u32 sw_if_index, void *ctx);

/**
 * @brief
 * Walk the SW interfaces on a HW interface - this is the super
 * interface and any sub-interfaces.
 */
void vnet_hw_interface_walk_sw (vnet_main_t * vnm,
				u32 hw_if_index,
				vnet_hw_sw_interface_walk_t fn, void *ctx);

/**
 * Call back walk type for walking SW indices on a HW interface
 */
typedef walk_rc_t (*vnet_sw_interface_walk_t) (vnet_main_t * vnm,
					       vnet_sw_interface_t * si,
					       void *ctx);

/**
 * @brief
 * Walk all the SW interfaces in the system.
 */
void vnet_sw_interface_walk (vnet_main_t * vnm,
			     vnet_sw_interface_walk_t fn, void *ctx);


/**
 * Call back walk type for walking all HW indices
 */
typedef walk_rc_t (*vnet_hw_interface_walk_t) (vnet_main_t * vnm,
					       u32 hw_if_index, void *ctx);

/**
 * @brief
 * Walk all the HW interface
 */
void vnet_hw_interface_walk (vnet_main_t * vnm,
			     vnet_hw_interface_walk_t fn, void *ctx);

/* Register a hardware interface instance. */
u32 vnet_register_interface (vnet_main_t * vnm,
			     u32 dev_class_index,
			     u32 dev_instance,
			     u32 hw_class_index, u32 hw_instance);

/**
 * Set interface output node - for interface registered without its output/tx
 * nodes created because its VNET_DEVICE_CLASS did not specify any tx_function.
 * This is typically the case for tunnel interfaces.
 */
void vnet_set_interface_output_node (vnet_main_t * vnm,
				     u32 hw_if_index, u32 node_index);

void vnet_set_interface_l3_output_node (vlib_main_t *vm, u32 sw_if_index,
					u8 *output_node);
void vnet_reset_interface_l3_output_node (vlib_main_t *vm, u32 sw_if_index);

/* Creates a software interface given template. */
clib_error_t *vnet_create_sw_interface (vnet_main_t * vnm,
					vnet_sw_interface_t * template,
					u32 * sw_if_index);

void vnet_delete_hw_interface (vnet_main_t * vnm, u32 hw_if_index);
void vnet_delete_sw_interface (vnet_main_t * vnm, u32 sw_if_index);
int vnet_sw_interface_is_p2p (vnet_main_t * vnm, u32 sw_if_index);
int vnet_sw_interface_is_nbma (vnet_main_t * vnm, u32 sw_if_index);

always_inline vnet_sw_interface_flags_t
vnet_sw_interface_get_flags (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);
  return sw->flags;
}

always_inline uword
vnet_sw_interface_is_valid (vnet_main_t * vnm, u32 sw_if_index)
{
  return !pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index);
}

always_inline uword
vnet_hw_interface_is_valid (vnet_main_t * vnm, u32 hw_if_index)
{
  return !pool_is_free_index (vnm->interface_main.hw_interfaces, hw_if_index);
}


always_inline uword
vnet_sw_interface_is_admin_up (vnet_main_t * vnm, u32 sw_if_index)
{
  return (vnet_sw_interface_get_flags (vnm, sw_if_index) &
	  VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
}

always_inline uword
vnet_swif_is_api_visible (vnet_sw_interface_t * si)
{
  return !(si->flags & VNET_SW_INTERFACE_FLAG_HIDDEN);
}

always_inline uword
vnet_sw_interface_is_api_visible (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  return vnet_swif_is_api_visible (si);
}

always_inline uword
vnet_sw_interface_is_api_valid (vnet_main_t * vnm, u32 sw_if_index)
{
  return !pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index)
    && vnet_sw_interface_is_api_visible (vnm, sw_if_index);
}

always_inline const u8 *
vnet_sw_interface_get_hw_address (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  return hw->hw_address;
}

always_inline uword
vnet_hw_interface_get_flags (vnet_main_t * vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  return hw->flags;
}

always_inline u32
vnet_hw_interface_get_mtu (vnet_main_t * vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  return hw->max_packet_bytes;
}

always_inline u32
vnet_sw_interface_get_mtu (vnet_main_t * vnm, u32 sw_if_index, vnet_mtu_t af)
{
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);
  u32 mtu;
  mtu = sw->mtu[af] > 0 ? sw->mtu[af] : sw->mtu[VNET_MTU_L3];
  if (mtu == 0)
    return 9000;		/* $$$ Deal with interface-types not setting MTU */
  return mtu;
}

always_inline uword
vnet_hw_interface_is_link_up (vnet_main_t * vnm, u32 hw_if_index)
{
  return ((vnet_hw_interface_get_flags (vnm, hw_if_index) &
	   VNET_HW_INTERFACE_FLAG_LINK_UP) != 0);
}

always_inline uword
vnet_sw_interface_is_link_up (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  return (vnet_hw_interface_is_link_up (vnm, sw->hw_if_index));
}

always_inline uword
vnet_sw_interface_is_up (vnet_main_t * vnm, u32 sw_if_index)
{
  return (vnet_sw_interface_is_admin_up (vnm, sw_if_index) &&
	  vnet_sw_interface_is_link_up (vnm, sw_if_index));
}

always_inline uword
vnet_sw_interface_is_sub (vnet_main_t *vnm, u32 sw_if_index)
{
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);

  return (sw->sw_if_index != sw->sup_sw_if_index);
}

clib_error_t *vnet_sw_interface_supports_addressing (vnet_main_t *vnm,
						     u32 sw_if_index);

always_inline vlib_frame_t *
vnet_get_frame_to_sw_interface (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  return vlib_get_frame_to_node (vlib_get_main (), hw->output_node_index);
}

always_inline void
vnet_put_frame_to_sw_interface (vnet_main_t * vnm, u32 sw_if_index,
				vlib_frame_t * f)
{
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  return vlib_put_frame_to_node (vlib_get_main (), hw->output_node_index, f);
}

always_inline void
vnet_hw_interface_set_link_speed (vnet_main_t * vnm, u32 hw_if_index,
				  u32 link_speed)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  hw->link_speed = link_speed;
}

/* Change interface flags (e.g. up, down, enable, disable). */
clib_error_t *vnet_hw_interface_set_flags (vnet_main_t * vnm, u32 hw_if_index,
					   vnet_hw_interface_flags_t flags);

/* Change interface flags (e.g. up, down, enable, disable). */
clib_error_t *vnet_sw_interface_set_flags (vnet_main_t * vnm, u32 sw_if_index,
					   vnet_sw_interface_flags_t flags);

void vnet_sw_interface_admin_up (vnet_main_t * vnm, u32 sw_if_index);
void vnet_sw_interface_admin_down (vnet_main_t * vnm, u32 sw_if_index);

/* Change interface class. */
clib_error_t *vnet_hw_interface_set_class (vnet_main_t * vnm, u32 hw_if_index,
					   u32 new_hw_class_index);

/* Redirect rx pkts to node */
int vnet_hw_interface_rx_redirect_to_node (vnet_main_t * vnm, u32 hw_if_index,
					   u32 node_index);

void vnet_hw_interface_init_for_class (vnet_main_t * vnm, u32 hw_if_index,
				       u32 hw_class_index, u32 hw_instance);

/* Rename interface */
clib_error_t *vnet_rename_interface (vnet_main_t * vnm, u32 hw_if_index,
				     char *new_name);

/* Add/delete secondary interface mac address*/
clib_error_t *vnet_hw_interface_add_del_mac_address (vnet_main_t * vnm,
						     u32 hw_if_index,
						     const u8 * mac_address,
						     u8 is_add);

/* Change interface mac address*/
clib_error_t *vnet_hw_interface_change_mac_address (vnet_main_t * vnm,
						    u32 hw_if_index,
						    const u8 * mac_address);

/* Change rx-mode */
clib_error_t *set_hw_interface_change_rx_mode (vnet_main_t * vnm,
					       u32 hw_if_index,
					       u8 queue_id_valid,
					       u32 queue_id,
					       vnet_hw_if_rx_mode mode);

/* Set rx-placement on the interface */
clib_error_t *set_hw_interface_rx_placement (u32 hw_if_index, u32 queue_id,
					     u32 thread_index, u8 is_main);
/* Set tx-queue placement on the interface */
int set_hw_interface_tx_queue (u32 hw_if_index, u32 queue_id, uword *bitmap);

/* Set the MTU on the HW interface */
clib_error_t *vnet_hw_interface_set_mtu (vnet_main_t *vnm, u32 hw_if_index,
					 u32 mtu);

/* Set the MTU on the SW interface */
void vnet_sw_interface_set_mtu (vnet_main_t * vnm, u32 sw_if_index, u32 mtu);
void vnet_sw_interface_set_protocol_mtu (vnet_main_t * vnm, u32 sw_if_index,
					 u32 mtu[]);

/* update the unnumbered state of an interface */
int vnet_sw_interface_update_unnumbered (u32 sw_if_index, u32 ip_sw_if_index,
					 u8 enable);

int vnet_sw_interface_stats_collect_enable_disable (u32 sw_if_index,
						    u8 enable);
void vnet_sw_interface_ip_directed_broadcast (vnet_main_t * vnm,
					      u32 sw_if_index, u8 enable);

/* set interface rss queues */
clib_error_t *vnet_hw_interface_set_rss_queues (vnet_main_t * vnm,
						vnet_hw_interface_t * hi,
						clib_bitmap_t * bitmap);

void vnet_hw_if_update_runtime_data (vnet_main_t *vnm, u32 hw_if_index);

/* Formats sw/hw interface. */
format_function_t format_vnet_hw_interface;
format_function_t format_vnet_hw_if_rx_mode;
format_function_t format_vnet_hw_if_index_name;
format_function_t format_vnet_sw_interface;
format_function_t format_vnet_sw_interface_name;
format_function_t format_vnet_sw_interface_name_override;
format_function_t format_vnet_sw_if_index_name;
format_function_t format_vnet_sw_interface_flags;

/* Parses sw/hw interface name -> index. */
unformat_function_t unformat_vnet_sw_interface;
unformat_function_t unformat_vnet_hw_interface;
unformat_function_t unformat_vnet_buffer_flags;
unformat_function_t unformat_vnet_buffer_offload_flags;

/* Parses interface flags (up, down, enable, disable, etc.) */
unformat_function_t unformat_vnet_hw_interface_flags;
unformat_function_t unformat_vnet_sw_interface_flags;

/* VLAN tag-rewrite */
format_function_t format_vtr;

/* Node runtime for interface output function. */
typedef struct
{
  u32 hw_if_index;
  u32 sw_if_index;
  u32 dev_instance;
  u32 is_deleted;
} vnet_interface_output_runtime_t;

/* Interface output function. */
word vnet_sw_interface_compare (vnet_main_t * vnm, uword sw_if_index0,
				uword sw_if_index1);
word vnet_hw_interface_compare (vnet_main_t * vnm, uword hw_if_index0,
				uword hw_if_index1);

typedef enum
{
  VNET_INTERFACE_OUTPUT_NEXT_DROP,
  VNET_INTERFACE_OUTPUT_NEXT_TX,
} vnet_interface_output_next_t;

typedef enum
{
  VNET_INTERFACE_TX_NEXT_DROP,
  VNET_INTERFACE_TX_N_NEXT,
} vnet_interface_tx_next_t;

#define VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT VNET_INTERFACE_TX_N_NEXT
#define VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT (VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT + 1)

typedef enum
{
  VNET_INTERFACE_OUTPUT_ERROR_INTERFACE_DOWN,
  VNET_INTERFACE_OUTPUT_ERROR_INTERFACE_DELETED,
  VNET_INTERFACE_OUTPUT_ERROR_NO_TX_QUEUE,
} vnet_interface_output_error_t;

/* Format for interface output traces. */
u8 *format_vnet_interface_output_trace (u8 * s, va_list * va);

serialize_function_t serialize_vnet_interface_state,
  unserialize_vnet_interface_state;

/**
 * @brief Add buffer (vlib_buffer_t) to the trace
 *
 * @param *pm - pcap_main_t
 * @param *vm - vlib_main_t
 * @param buffer_index - u32
 * @param n_bytes_in_trace - u32
 *
 */
static inline void
pcap_add_buffer (pcap_main_t *pm, struct vlib_main_t *vm, u32 buffer_index,
		 u32 n_bytes_in_trace)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
  u32 n = vlib_buffer_length_in_chain (vm, b);
  i32 n_left = clib_min (n_bytes_in_trace, n);
  f64 time_now = vlib_time_now (vm);
  void *d;

  if (PREDICT_TRUE (pm->n_packets_captured < pm->n_packets_to_capture))
    {
      clib_spinlock_lock_if_init (&pm->lock);
      d = pcap_add_packet (pm, time_now, n_left, n);
      while (1)
	{
	  u32 copy_length = clib_min ((u32) n_left, b->current_length);
	  clib_memcpy_fast (d, b->data + b->current_data, copy_length);
	  n_left -= b->current_length;
	  if (n_left <= 0)
	    break;
	  d += b->current_length;
	  ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
	  b = vlib_get_buffer (vm, b->next_buffer);
	}
      clib_spinlock_unlock_if_init (&pm->lock);
    }
}

typedef struct
{
  vnet_hw_if_caps_t val;
  vnet_hw_if_caps_t mask;
} vnet_hw_if_caps_change_t;

void vnet_hw_if_change_caps (vnet_main_t *vnm, u32 hw_if_index,
			     vnet_hw_if_caps_change_t *caps);

static_always_inline void
vnet_hw_if_set_caps (vnet_main_t *vnm, u32 hw_if_index, vnet_hw_if_caps_t caps)
{
  vnet_hw_if_caps_change_t cc = { .val = caps, .mask = caps };
  vnet_hw_if_change_caps (vnm, hw_if_index, &cc);
}

static_always_inline void
vnet_hw_if_unset_caps (vnet_main_t *vnm, u32 hw_if_index,
		       vnet_hw_if_caps_t caps)
{
  vnet_hw_if_caps_change_t cc = { .val = 0, .mask = caps };
  vnet_hw_if_change_caps (vnm, hw_if_index, &cc);
}

#endif /* included_vnet_interface_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
