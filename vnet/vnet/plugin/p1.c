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
 * This file and in fact the entire directory shouldn't even exist.
 * Vnet ought to be a dynamic library. 

 * Unfortunately, various things malfunction when we try to go there. 
 * Plugin DLL's end up with their own copies of critical
 * data structures. No one of these problems would be tough to fix, 
 * but there are quite a number of them.
 */

/* 
 * Make certain that plugin .dll's which reference the following functions
 * can find them...
 */

#define foreach_plugin_reference                \
_(unformat_vnet_hw_interface)                   \
_(unformat_vnet_sw_interface)                   \
_(vnet_hw_interface_rx_redirect_to_node)        \
_(vnet_config_add_feature)                      \
_(vnet_config_del_feature)                      \
_(vnet_get_main)                                \
_(_vlib_init_function_l2_init)                  \
_(_vlib_init_function_pg_init)                  \
_(_vlib_init_function_ip_main_init)             \
_(_vlib_init_function_ethernet_init)            \
_(_vlib_init_function_ethernet_arp_init)        \
_(l2input_intf_bitmap_enable)                   \
_(ip4_main)                                     \
_(ip6_main)                                     \
_(format_ip4_address)                           \
_(unformat_ip4_address)                         \
_(ip4_address_compare)                          \
_(ip6_address_compare)                          \
_(format_ip6_address)                           \
_(format_ip6_address_and_length)                \
_(udp_register_dst_port)                        \
_(ethernet_register_input_type)                 \
_(ethernet_set_flags)				\
_(format_ip6_address)                           \
_(unformat_ip6_address)                         \
_(ip6_main)					\
_(find_ip6_fib_by_table_index_or_id)		\
_(format_ethernet_address)			\
_(unformat_ethernet_address)			\
_(unformat_ethernet_interface)			\
_(ethernet_register_l2_input)			\
_(ethernet_register_l3_redirect)                \
_(unformat_pg_payload)				\
_(format_ip4_address_and_length)		\
_(ip_incremental_checksum)                      \
_(ethernet_sw_interface_set_l2_mode)            \
_(vnet_create_loopback_interface)               \
_(ethernet_set_rx_redirect)                     \
_(ethernet_set_flags)                           \
_(ethernet_get_main)                            \
_(ethernet_get_interface)                       \
_(vnet_hw_interface_set_flags)                  \
_(vnet_sw_interface_set_flags)                  \
_(vnet_create_sw_interface)                     \
_(vnet_delete_sw_interface)                     \
_(vnet_get_main)                                \
_(pg_stream_add)                                \
_(pg_stream_del)                                \
_(pg_stream_enable_disable)                     \
_(pg_main) 

#if DPDK > 0
#define foreach_dpdk_plugin_reference		\
_(dpdk_set_next_node)                           \
_(dpdk_worker_thread)                           \
_(dpdk_io_thread)                               \
_(dpdk_frame_queue_dequeue)                     \
_(vlib_get_handoff_queue_elt)                   \
_(dpdk_get_handoff_node_index)                  \
_(dpdk_set_flowcontrol_callback)                \
_(dpdk_interface_tx_vector)                     \
_(rte_calloc)                                   \
_(rte_free)                                     \
_(rte_malloc)                                   \
_(post_sw_interface_set_flags)                  \
_(dpdk_get_admin_up_down_in_progress)           \
_(efd_config)
#else
#define foreach_dpdk_plugin_reference
#endif

#if IPV6SR > 0
#define foreach_ip6_sr_plugin_reference		\
_(vnet_register_sr_app_callback)		\
_(format_ip6_sr_header)
#else
#define foreach_ip6_sr_plugin_reference
#endif 

#define _(a) void a (void);
foreach_plugin_reference
foreach_dpdk_plugin_reference
foreach_ip6_sr_plugin_reference
#undef _

void *vnet_library_plugin_references[] =
  {
#define _(a) &a,
    foreach_plugin_reference
    foreach_dpdk_plugin_reference
    foreach_ip6_sr_plugin_reference
#undef _
  };

void vnet_library_plugin_reference(void) { }
