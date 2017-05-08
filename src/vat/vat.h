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
#ifndef __included_vat_h__
#define __included_vat_h__

#include <stdio.h>
#include <setjmp.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/time.h>
#include <vppinfra/macros.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include "vat/json_format.h"

#include <vlib/vlib.h>

typedef struct
{
  u8 *interface_name;
  u32 sw_if_index;
  /*
   * Subinterface ID. A number 0-N to uniquely identify this
   * subinterface under the super interface
   */
  u32 sub_id;

  /* 0 = dot1q, 1=dot1ad */
  u8 sub_dot1ad;

  /* Number of tags 0-2 */
  u8 sub_number_of_tags;
  u16 sub_outer_vlan_id;
  u16 sub_inner_vlan_id;
  u8 sub_exact_match;
  u8 sub_default;
  u8 sub_outer_vlan_id_any;
  u8 sub_inner_vlan_id_any;

  /* vlan tag rewrite */
  u32 vtr_op;
  u32 vtr_push_dot1q;
  u32 vtr_tag1;
  u32 vtr_tag2;
} sw_interface_subif_t;

typedef struct
{
  u8 ip[16];
  u8 prefix_length;
} ip_address_details_t;

typedef struct
{
  u8 present;
  ip_address_details_t *addr;
} ip_details_t;

typedef struct
{
  u64 packets;
  u64 bytes;
} interface_counter_t;

typedef struct
{
  struct in_addr address;
  u8 address_length;
  u64 packets;
  u64 bytes;
} ip4_fib_counter_t;

typedef struct
{
  struct in6_addr address;
  u8 address_length;
  u64 packets;
  u64 bytes;
} ip6_fib_counter_t;

typedef struct
{
  struct in_addr address;
  vnet_link_t linkt;
  u64 packets;
  u64 bytes;
} ip4_nbr_counter_t;

typedef struct
{
  struct in6_addr address;
  vnet_link_t linkt;
  u64 packets;
  u64 bytes;
} ip6_nbr_counter_t;

typedef struct
{
  /* vpe input queue */
  unix_shared_memory_queue_t *vl_input_queue;

  /* interface name table */
  uword *sw_if_index_by_interface_name;

  /* subinterface table */
  sw_interface_subif_t *sw_if_subif_table;

  /* Graph node table */
  uword *graph_node_index_by_name;
  vlib_node_t **graph_nodes;

  /* ip tables */
  ip_details_t *ip_details_by_sw_if_index[2];

  /* sw_if_index of currently processed interface */
  u32 current_sw_if_index;

  /* remember that we are dumping ipv6 */
  u8 is_ipv6;

  /* function table */
  uword *function_by_name;

  /* help strings */
  uword *help_by_name;

  /* macro table */
  macro_main_t macro_main;

  /* Errors by number */
  uword *error_string_by_error_number;


  /* Main thread can spin (w/ timeout) here if needed */
  u32 async_mode;
  u32 async_errors;
  volatile u32 result_ready;
  volatile i32 retval;
  volatile u32 sw_if_index;
  volatile u8 *shmem_result;
  volatile u8 *cmd_reply;

  /* our client index */
  u32 my_client_index;

  /* Time is of the essence... */
  clib_time_t clib_time;

  /* Unwind (so we can quit) */
  jmp_buf jump_buf;
  int jump_buf_set;
  volatile int do_exit;

  /* temporary parse buffer */
  unformat_input_t *input;

  /* input buffer */
  u8 *inbuf;

  /* stdio input / output FILEs */
  FILE *ifp, *ofp;
  u8 *current_file;
  u32 input_line_number;

  /* exec mode toggle */
  int exec_mode;

  /* Regenerate the interface table */
  volatile int regenerate_interface_table;

  /* flag for JSON output format */
  u8 json_output;

  /* flag for interface event display */
  u8 interface_event_display;

  /* JSON tree used in composing dump api call results */
  vat_json_node_t json_tree;

  /* counters */
  u64 **simple_interface_counters;
  interface_counter_t **combined_interface_counters;
  ip4_fib_counter_t **ip4_fib_counters;
  u32 *ip4_fib_counters_vrf_id_by_index;
  ip6_fib_counter_t **ip6_fib_counters;
  u32 *ip6_fib_counters_vrf_id_by_index;
  ip4_nbr_counter_t **ip4_nbr_counters;
  ip6_nbr_counter_t **ip6_nbr_counters;

  /* Convenience */
  vlib_main_t *vlib_main;
} vat_main_t;

extern vat_main_t vat_main;

void vat_suspend (vlib_main_t * vm, f64 interval);
f64 vat_time_now (vat_main_t * vam);
void errmsg (char *fmt, ...);
void vat_api_hookup (vat_main_t * vam);
int api_sw_interface_dump (vat_main_t * vam);
void do_one_file (vat_main_t * vam);
int exec (vat_main_t * vam);

/* Plugin API library functions */
char *vat_plugin_path;
char *vat_plugin_name_filter;
void vat_plugin_api_reference (void);
uword unformat_sw_if_index (unformat_input_t * input, va_list * args);
uword unformat_ip4_address (unformat_input_t * input, va_list * args);
uword unformat_ethernet_address (unformat_input_t * input, va_list * args);
uword unformat_ethernet_type_host_byte_order (unformat_input_t * input,
					      va_list * args);
uword unformat_ip6_address (unformat_input_t * input, va_list * args);
u8 *format_ip4_address (u8 * s, va_list * args);
u8 *format_ip6_address (u8 * s, va_list * args);
u8 *format_ip46_address (u8 * s, va_list * args);
u8 *format_ethernet_address (u8 * s, va_list * args);

#if VPP_API_TEST_BUILTIN
#define print api_cli_output
void api_cli_output (void *, const char *fmt, ...);
#else
#define print fformat_append_cr
void fformat_append_cr (FILE *, const char *fmt, ...);
#endif

#endif /* __included_vat_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
