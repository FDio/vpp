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
 * srp.h: types/functions for srp.
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

#ifndef included_srp_h
#define included_srp_h

#include <vnet/vnet.h>
#include <vnet/srp/packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/pg/pg.h>

extern vnet_hw_interface_class_t srp_hw_interface_class;

/* See RFC 2892. */
#define foreach_srp_ips_state			\
  _ (idle)					\
  _ (pass_thru)					\
  _ (wrapped)

typedef enum {
#define _(f) SRP_IPS_STATE_##f,
  foreach_srp_ips_state
#undef _
  SRP_N_IPS_STATE,
} srp_ips_state_t;

typedef enum {
  SRP_RING_OUTER,
  SRP_RING_INNER,
  SRP_N_RING = 2,
  SRP_SIDE_A = SRP_RING_OUTER,	/* outer rx, inner tx */
  SRP_SIDE_B = SRP_RING_INNER,	/* inner rx, outer tx */
  SRP_N_SIDE = 2,
} srp_ring_type_t;

typedef struct {
  srp_ring_type_t ring;

  /* Hardware interface for this ring/side. */
  u32 hw_if_index;

  /* Software interface corresponding to hardware interface. */
  u32 sw_if_index;

  /* Mac address of neighbor on RX fiber. */
  u8 rx_neighbor_address[6];

  u8 rx_neighbor_address_valid;

  /* True if we are waiting to restore signal. */
  u8 waiting_to_restore;

  /* Time stamp when signal became valid. */
  f64 wait_to_restore_start_time;
} srp_interface_ring_t;

struct srp_interface_t;
typedef void (srp_hw_wrap_function_t) (u32 hw_if_index, u32 wrap_enable);
typedef void (srp_hw_enable_function_t) (struct srp_interface_t * si, u32 wrap_enable);

typedef struct {
  /* Delay between wait to restore event and entering idle state in seconds. */
  f64 wait_to_restore_idle_delay;

  /* Number of seconds between sending ips messages to neighbors. */
  f64 ips_tx_interval;
} srp_interface_config_t;

typedef struct srp_interface_t {
  /* Current IPS state. */
  srp_ips_state_t current_ips_state;

  /* Address for this interface. */
  u8 my_address[6];

  /* Enable IPS process handling for this interface. */
  u8 ips_process_enable;

  srp_interface_ring_t rings[SRP_N_RING];

  /* Configurable parameters. */
  srp_interface_config_t config;

  srp_hw_wrap_function_t * hw_wrap_function;

  srp_hw_enable_function_t * hw_enable_function;
} srp_interface_t;

typedef struct {
  vlib_main_t * vlib_main;

  /* Pool of SRP interfaces. */
  srp_interface_t * interface_pool;

  uword * interface_index_by_hw_if_index;

  /* TTL to use for outgoing data packets. */
  u32 default_data_ttl;

  vlib_one_time_waiting_process_t * srp_register_interface_waiting_process_pool;

  uword * srp_register_interface_waiting_process_pool_index_by_hw_if_index;
} srp_main_t;

/* Registers sides A/B hardware interface as being SRP capable. */
void srp_register_interface (u32 * hw_if_indices);

/* Enable sending IPS messages for interface implied by given vlib hardware interface. */
void srp_interface_enable_ips (u32 hw_if_index);

/* Set function to wrap hardware side of SRP interface. */
void srp_interface_set_hw_wrap_function (u32 hw_if_index, srp_hw_wrap_function_t * f);

void srp_interface_set_hw_enable_function (u32 hw_if_index, srp_hw_enable_function_t * f);

extern vlib_node_registration_t srp_ips_process_node;

/* Called when an IPS control packet is received on given interface. */
void srp_ips_rx_packet (u32 sw_if_index, srp_ips_header_t * ips_packet);

/* Preform local IPS request on given interface. */
void srp_ips_local_request (u32 sw_if_index, srp_ips_request_type_t request);

always_inline void
srp_ips_link_change (u32 sw_if_index, u32 link_is_up)
{
  srp_ips_local_request (sw_if_index,
			 link_is_up
			 ? SRP_IPS_REQUEST_wait_to_restore
			 : SRP_IPS_REQUEST_signal_fail);
}

void srp_interface_get_interface_config (u32 hw_if_index, srp_interface_config_t * c);
void srp_interface_set_interface_config (u32 hw_if_index, srp_interface_config_t * c);

srp_main_t srp_main;

always_inline srp_interface_t *
srp_get_interface_from_vnet_hw_interface (u32 hw_if_index)
{
  srp_main_t * sm = &srp_main;
  uword * p = hash_get (sm->interface_index_by_hw_if_index, hw_if_index);
  return p ? pool_elt_at_index (sm->interface_pool, p[0]) : 0;
}

u8 * format_srp_header (u8 * s, va_list * args);
u8 * format_srp_header_with_length (u8 * s, va_list * args);
u8 * format_srp_device (u8 * s, va_list * args);

/* Parse srp header. */
uword
unformat_srp_header (unformat_input_t * input, va_list * args);

uword unformat_pg_srp_header (unformat_input_t * input, va_list * args);

always_inline void
srp_setup_node (vlib_main_t * vm, u32 node_index)
{
  vlib_node_t * n = vlib_get_node (vm, node_index);
  pg_node_t * pn = pg_get_node (node_index);
  n->format_buffer = format_srp_header_with_length;
  n->unformat_buffer = unformat_srp_header;
  pn->unformat_edit = unformat_pg_srp_header;
}

#define foreach_srp_error						\
  _ (NONE, "no error")							\
  _ (UNKNOWN_MODE, "unknown mode in SRP header")			\
  _ (KEEP_ALIVE_DROPPED, "v1 keep alive mode in SRP header")		\
  _ (CONTROL_PACKETS_PROCESSED, "control packets processed")		\
  _ (IPS_PACKETS_PROCESSED, "IPS packets processed")			\
  _ (UNKNOWN_CONTROL, "unknown control packet")				\
  _ (CONTROL_VERSION_NON_ZERO, "control packet with non-zero version")	\
  _ (CONTROL_BAD_CHECKSUM, "control packet with bad checksum")		\
  _ (TOPOLOGY_BAD_LENGTH, "topology packet with bad length")

typedef enum {
#define _(n,s) SRP_ERROR_##n,
  foreach_srp_error
#undef _
  SRP_N_ERROR,
} srp_error_t;

serialize_function_t serialize_srp_main, unserialize_srp_main;

#endif /* included_srp_h */
