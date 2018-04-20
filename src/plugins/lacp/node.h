/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#ifndef __included_lacp_node_h__
#define __included_lacp_node_h__

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <lacp/protocol.h>
#include <lacp/rx_machine.h>
#include <lacp/tx_machine.h>
#include <lacp/mux_machine.h>
#include <lacp/ptx_machine.h>

typedef enum
{
  LACP_PACKET_TEMPLATE_ETHERNET,
  LACP_N_PACKET_TEMPLATES,
} lacp_packet_template_id_t;

typedef enum
{
  MARKER_PACKET_TEMPLATE_ETHERNET,
  MARKER_N_PACKET_TEMPLATES,
} marker_packet_template_id_t;

enum
{
  LACP_PROCESS_EVENT_START = 1,
  LACP_PROCESS_EVENT_STOP = 2,
} lacp_process_event_t;

#define LACP_DBG(n, args...)			\
  {						\
    lacp_main_t *_lm = &lacp_main;              \
    if (_lm->debug || n->debug)			\
      clib_warning (args);			\
  }

#define LACP_DBG2(n, e, s, m, t)   		  \
  {						  \
    lacp_main_t *_lm = &lacp_main;                \
    if ((m)->debug && (_lm->debug || (n)->debug)) \
      (*m->debug)(n, e, s, t);			  \
  }

/* Packet counters */
#define foreach_lacp_error                                               \
_ (NONE, "good lacp packets -- consumed")	                         \
_ (CACHE_HIT, "good lacp packets -- cache hit")                          \
_ (UNSUPPORTED, "unsupported slow protocol packets")                     \
_ (TOO_SMALL, "bad lacp packets -- packet too small")                    \
_ (BAD_TLV, "bad lacp packets -- bad TLV length")                        \
_ (DISABLED, "lacp packets received on disabled interfaces")

typedef enum
{
#define _(sym,str) LACP_ERROR_##sym,
  foreach_lacp_error
#undef _
    LACP_N_ERROR,
} lacp_error_t;

/* lacp packet trace capture */
typedef struct
{
  u32 sw_if_index;
  u32 len;
  union
  {
    marker_pdu_t marker;
    lacp_pdu_t lacpdu;
  } pkt;
} lacp_input_trace_t;

/** LACP interface details struct */
typedef struct
{
  u32 sw_if_index;
  u8 interface_name[64];
  u32 rx_state;
  u32 tx_state;
  u32 mux_state;
  u32 ptx_state;
  u8 bond_interface_name[64];
  u16 actor_system_priority;
  u8 actor_system[6];
  u16 actor_key;
  u16 actor_port_priority;
  u16 actor_port_number;
  u8 actor_state;
  u16 partner_system_priority;
  u8 partner_system[6];
  u16 partner_key;
  u16 partner_port_priority;
  u16 partner_port_number;
  u8 partner_state;
} lacp_interface_details_t;

typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Background process node index */
  u32 lacp_process_node_index;

  /* Packet templates for different encap types */
  vlib_packet_template_t packet_templates[LACP_N_PACKET_TEMPLATES];

  /* Packet templates for different encap types */
  vlib_packet_template_t marker_packet_templates[MARKER_N_PACKET_TEMPLATES];

  /* LACP interface count */
  u32 lacp_int;

  /* debug is on or off */
  u8 debug;
} lacp_main_t;

extern lacp_state_struct lacp_state_array[];
extern lacp_main_t lacp_main;

clib_error_t *lacp_plugin_api_hookup (vlib_main_t * vm);
int lacp_dump_ifs (lacp_interface_details_t ** out_bondids);
lacp_error_t lacp_input (vlib_main_t * vm, vlib_buffer_t * b0, u32 bi0);
void lacp_periodic (vlib_main_t * vm);
u8 *lacp_input_format_trace (u8 * s, va_list * args);
void lacp_init_neighbor (slave_if_t * sif, u8 * hw_address,
			 u16 port_number, u32 group);
void lacp_init_state_machines (vlib_main_t * vm, slave_if_t * sif);
void lacp_init_rx_machine (vlib_main_t * vm, slave_if_t * sif);
void lacp_init_tx_machine (vlib_main_t * vm, slave_if_t * sif);
void lacp_init_ptx_machine (vlib_main_t * vm, slave_if_t * sif);
void lacp_init_mux_machine (vlib_main_t * vm, slave_if_t * sif);
void lacp_selection_logic (vlib_main_t * vm, slave_if_t * sif);
void lacp_send_lacp_pdu (vlib_main_t * vm, slave_if_t * sif);

static inline void
lacp_stop_timer (f64 * timer)
{
  *timer = 0.0;
}

static inline u8
lacp_timer_is_running (f64 timer)
{
  return (timer != 0.0);
}

static inline u8
lacp_timer_is_expired (vlib_main_t * vm, f64 timer)
{
  f64 now = vlib_time_now (vm);

  return (now >= timer);
}

static inline u8 *
format_rx_sm_state (u8 * s, va_list * args)
{
  lacp_state_struct lacp_rx_sm_state_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_rx_sm_state
#undef _
    {.str = NULL}
  };
  int state = va_arg (*args, int);
  lacp_state_struct *state_entry =
    (lacp_state_struct *) & lacp_rx_sm_state_array;

  if (state >= (sizeof (lacp_rx_sm_state_array) / sizeof (*state_entry)))
    s = format (s, "Bad state %d", state);
  else
    s = format (s, "%s", state_entry[state].str);

  return s;
}

static inline u8 *
format_tx_sm_state (u8 * s, va_list * args)
{
  lacp_state_struct lacp_tx_sm_state_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_tx_sm_state
#undef _
    {.str = NULL}
  };
  int state = va_arg (*args, int);
  lacp_state_struct *state_entry =
    (lacp_state_struct *) & lacp_tx_sm_state_array;

  if (state >= (sizeof (lacp_tx_sm_state_array) / sizeof (*state_entry)))
    s = format (s, "Bad state %d", state);
  else
    s = format (s, "%s", state_entry[state].str);

  return s;
}

static inline u8 *
format_mux_sm_state (u8 * s, va_list * args)
{
  lacp_state_struct lacp_mux_sm_state_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_mux_sm_state
#undef _
    {.str = NULL}
  };
  int state = va_arg (*args, int);
  lacp_state_struct *state_entry =
    (lacp_state_struct *) & lacp_mux_sm_state_array;

  if (state >= (sizeof (lacp_mux_sm_state_array) / sizeof (*state_entry)))
    s = format (s, "Bad state %d", state);
  else
    s = format (s, "%s", state_entry[state].str);

  return s;
}

static inline u8 *
format_ptx_sm_state (u8 * s, va_list * args)
{
  lacp_state_struct lacp_ptx_sm_state_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_ptx_sm_state
#undef _
    {.str = NULL}
  };
  int state = va_arg (*args, int);
  lacp_state_struct *state_entry =
    (lacp_state_struct *) & lacp_ptx_sm_state_array;

  if (state >= (sizeof (lacp_ptx_sm_state_array) / sizeof (*state_entry)))
    s = format (s, "Bad state %d", state);
  else
    s = format (s, "%s", state_entry[state].str);

  return s;
}

static inline int
lacp_bit_test (u8 val, u8 bit)
{
  if (val & (1 << bit))
    return 1;
  else
    return 0;
}

#endif /* __included_lacp_node_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
