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
#ifndef __included_vnet_bonding_lacp_node_h__
#define __included_vnet_bonding_lacp_node_h__

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vnet/bonding/lacp/protocol.h>

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

typedef struct
{
  u8 persistent_hw_address[6];

  /* neighbor's vlib software interface index */
  u32 sw_if_index;

  /* Timers */
  f64 last_heard;

  /* Neighbor time-to-live (usually 3s) */
  f32 ttl_in_seconds;

  /* 1 = debug is on; 0 = debug is off */
  u8 debug;

  /* tx packet template id for this neighbor */
  u8 packet_template_index;

  /* Info we actually keep about each neighbor */

  /* Jenkins hash optimization: avoid tlv scan, send short keepalive msg */
  u8 last_packet_signature_valid;
  uword last_packet_signature;

  /* last received lacp packet, for the J-hash optimization */
  u8 *last_rx_pkt;

  /* last marker packet */
  u8 *last_marker_pkt;

  /* neighbor vlib hw_if_index */
  u32 hw_if_index;

  /* actor does not initiate the protocol exchange */
  u8 is_passive;

  /* Partner port information */
  lacp_port_info_t partner;
  lacp_port_info_t partner_admin;;

  /* Partner port information */
  lacp_port_info_t actor;
  lacp_port_info_t actor_admin;

  /* Need To Transmit flag */
  u8 ntt;

  /* Link has been established and Aggregate Port is operable */
  u8 port_enabled;

  /* Initialization or reinitialization of the lacp protocol entity */
  u8 begin;

  /* Aggregation Port is operating the lacp */
  u8 lacp_enabled;

  /* MUX to indicate to the Selection Logic wait_while_timer expired */
  u8 ready_n;

  /* Selection Logic indicates al Aggregation Ports attached */
  u8 ready;

  /* Selection Logic selected an Aggregator */
  int selected;

  /* RX machine indicates an Aggregation Port in PORT_DISABLED state */
  u8 port_moved;

  /* timer used to detect whether received protocol information has expired */
  f64 current_while_timer;

  /* timer used to detect actor churn states */
  f64 actor_churn_timer;

  /* timer used to generate periodic transmission */
  f64 periodic_timer;

  /* timer used to detect partner churn states */
  f64 partner_churn_timer;

  /* provides hysteresis before performing an aggregation change */
  f64 wait_while_timer;

  /* Implemention variables, not in the spec */
  int rx_state;
  int tx_state;
  int mux_state;
  int ptx_state;

  /* actor admin key */
  u32 group;

  u32 marker_tx_id;

  u32 bif_dev_instance;
} slave_if_t;

#define LACP_DBG(n, args...)			\
  {						\
    bond_main_t *_bm = &bond_main;              \
    if (_bm->debug || n->debug)			\
      clib_warning (args);			\
  }

#define LACP_DBG2(n, e, s, m, t)   		  \
  {						  \
    bond_main_t *_bm = &bond_main;                \
    if ((m)->debug && (_bm->debug || (n)->debug)) \
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
  u32 len;
  union
  {
    marker_pdu_t marker;
    lacp_pdu_t lacpdu;
  } pkt;
} lacp_input_trace_t;

extern lacp_state_struct lacp_state_array[];

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
void lacp_send_lacp_pdu (slave_if_t * sif);

#endif /* __included_vnet_bonding_lacp_node_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
