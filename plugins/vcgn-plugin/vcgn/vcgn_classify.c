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

#include <vnet/plugin/plugin.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vppinfra/pool.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include "cnat_db.h"
#include "cnat_global.h"
#include "cnat_cli.h"
#include "cnat_config.h"
#include "cnat_logging.h"
#include "cnat_config_api.h"
#include "cnat_show_api.h"
#include "cnat_show_response.h"
#include "cnat_ipv4_udp.h"
#include "cnat_common_api.h"

#include <arpa/inet.h>

typedef struct {
  u32 cached_next_index;

  /* inside, outside interface handles */
  u32 * inside_sw_if_index_table;
  u32 * outside_sw_if_index_table;

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  u8 cnat_db_initalized;
} vcgn_classify_main_t;

typedef struct {
  /* $$$$ fill in with per-pkt trace data */ 
  u32 next_index;
  u32 sw_if_index;
  u32 orig_dst_address;
  u16 orig_dst_port;
} vcgn_classify_trace_t;

#define FIND_MY_VRF_USING_I_VRF_ID                                       \
    my_vrfmap_found = 0;                                                 \
    pool_foreach (my_vrfmap, cnat_map_by_vrf, ({                         \
        if (my_vrfmap->i_vrf_id == i_vrf_id) {                           \
            my_vrfmap_found = 1;                                         \
            my_vrfmap_temp = my_vrfmap;                                  \
            break;                                                       \
        }                                                                \
    }));


/* packet trace format function */
static u8 * format_swap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vcgn_classify_trace_t * t = va_arg (*args, vcgn_classify_trace_t *);
  
  s = format (s, "VCGN_CLASSIFY: dst %U dst_port %d sw_if_index %d next %d",
              format_ip4_address, (ip4_header_t *) &t->orig_dst_address,
              clib_net_to_host_u16(t->orig_dst_port), 
              t->sw_if_index, t->next_index);
  return s;
}

vcgn_classify_main_t vcgn_classify_main;

vlib_node_registration_t vcgn_classify_node;

#define foreach_vcgn_classify_error \
_(PACKETS_RECEIVED,     "total packets received")   \
_(V4_PACKETS_PROCESSED, "ipv4 packets processed for vCGN")   \
_(V4_PACKETS_PUNTED,    "ipv4 packets punted")   \
_(V6_PACKETS_PUNTED,    "ipv6 packets punted")   \
_(MPLS_PACKETS_PUNTED,  "mpls unicast packets punted")   \
_(ETH_PACKETS_PUNTED,   "ethernet packets punted")


typedef enum {
#define _(sym,str) VCGN_CLASSIFY_ERROR_##sym,
  foreach_vcgn_classify_error
#undef _
  VCGN_CLASSIFY_N_ERROR,
} vcgn_classify_error_t;

static char * vcgn_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_vcgn_classify_error
#undef _
};

/* 
 * To drop a pkt and increment one of the previous counters:
 * 
 * set b0->error = error_node->errors[VCGN_CLASSIFY_ERROR_EXAMPLE];
 * set next0 to a disposition index bound to "error-drop".
 *
 * To manually increment the specific counter VCGN_CLASSIFY_ERROR_EXAMPLE:
 *
 *  vlib_node_t *n = vlib_get_node (vm, vcgn_classify.index);
 *  u32 node_counter_base_index = n->error_heap_index;
 *  vlib_error_main_t * em = &vm->error_main;
 *  em->counters[node_counter_base_index + VCGN_CLASSIFY_ERROR_EXAMPLE] += 1;
 * 
 */

typedef enum {
  VCGN_CLASSIFY_NEXT_IP4_INPUT,
  VCGN_CLASSIFY_NEXT_IP6_INPUT,
  VCGN_CLASSIFY_NEXT_MPLS_INPUT,
  VCGN_CLASSIFY_NEXT_ETHERNET_INPUT,
  VCGN_CLASSIFY_NEXT_UDP_INSIDE,
  VCGN_CLASSIFY_NEXT_UDP_OUTSIDE,
  VCGN_CLASSIFY_NEXT_TCP_INSIDE,
  VCGN_CLASSIFY_NEXT_TCP_OUTSIDE,
  VCGN_CLASSIFY_NEXT_ICMP_Q_INSIDE,
  VCGN_CLASSIFY_NEXT_ICMP_Q_OUTSIDE,
  VCGN_CLASSIFY_NEXT_ICMP_E_INSIDE,
  VCGN_CLASSIFY_NEXT_ICMP_E_OUTSIDE,
  VCGN_CLASSIFY_N_NEXT,
} vcgn_classify_next_t;

static uword
vcgn_classify_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  vcgn_classify_next_t next_index;
  vcgn_classify_main_t * vcm = &vcgn_classify_main;
  vlib_node_t *n = vlib_get_node (vm, vcgn_classify_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t * em = &vm->error_main;
  u16 *l3_type;
  int counter;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      #if 0
      while (n_left_from >= 4 && n_left_to_next >= 2)
      {
          u32 bi0, bi1;
          vlib_buffer_t * b0, * b1;
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;
            
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
            
	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

          /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          next0 = vcm->cached_next_index;
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
          next1 = vcm->cached_next_index;

          /* $$$$ your message in this space. Process 2 x pkts */
          em->counters[node_counter_base_index + VCGN_CLASSIFY_ERROR_PACKETS_RECEIVED] += 2;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    vcgn_classify_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    vcgn_classify_trace_t *t = 
                      vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->sw_if_index = sw_if_index1;
                    t->next_index = next1;
                  }
              }
            
            /* verify speculative enqueues, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, bi1, next0, next1);
        }
        #endif /* if 0 */
      
      while (n_left_from > 0 && n_left_to_next > 0)
      {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
          ip4_header_t * h0;
          //ipv4_header *h0;
          ethernet_header_t *eth0;
          icmp_v4_t *icmp;
          u8 icmp_type;
          u8 ipv4_hdr_len;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          
          eth0 = (ethernet_header_t *) vlib_buffer_get_current(b0);
          u16 *etype = &eth0->type;
    
          /* vlan tag 0x8100 */      
          if (*etype == clib_host_to_net_u16(ETHERNET_TYPE_VLAN)) { 
            l3_type = (etype + 1); /* Skip 2 bytes of vlan id */  
            vlib_buffer_advance(b0, 18);
          } else {
            l3_type = etype;
            vlib_buffer_advance(b0, 14);
          }
          /* Handling v4 pkts 0x800 */
          if (*l3_type == clib_host_to_net_u16(ETHERNET_TYPE_IP4)) {  
          
              h0 = vlib_buffer_get_current (b0);

              u8 protocol_type = h0->protocol;

              sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
              next0 = VCGN_CLASSIFY_NEXT_IP4_INPUT;
              counter = VCGN_CLASSIFY_ERROR_V4_PACKETS_PROCESSED;

              if (protocol_type == 0x11) { /* UDP# 17 */
                  next0 = (sw_if_index0 < vec_len(vcm->inside_sw_if_index_table) &&
                    vcm->inside_sw_if_index_table[sw_if_index0] != EMPTY) ?
                        VCGN_CLASSIFY_NEXT_UDP_INSIDE : next0;

                  next0 = (sw_if_index0 < vec_len(vcm->outside_sw_if_index_table) &&
                    vcm->outside_sw_if_index_table[sw_if_index0] != EMPTY) ?
                        VCGN_CLASSIFY_NEXT_UDP_OUTSIDE : next0;

              } else if (protocol_type == 0x06) { /* TCP# 6 */
                  next0 = (sw_if_index0 < vec_len(vcm->inside_sw_if_index_table) &&
                    vcm->inside_sw_if_index_table[sw_if_index0] != EMPTY) ?
                        VCGN_CLASSIFY_NEXT_TCP_INSIDE : next0;

                  next0 = (sw_if_index0 < vec_len(vcm->outside_sw_if_index_table) &&
                    vcm->outside_sw_if_index_table[sw_if_index0] != EMPTY) ?
                        VCGN_CLASSIFY_NEXT_TCP_OUTSIDE : next0;

              } else if (protocol_type == 0x01) { /* ICMP # 1 */

                  ipv4_hdr_len = (h0->ip_version_and_header_length & 0xf) << 2;
                  icmp = (icmp_v4_t *)((u8*)h0 + ipv4_hdr_len);
                  icmp_type = icmp->type;

                  if ((icmp_type == ICMPV4_ECHO) || 
                          (icmp_type == ICMPV4_ECHOREPLY)) {
                      next0 = (sw_if_index0 < vec_len(vcm->inside_sw_if_index_table) &&
                        vcm->inside_sw_if_index_table[sw_if_index0] != EMPTY) ?
                            VCGN_CLASSIFY_NEXT_ICMP_Q_INSIDE : next0;

                      next0 = (sw_if_index0 < vec_len(vcm->outside_sw_if_index_table) &&
                        vcm->outside_sw_if_index_table[sw_if_index0] != EMPTY) ?
                            VCGN_CLASSIFY_NEXT_ICMP_Q_OUTSIDE : next0;

                  } else {
                      next0 = (sw_if_index0 < vec_len(vcm->inside_sw_if_index_table) &&
                        vcm->inside_sw_if_index_table[sw_if_index0] != EMPTY) ?
                            VCGN_CLASSIFY_NEXT_ICMP_E_INSIDE : next0;

                      next0 = (sw_if_index0 < vec_len(vcm->outside_sw_if_index_table) &&
                        vcm->outside_sw_if_index_table[sw_if_index0] != EMPTY) ?
                            VCGN_CLASSIFY_NEXT_ICMP_E_OUTSIDE : next0;
                  }
              } else {
                 /* cannot do NATting with this L4 protocol */
                  counter = VCGN_CLASSIFY_ERROR_V4_PACKETS_PUNTED;
              }

              if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                          && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
                  udp_header_t * u0 = (udp_header_t *)(h0+1);
                  vcgn_classify_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                  t->sw_if_index = sw_if_index0;
                  t->next_index = next0;
                  t->orig_dst_address = h0->dst_address.as_u32;
                  t->orig_dst_port = u0->dst_port;
              }

          } else if (*l3_type == clib_host_to_net_u16(ETHERNET_TYPE_IP6)) { 

                /* IPv6 0x86DD */
                next0 = VCGN_CLASSIFY_NEXT_IP6_INPUT;
                counter = VCGN_CLASSIFY_ERROR_V6_PACKETS_PUNTED;

            } else if (*l3_type == 
                clib_host_to_net_u16(ETHERNET_TYPE_MPLS_UNICAST)) { 

                /* MPLS unicast 0x8847 */
                next0 = VCGN_CLASSIFY_NEXT_MPLS_INPUT;
                counter = VCGN_CLASSIFY_ERROR_MPLS_PACKETS_PUNTED;
          } else { /* Remaining all should be pushed to "ethernet-input" */

                next0 = VCGN_CLASSIFY_NEXT_ETHERNET_INPUT;
                counter = VCGN_CLASSIFY_ERROR_ETH_PACKETS_PUNTED;
          }

          em->counters[node_counter_base_index + counter] += 1;
          em->counters[node_counter_base_index + 
                    VCGN_CLASSIFY_ERROR_PACKETS_RECEIVED] += 1;

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (vcgn_classify_node) = {
  .function = vcgn_classify_node_fn,
  .name = "vcgn-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_swap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(vcgn_classify_error_strings),
  .error_strings = vcgn_classify_error_strings,

  .n_next_nodes = VCGN_CLASSIFY_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [VCGN_CLASSIFY_NEXT_IP4_INPUT]      = "ip4-input",
    [VCGN_CLASSIFY_NEXT_IP6_INPUT]      = "ip6-input",
    [VCGN_CLASSIFY_NEXT_MPLS_INPUT]     = "mpls-input",
    [VCGN_CLASSIFY_NEXT_ETHERNET_INPUT] = "ethernet-input",
	[VCGN_CLASSIFY_NEXT_UDP_INSIDE]     = "vcgn-v4-udp-i2o",
	[VCGN_CLASSIFY_NEXT_UDP_OUTSIDE]    = "vcgn-v4-udp-o2i",
	[VCGN_CLASSIFY_NEXT_TCP_INSIDE]     = "vcgn-v4-tcp-i2o",
	[VCGN_CLASSIFY_NEXT_TCP_OUTSIDE]    = "vcgn-v4-tcp-o2i",
	[VCGN_CLASSIFY_NEXT_ICMP_Q_INSIDE]  = "vcgn-v4-icmp-q-i2o",
	[VCGN_CLASSIFY_NEXT_ICMP_Q_OUTSIDE] = "vcgn-v4-icmp-q-o2i",
	[VCGN_CLASSIFY_NEXT_ICMP_E_INSIDE]  = "vcgn-v4-icmp-e-i2o",
	[VCGN_CLASSIFY_NEXT_ICMP_E_OUTSIDE] = "vcgn-v4-icmp-e-o2i"
  },
};


/* A test function to init the vrf map */

clib_error_t *vcgn_classify_init (vlib_main_t *vm)
{
  vcgn_classify_main_t * mp = &vcgn_classify_main;
    
  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();
  u32 inside_sw_if_index = 1;
  u32 outside_sw_if_index = 0;

  vec_validate_init_empty (mp->inside_sw_if_index_table,
    inside_sw_if_index + 1, EMPTY);
  vec_validate_init_empty (mp->outside_sw_if_index_table,
    outside_sw_if_index + 1, EMPTY);

  /*
   * inside_sw_if_index cell of the table stores outside_sw_if_index
   * and vice versa. This is ensurs pair of indices being remembered
   * using one mem-location.
   */
  mp->inside_sw_if_index_table[inside_sw_if_index] = outside_sw_if_index;
  mp->outside_sw_if_index_table[outside_sw_if_index] = inside_sw_if_index;

#if DPDK==1
  dpdk_set_next_node (DPDK_RX_NEXT_IP4_INPUT, "vcgn-classify");
#endif

  {
    pg_node_t * pn;
    pn = pg_get_node (vcgn_classify_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
  }
  return 0;
}

VLIB_INIT_FUNCTION (vcgn_classify_init);

/* Show command handlers */
static clib_error_t *
show_vcgn_stats_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
    if (cnat_db_init_done) {
        cnat_nat44_handle_show_stats(vm);
    } else {
        vlib_cli_output(vm, "vCGN is not configured !!\n");
    }
    return 0;
}


static clib_error_t *
show_vcgn_config_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  cnat_nat44_handle_show_config(vm);
  return 0;
}

static clib_error_t *
show_vcgn_inside_translation_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
    vnet_main_t * vnm = vnet_get_main();
    vcgn_classify_main_t * vcm = &vcgn_classify_main;
    spp_api_cnat_v4_show_inside_entry_req_t inside_req;
    u8 *proto; 
    ip4_address_t inside_addr;
    u32 start_port = 1;
    u32 end_port = 65535;
    u32 inside_sw_if_index = EMPTY;
    
    inside_req.start_port = start_port;
    inside_req.end_port = end_port;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "protocol %s", &proto)) { 
            if (!strncmp((char *) proto, "udp", 3)) {
                inside_req.protocol = 1;
            } else if (!strncmp((char *) proto, "tcp", 3)) {
                inside_req.protocol = 2;
            } else {
                inside_req.protocol = 3;
            } 
        } else if (unformat (input, "interface %U", 
		    unformat_vnet_sw_interface, vnm, &inside_sw_if_index)) {
            if (inside_sw_if_index > vec_len(vcm->inside_sw_if_index_table) ||
                vcm->inside_sw_if_index_table[inside_sw_if_index] == EMPTY) {
                    return clib_error_return (0, "Could not find the inside interface");
            }
        } else if (unformat (input, "inside-addr %U", 
                       unformat_ip4_address, &inside_addr)) {
            inside_req.ipv4_addr = clib_net_to_host_u32(inside_addr.as_u32); 
        } else if (unformat(input, "start-port %u", &start_port)) {
            inside_req.start_port = start_port;
        } else if (unformat(input, "end-port %u", &end_port)) {
            inside_req.end_port = end_port;
        } else { break;}
    }
    inside_req.vrf_id = inside_sw_if_index;
    inside_req.flags |= CNAT_TRANSLATION_ENTRY_DYNAMIC; /* as of now only dynamic */  
    inside_req.all_entries = 0; /* we can see it later */
#if DEBUG
    vlib_cli_output(vm, "proto %d, inside-addr 0x%x, start_port %u, "
                "end_port %u, vrf 0x%x\n",
                inside_req.protocol, 
                inside_req.ipv4_addr,
                inside_req.start_port,
                inside_req.end_port,
                inside_sw_if_index);
#endif
    if (cnat_db_init_done) {
        cnat_v4_show_inside_entry_req_t_handler(&inside_req, vm);
    } else {
        vlib_cli_output(vm, "vCGN is not configured !!\n");
    }
    return 0;
}


static clib_error_t *
show_vcgn_outside_translation_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
    void cnat_v4_show_outside_entry_req_t_handler
        (spp_api_cnat_v4_show_outside_entry_req_t *mp, vlib_main_t *vm);
    vnet_main_t * vnm = vnet_get_main();
    vcgn_classify_main_t * vcm = &vcgn_classify_main;
    spp_api_cnat_v4_show_outside_entry_req_t outside_req;
    u8 *proto; 
    ip4_address_t outside_addr;
    u32 start_port = 1;
    u32 end_port = 65535;
    u32 outside_sw_if_index = EMPTY;
    
    
    outside_req.start_port = start_port;
    outside_req.end_port = end_port;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "protocol %s", &proto)) { 
            if (!strncmp((char *) proto, "udp", 3)) {
                outside_req.protocol = 1;
            } else if (!strncmp((char *) proto, "tcp", 3)) {
                outside_req.protocol = 2;
            } else {
                outside_req.protocol = 3;
            } 
        } else if (unformat (input, "interface %U", 
            unformat_vnet_sw_interface, vnm, &outside_sw_if_index)) {
            if (outside_sw_if_index > vec_len(vcm->outside_sw_if_index_table) ||
                vcm->outside_sw_if_index_table[outside_sw_if_index] == EMPTY) {
                    return clib_error_return (0, "Could not find the outside interface");
            }
        } else if (unformat (input, "outside-addr %U", 
                       unformat_ip4_address, &outside_addr)) {
            outside_req.ipv4_addr = clib_net_to_host_u32(outside_addr.as_u32); 
        } else if (unformat(input, "start-port %u", &start_port)) {
            outside_req.start_port = start_port;
        } else if (unformat(input, "end-port %u", &end_port)) {
            outside_req.end_port = end_port;
        } else { break;}
    }
    outside_req.vrf_id = outside_sw_if_index;
    outside_req.flags |= CNAT_TRANSLATION_ENTRY_DYNAMIC; /* as of now only dynamic */  
#if DEBUG
    vlib_cli_output(vm, "proto %d, outside-addr 0x%x, start_port %u, "
                "end_port %u, vrf 0x%x\n",
                outside_req.protocol, 
                outside_req.ipv4_addr,
                outside_req.start_port,
                outside_req.end_port,
                outside_sw_if_index);
#endif
    if (cnat_db_init_done) {
        cnat_v4_show_outside_entry_req_t_handler(&outside_req, vm);
    } else {
        vlib_cli_output(vm, "vCGN is not configured !!\n");
    }
    return 0;
}


/* Config command handlers */
static clib_error_t *
set_vcgn_inside_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  vcgn_classify_main_t * vcm = &vcgn_classify_main;
  u32 inside_sw_if_index = 1;
  u32 outside_sw_if_index = ~0;
  void cnat_db_v2_init (void );

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
      if (unformat(input, "%U", 
		   unformat_vnet_sw_interface, vnm, &inside_sw_if_index))
    ;
      else if (unformat(input, "outside %U", 
		   unformat_vnet_sw_interface, vnm, &outside_sw_if_index))
	; 
      else break;
    }
    if (inside_sw_if_index == ~0 ||
	outside_sw_if_index == ~0)
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);

    if (inside_sw_if_index == outside_sw_if_index)
      return clib_error_return (0, "inside and outside interfaces can't be the same...");

    /*
     * Initialize in/out sw_if_index table. Could use
     * non-indexed table to reduce memory. However, this
     * is consulted in vcgn_classify for every packet.
     * Therefore, table is indexed by sw_if_index.
     */
    vec_validate_init_empty (vcm->inside_sw_if_index_table,
        inside_sw_if_index + 1, EMPTY);
    vec_validate_init_empty (vcm->outside_sw_if_index_table,
        outside_sw_if_index + 1, EMPTY);

    /*
     * inside_sw_if_index cell of the table stores outside_sw_if_index
     * and vice versa. This is ensurs pair of indices being remembered
     * using one mem-location.
     */
    vcm->inside_sw_if_index_table[inside_sw_if_index] = outside_sw_if_index;
    vcm->outside_sw_if_index_table[outside_sw_if_index] = inside_sw_if_index;

    if (! vcm->cnat_db_initalized) {
        int i;
        cnat_db_v2_init();
        
        for (i = 0; i < CNAT_MAX_VRFMAP_ENTRIES; i++) {
            vrf_map_array[i] = VRF_MAP_ENTRY_EMPTY;
        }
        /* Turn on the db scanner process */
        cnat_scanner_db_process_turn_on(vm);
        vcm->cnat_db_initalized = 1;
    }
    return 0;
}

static clib_error_t *
set_vcgn_map_command_fn (vlib_main_t * vm,
			 unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  vcgn_classify_main_t * vcm = &vcgn_classify_main;
  ip4_address_t lo, hi;
  spp_api_cnat_v4_add_vrf_map_t map;
  u32 inside_sw_if_index = EMPTY;
  u32 outside_sw_if_index;

  vnet_hw_interface_t *inside_hw_if_index = NULL;
  vnet_hw_interface_t *outside_hw_if_index = NULL;

  if (! unformat(input, "inside %U", 
       unformat_vnet_sw_interface, vnm, &inside_sw_if_index))
    return clib_error_return (0, "unknown input `%U'",
                  format_unformat_error, input);

  if (!unformat (input, "%U", unformat_ip4_address, &lo))
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  if (unformat (input, "- %U", unformat_ip4_address, &hi))
    ;

  /* $$$$ remember to set i_vrf, i_vrf_id as needed */

  /* Fill the structure spp_api_cnat_v4_add_vrf_map_t & let this API handle it */
  /* i_vrf_id & o_vrf_id are 32-bit & i_vrf, o_vrf are 16 bit */

  if (inside_sw_if_index > vec_len(vcm->inside_sw_if_index_table) ||
    vcm->inside_sw_if_index_table[inside_sw_if_index] == EMPTY) {
      return clib_error_return (0, "Could not find the inside interface");
  }
  outside_sw_if_index = vcm->inside_sw_if_index_table[inside_sw_if_index];

  map.i_vrf_id = inside_sw_if_index; 
  map.o_vrf_id = outside_sw_if_index; 
  map.i_vrf    = inside_sw_if_index;
  map.o_vrf    = outside_sw_if_index;

  map.start_addr[0] = clib_net_to_host_u32(lo.as_u32); 
  map.end_addr[0]   = clib_net_to_host_u32(hi.as_u32); 

  cnat_nat44_add_vrf_map_t_handler(&map, vm);

#if 1
  inside_hw_if_index = vnet_get_sup_hw_interface(vcm->vnet_main, inside_sw_if_index);
  if (inside_hw_if_index) {
    vnet_hw_interface_rx_redirect_to_node(vcm->vnet_main, 
            inside_hw_if_index->hw_if_index, vcgn_classify_node.index);
  }
  outside_hw_if_index = vnet_get_sup_hw_interface(vcm->vnet_main, outside_sw_if_index);
  if (outside_hw_if_index) {
    vnet_hw_interface_rx_redirect_to_node(vcm->vnet_main, 
            outside_hw_if_index->hw_if_index, vcgn_classify_node.index);
  }
#endif
  return 0;
}

static clib_error_t *
set_vcgn_tcp_timeout_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  /*
  vnet_main_t * vnm = vnet_get_main();
  vcgn_classify_main_t * vcm = &vcgn_classify_main;
  */
  u32 act_timeout = 0;
  u32 init_timeout = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "active %u", &act_timeout)) 
            tcp_active_timeout = act_timeout;
        else if (unformat(input, "init %u", &init_timeout)) 
            tcp_initial_setup_timeout = init_timeout; 
        else break;
    }
    return 0;
}

static clib_error_t *
set_vcgn_udp_timeout_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  /*
  vnet_main_t * vnm = vnet_get_main();
  vcgn_classify_main_t * vcm = &vcgn_classify_main;
  */
  u32 act_timeout = 0;
  u32 init_timeout = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "active %u", &act_timeout)) 
            udp_act_session_timeout = act_timeout;
        else if (unformat(input, "init %u", &init_timeout)) 
            udp_init_session_timeout = init_timeout; 
        else break;
    }
    return 0;
}


static clib_error_t *
set_vcgn_icmp_timeout_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  /* 
   * vnet_main_t * vnm = vnet_get_main(); 
   * vcgn_classify_main_t * vcm = &vcgn_classify_main;
   */
  u32 timeout = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "%u", &timeout)) 
            ; 
        else break;
    }
    icmp_session_timeout = timeout;
    return 0;
}


static clib_error_t *
set_vcgn_protocol_default_timeout_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
    /*
    vnet_main_t * vnm = vnet_get_main();
    vcgn_classify_main_t * vcm = &vcgn_classify_main;
    */
    u8 *protocol;
    u8 reset = 1; 

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
      if (unformat(input, "%s", &protocol)) 
	;
      else break;
    }
    cnat_nat44_set_protocol_timeout_value(0, 0, protocol, reset, vm);
    return 0;
}

static clib_error_t *
set_vcgn_dynamic_port_start_range_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
    /*
    vnet_main_t * vnm = vnet_get_main();
    vcgn_classify_main_t * vcm = &vcgn_classify_main;
    */
    u32 port = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
      if (unformat(input, "%u", &port)) 
	;
      else break;
    }
    if (port != 0 && port > 65535) {
        vlib_cli_output(vm, "Error !! Invalid port\n");
    } else {
        cnat_static_port_range = port;
        vlib_cli_output(vm, "Dynamic Port Range Config Successful !!\n");
    }
    return 0;
}

static clib_error_t *
set_vcgn_port_limit_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
    /*
    vnet_main_t * vnm = vnet_get_main();
    vcgn_classify_main_t * vcm = &vcgn_classify_main;
    */
    u32 port = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
      if (unformat(input, "%u", &port)) 
	;
      else break;
    }
    if (port != 0 && port > 65535) {
        vlib_cli_output(vm, "Error !! Invalid port\n");
    } else {
        cnat_main_db_max_ports_per_user = port;
        vlib_cli_output(vm, "Port Limit Config Successful !!\n");
    }
    return 0;
}

static inline void nfv9_init_pkt_sent_data(cnat_nfv9_logging_info_t *nfv9_info)
{
    nfv9_server_info_t *server = nfv9_server_info_pool +
        nfv9_info->server_index;

        /*
         * Reset the pkts_since_last_template and sent_time
         * so that template will be sent next time
         */
        server->last_template_sent_time  = 0;
        server->pkts_since_last_template = 0xffffffff;
}

static inline u16 nfv9_get_max_length_minus_max_record_size(u16 path_mtu)
{
    u16 max_length_minus_max_record_size;
    if(!path_mtu) /* Use default */
        path_mtu = NFV9_DEF_PATH_MTU;

    max_length_minus_max_record_size = path_mtu -
        CNAT_NFV9_DATAFLOW_RECORD_HEADER_LENGTH -
        NFV9_PAD_VALUE -
        CNAT_NFV9_MAX_SINGLE_RECORD_LENGTH; /* Note.. as of now this record
            * requires max number of bytes. If you add more records,
            * this needs to be re-checked */
        if (max_length_minus_max_record_size < CNAT_NFV9_MIN_RECORD_SIZE) {
            max_length_minus_max_record_size = CNAT_NFV9_MIN_RECORD_SIZE;
        }
   return max_length_minus_max_record_size;
}

/* This function finds if the netflow server indicated by
 * new_server_info is already configured for some other instance
 * if yes, it returns the same pointer so that, info sent to the
 * server is consistent. If the server is not found, a new instance
 * is created and returned. If an existing server is used, its refernce
 * count is incrimented (indicating the number of instances using the
 * same server
 */
 /* #define DEBUG_NF_SERVER_CONFIG 1 */
static u16 nfv9_get_server_instance(
    cnat_nfv9_logging_info_t *nfv9_info, nfv9_server_info_t *new_server_info)
{

    /* Check if the instance has a server already and if yes, does it match */
    nfv9_server_info_t *server;
    if(nfv9_info->server_index != EMPTY) {
        server =  nfv9_server_info_pool + nfv9_info->server_index;

        if((server->ipv4_address == new_server_info->ipv4_address) &&
            (server->port == new_server_info->port)) {
            /* Same server.. just check if refresh rate/timeouts are reduced */
#ifdef DEBUG_NF_SERVER_CONFIG
            if(my_instance_number == 1) {
            printf("\n Server match for %x and port %d\n",
                new_server_info->ipv4_address, new_server_info->port);
            }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
            goto adjust_refresh_rate;
        } else { /* The server is being changed */
            server->ref_count--;
#ifdef DEBUG_NF_SERVER_CONFIG
            if(my_instance_number == 1) {
            printf("\n Server change from %x, %d to %x, %d"
                "Ref count %d\n",
                server->ipv4_address,
                server->port,
                new_server_info->ipv4_address, new_server_info->port,
                server->ref_count);
            }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
            if(!server->ref_count) {
                /* Return this server to pool */
#ifdef DEBUG_NF_SERVER_CONFIG
                if(my_instance_number == 1) {
                    PLATFORM_DEBUG_PRINT("Deleting Server %x, %d at %d\n",
                    server->ipv4_address,
                    server->port,
                    nfv9_info->server_index);
                }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
                pool_put(nfv9_server_info_pool, server);
            }
        }
    }

    /* Now check if the server is already present in the pool */
    u8 found = 0;
    server = 0;
    pool_foreach (server, nfv9_server_info_pool, ({
        if ((server->ipv4_address == new_server_info->ipv4_address) &&
            (server->port == new_server_info->port)) {
            server->ref_count++;
            nfv9_info->server_index = server - nfv9_server_info_pool;
            found = 1;
#ifdef DEBUG_NF_SERVER_CONFIG
            if(my_instance_number == 1) {
            printf("Re-using server %x, %d Ref count %d\n",
            server->ipv4_address, server->port, server->ref_count);
            }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
            break;
        }
    }));

    if(!found) {
        /* Create a new one, initialize and return */
        server = 0;
        pool_get(nfv9_server_info_pool, server);
        clib_memcpy(server, new_server_info, sizeof(nfv9_server_info_t));
        server->ref_count = 1;
        nfv9_info->server_index = server - nfv9_server_info_pool;
#ifdef DEBUG_NF_SERVER_CONFIG
        if(my_instance_number == 1) {
        printf("Create new server for at %d %x and port %d\n",
                nfv9_info->server_index,
                new_server_info->ipv4_address, new_server_info->port);
        }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
        return CNAT_SUCCESS;
    }

adjust_refresh_rate:
    if(server->refresh_rate >
        new_server_info->refresh_rate) {
        server->refresh_rate =
            new_server_info->refresh_rate;
#ifdef DEBUG_NF_SERVER_CONFIG
        if(my_instance_number == 1) {
        printf("Reset refresh rate to %d\n",
            server->refresh_rate);
        }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
    }

    if(server->timeout_rate >
        new_server_info->timeout_rate) {
        server->timeout_rate =
        new_server_info->timeout_rate;
#ifdef DEBUG_NF_SERVER_CONFIG
        if(my_instance_number == 1) {
            printf("Reset timeout rate to %d\n",
            server->timeout_rate);
        }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
    }

    return CNAT_SUCCESS;
}
static clib_error_t *
set_vcgn_nfv9_logging_cofig_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
    vcgn_classify_main_t * vcm = &vcgn_classify_main;
    spp_api_cnat_v4_config_nfv9_logging_t nfv9_conf;
    ip4_address_t server_addr;
    u32 ip_addr = 0;
    u32 port;
    u32 refresh_rate = 0;
    u32 timeout = 0;
    u32 pmtu = 0;
    u8 enable = 1;
/* vcgn changes start*/
    cnat_nfv9_logging_info_t *my_nfv9_logging_info = NULL;
    cnat_nfv9_logging_info_t *my_nfv9_logging_info_tmp = NULL;
    cnat_vrfmap_t *my_vrfmap = 0, *my_vrfmap_temp = 0; 
    u16           i_vrf = ~0;
    u32           i_vrf_id = ~0;
    u8            found;
    u32 inside_sw_if_index = EMPTY;
    /*
     * Init NFv9 logging info as needed, this will be done only once
     */
    cnat_nfv9_logging_init();

    found = 0;
  
/* vcgn changes end*/
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "inside %U", 
               unformat_vnet_sw_interface, &inside_sw_if_index)) {
            /* Do nothing */
        } else if (unformat (input, "server %U", unformat_ip4_address, &server_addr))
            ip_addr = clib_net_to_host_u32(server_addr.as_u32);
        else if (unformat(input, "port %u", &port)) 
        ;
        else if (unformat(input, "refresh-rate %u", &refresh_rate)) 
        ;
        else if (unformat(input, "timeout %u", &timeout)) 
        ;
        else if (unformat(input, "pmtu %u", &pmtu)) 
        ;
        else if (unformat(input, "del")) 
            enable = 0;
        else break;
    }

    if (inside_sw_if_index > vec_len(vcm->inside_sw_if_index_table) ||
        vcm->inside_sw_if_index_table[inside_sw_if_index] == EMPTY) {
            return clib_error_return (0, "Could not find the inside interface");
    }
    i_vrf    = inside_sw_if_index;
    i_vrf_id = inside_sw_if_index; 

    #if 0
    vlib_cli_output(vm, "ip 0x%x, port %u, refresh %u, "
                    "timeout %u, pmtu %u enable %u\n",
                    ip_addr, port, refresh_rate, 
                    timeout, pmtu, enable);
    #endif
    if (refresh_rate == 0) refresh_rate = 500; /* num of pkts */
    if (timeout == 0) timeout = 30;  /* in mins */

    nfv9_conf.enable = enable;
    nfv9_conf.ipv4_address = ip_addr;
    nfv9_conf.i_vrf_id = inside_sw_if_index;
    nfv9_conf.i_vrf = inside_sw_if_index;
    nfv9_conf.port = port;
    nfv9_conf.refresh_rate = refresh_rate;
    nfv9_conf.timeout_rate = timeout;
    nfv9_conf.path_mtu = pmtu;
    nfv9_conf.nfv9_global_collector = 0;
    nfv9_conf.session_logging = 0;

    /*
     * At this point the NFv9 global information should already be
     * inited as we have called cnat_nfv9_logging_init()
     */

    if (nfv9_conf.nfv9_global_collector) {
        if (cnat_nfv9_global_info.cnat_nfv9_global_collector_index != EMPTY) {
            found = 1;
            my_nfv9_logging_info = cnat_nfv9_logging_info_pool +
                    cnat_nfv9_global_info.cnat_nfv9_global_collector_index;
        }
    } else {
        /* Do we already have a map for this VRF? */
        pool_foreach (my_nfv9_logging_info, cnat_nfv9_logging_info_pool, ({
              if (my_nfv9_logging_info->i_vrf_id == i_vrf_id) {
                  nfv9_server_info_t *server =  nfv9_server_info_pool +
                      my_nfv9_logging_info->server_index;
                  if((server->ipv4_address ==  (nfv9_conf.ipv4_address)) && (server->port == (nfv9_conf.port))) {
                      found = 1;
                      my_nfv9_logging_info_tmp = my_nfv9_logging_info;
                      break;
                  }
              }
          }));
    }

    if ((nfv9_conf.ipv4_address == 0) ||
        (nfv9_conf.port == 0)) {
        vlib_cli_output(vm,
            "Add NFv9 ivrf %d Logging Invalid values [IPv4 0x%x, PORT %d]\n",
                i_vrf,
                (nfv9_conf.ipv4_address),
                (nfv9_conf.port));
         goto done;    
    }

    if (nfv9_conf.enable) {
        if ((nfv9_conf.ipv4_address == 0) ||
              (nfv9_conf.port == 0)) {
              nfv9_conf.rc = CNAT_ERR_PARSER;
              vlib_cli_output(vm,
                  "NFV9_logging i_vrf %d, Invalid [v4_addr 0x%x port %d]\n",
                  i_vrf,
                  (nfv9_conf.ipv4_address),
                  (nfv9_conf.port));
              goto done;    
        }

        nfv9_server_info_t new_server_info;
        memset(&new_server_info, 0, sizeof(nfv9_server_info_t));
        new_server_info.ipv4_address =
                nfv9_conf.ipv4_address;
        new_server_info.port =
                (nfv9_conf.port);
        new_server_info.refresh_rate =
            (nfv9_conf.refresh_rate);
        /*
         * Store the timeout in seconds.  User configures it in minutes
         */
        new_server_info.timeout_rate =
            60*(nfv9_conf.timeout_rate);
        if (found && my_nfv9_logging_info) {
            /*
             * Entry already present, change it
             */
            my_nfv9_logging_info->max_length_minus_max_record_size =
                nfv9_get_max_length_minus_max_record_size(
                    ((nfv9_conf.path_mtu)));
        } else {
            pool_get(cnat_nfv9_logging_info_pool, my_nfv9_logging_info);
            memset(my_nfv9_logging_info, 0, sizeof(*my_nfv9_logging_info));
            my_nfv9_logging_info->server_index = EMPTY;
            my_nfv9_logging_info->nfv9_logging_next_index = EMPTY;
            /*
             * Make the current and head logging context indeices as EMPTY.
             * When first logging happens, these get set correctly
             */
            my_nfv9_logging_info->current_logging_context = NULL;
            my_nfv9_logging_info->queued_logging_context  = NULL;
#if 0
            my_nfv9_logging_info->f  = NULL;
            my_nfv9_logging_info->to_next  = NULL;
            output_node =  vlib_get_node_by_name (vm, (u8 *) "ip4-input");
            my_nfv9_logging_info->ip4_input_node_index = output_node->index;
            printf("ip4_input_node_index %d\n", my_nfv9_logging_info->ip4_input_node_index);
#endif
            my_nfv9_logging_info->i_vrf    = i_vrf;
            my_nfv9_logging_info->i_vrf_id = i_vrf_id;
            my_nfv9_logging_info->max_length_minus_max_record_size =
            nfv9_get_max_length_minus_max_record_size(
                    nfv9_conf.path_mtu);

         /* my_nfv9_logging_info will have a copy of logging_policy
          * because, it is quite possible that nfv9 config arrives before
          * the corresponding vrfmap is initialized. In such cases
          * this copy will be used to update the vrfmap entry
          */
            my_nfv9_logging_info->logging_policy = nfv9_conf.session_logging;

            if (nfv9_conf.nfv9_global_collector) {
                cnat_nfv9_global_info.cnat_nfv9_global_collector_index =
                    my_nfv9_logging_info - cnat_nfv9_logging_info_pool;

                pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
                            if (my_vrfmap->nfv9_logging_index == EMPTY) {
                                my_vrfmap->nfv9_logging_index =
                                    cnat_nfv9_global_info.cnat_nfv9_global_collector_index;
                            }
                        }));
            } else {
                u32 my_vrfmap_found = 0;

                FIND_MY_VRF_USING_I_VRF_ID
                my_vrfmap = my_vrfmap_temp;
                    if (my_vrfmap_found) {
                        if(my_vrfmap->nfv9_logging_index == EMPTY) {
                            my_vrfmap->nfv9_logging_index =
                                my_nfv9_logging_info - cnat_nfv9_logging_info_pool;
                            // my_vrfmap->nf_logging_policy = mp->session_logging;
                        } else {
                            cnat_nfv9_logging_info_t *my_nfv9_logging_info_temp = cnat_nfv9_logging_info_pool + my_vrfmap->nfv9_logging_index;
                            while(my_nfv9_logging_info_temp->nfv9_logging_next_index != EMPTY){
                                my_nfv9_logging_info_temp = cnat_nfv9_logging_info_pool + my_nfv9_logging_info_temp->nfv9_logging_next_index;
                            }
                            my_nfv9_logging_info_temp->nfv9_logging_next_index = my_nfv9_logging_info - cnat_nfv9_logging_info_pool;
                        }
                    }
            }
        }

        /* Update logging policy */
        my_nfv9_logging_info->logging_policy = nfv9_conf.session_logging;
        if (nfv9_conf.nfv9_global_collector) {
                if(PLATFORM_DBL_SUPPORT) {
                    pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
                        if (my_vrfmap->nfv9_logging_index ==
                    cnat_nfv9_global_info.cnat_nfv9_global_collector_index) {
                    my_vrfmap->nf_logging_policy = nfv9_conf.session_logging;
                }
                    }));
                } else {
                        nfv9_conf.rc = CNAT_ERR_NO_SESSION_DB;
                }
        } else {
                if(PLATFORM_DBL_SUPPORT) {
                        u32 my_vrfmap_found = 0;
                        my_vrfmap_temp = NULL;
                        FIND_MY_VRF_USING_I_VRF_ID
                        my_vrfmap = my_vrfmap_temp;
                        if (my_vrfmap_found) {
                          //    my_vrfmap->nf_logging_policy = mp->session_logging;
                        }
                } else {
                        nfv9_conf.rc = CNAT_ERR_NO_SESSION_DB;
                }
        }
        u8  nfv9_logging_policy = 0;
        u32 my_vrfmap_found = 0;
        my_vrfmap_temp = NULL;
        FIND_MY_VRF_USING_I_VRF_ID
        my_vrfmap = my_vrfmap_temp;
            if (my_vrfmap_found) {
                u32 index_curr = my_vrfmap->nfv9_logging_index;
                cnat_nfv9_logging_info_t *my_nfv9_logging_info_temp;
                while(index_curr != EMPTY) {
                    my_nfv9_logging_info_temp = cnat_nfv9_logging_info_pool + index_curr;
                    nfv9_logging_policy = nfv9_logging_policy || my_nfv9_logging_info_temp->logging_policy;
                    index_curr = (cnat_nfv9_logging_info_pool + index_curr)->nfv9_logging_next_index;
                }
                my_vrfmap->nf_logging_policy = nfv9_logging_policy;
            }
            //vlib_cli_output(vm,"Netflow logging policy = %d\n", my_vrfmap->nf_logging_policy);
            if(nfv9_get_server_instance(my_nfv9_logging_info, &new_server_info)
               != CNAT_SUCCESS) {
                vlib_cli_output(vm, "Error to get server instance");
                nfv9_conf.rc = CNAT_ERR_PARSER;
                goto done;
            }
        nfv9_init_pkt_sent_data(my_nfv9_logging_info);

        vlib_cli_output(vm,"Adding NFv9 Logging Succeeded\n");
        nfv9_configured = 1;

    } else {
    /*Delete path*/
        if (found) {
            /* if found entry then we need to overwrite the my_nfv9_logging_info_tmp
             * to my_nfv9_logging_info
             */
            my_nfv9_logging_info = my_nfv9_logging_info_tmp;
            if (i_vrf == INVALID_UIDX) {
                /*
                 * We are deleting a global collector.  Mark the collectors
                 * in those VRFs using the global collector
                 */
                pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
                            if (my_vrfmap->nfv9_logging_index ==
                                cnat_nfv9_global_info.cnat_nfv9_global_collector_index) {
                                my_vrfmap->nfv9_logging_index = EMPTY;
                            }
                        }));

                cnat_nfv9_global_info.cnat_nfv9_global_collector_index = EMPTY;
            } else {
                u32 my_vrfmap_found = 0;
                my_vrfmap_temp = NULL;
                FIND_MY_VRF_USING_I_VRF_ID
                my_vrfmap = my_vrfmap_temp;
                    if (my_vrfmap_found) {
                        // my_vrfmap->nfv9_logging_index = cnat_nfv9_global_info.cnat_nfv9_global_collector_index;
                    }
            }
            if (my_nfv9_logging_info->queued_logging_context ||
                my_nfv9_logging_info->current_logging_context) {
                /*
                 * If there is a pending context:
                 * Set the deleted flag to 1.  This will ensure
                 * that the logging info structure gets freed after any
                 * pending packet get sent
                 */
                my_nfv9_logging_info->deleted = 1;
            } else {
                /*
                 * No pending context, just free the logging info structure
                 */
                u32  index = my_nfv9_logging_info - cnat_nfv9_logging_info_pool;
                if(index == my_vrfmap->nfv9_logging_index) {
                    /* Deleting the first sever */
                    my_vrfmap->nfv9_logging_index = my_nfv9_logging_info->nfv9_logging_next_index;
                    /* if(my_nfv9_logging_info->nfv9_logging_next_index != EMPTY){
                        my_vrfmap->nf_logging_policy = (cnat_nfv9_logging_info_pool + my_nfv9_logging_info->nfv9_logging_next_index)->logging_policy;
                    } else {
                        my_vrfmap->nf_logging_policy = EMPTY;
                    }*/
                } else {
                    u32 index_curr = my_vrfmap->nfv9_logging_index;
                    u32 index_prev = EMPTY;
                    while(index_curr != EMPTY) {
                        index_prev = index_curr;
                        index_curr = (cnat_nfv9_logging_info_pool + index_curr)->nfv9_logging_next_index;
                        if(index == index_curr)
                        {
                            (cnat_nfv9_logging_info_pool + index_prev)->nfv9_logging_next_index = (cnat_nfv9_logging_info_pool + index_curr)->nfv9_logging_next_index;
                            break;
                        }
                    }
                }
                nfv9_delete_server_info(my_nfv9_logging_info);
                pool_put(cnat_nfv9_logging_info_pool, my_nfv9_logging_info);
            }

            vlib_cli_output(vm, "Deleting NFv9 Logging Succeeded\n");
            /* 
             * Search across all vrf and check if nfv9 logging is configured.
             */ 
            nfv9_configured = 0;
            pool_foreach (my_nfv9_logging_info, cnat_nfv9_logging_info_pool, ({
                 nfv9_configured = 1;
                 break;
            }));
        } else {
            nfv9_conf.rc = CNAT_NO_CONFIG;
            vlib_cli_output(vm, "Add NFv9 Logging Failed (2) Non Existent vrf %d\n",
                                     i_vrf);

        }
        u8  nfv9_logging_policy = 0;
        u32 my_vrfmap_found = 0;
        my_vrfmap_temp = NULL;
        FIND_MY_VRF_USING_I_VRF_ID
        my_vrfmap = my_vrfmap_temp; 
            if (my_vrfmap_found) {
                u32 index_curr = my_vrfmap->nfv9_logging_index;
                cnat_nfv9_logging_info_t *my_nfv9_logging_info_temp;
                while(index_curr != EMPTY) {
                    my_nfv9_logging_info_temp = cnat_nfv9_logging_info_pool + index_curr;
                    nfv9_logging_policy = nfv9_logging_policy || my_nfv9_logging_info_temp->logging_policy;
                    index_curr = (cnat_nfv9_logging_info_pool + index_curr)->nfv9_logging_next_index;
                }
                my_vrfmap->nf_logging_policy = nfv9_logging_policy;
            }
    }

done:
    return 0;
}

/* config CLIs */
VLIB_CLI_COMMAND (set_vcgn_map_command) = {
    .path = "set vcgn map",
    .short_help = "set vcgn map <lo-address> [- <hi-address>]",
    .function = set_vcgn_map_command_fn,
};

VLIB_CLI_COMMAND (set_vcgn_inside_command) = {
    .path = "set vcgn inside",
    .short_help = "set vcgn inside <inside intfc> outside <outside intfc>",
    .function = set_vcgn_inside_command_fn,
};

VLIB_CLI_COMMAND (set_vcgn_tcp_timeout_command) = {
    .path = "set vcgn tcp timeout",
    .short_help = "set vcgn tcp timeout active <1-65535> init <1-65535>",
    .function = set_vcgn_tcp_timeout_command_fn,
};

VLIB_CLI_COMMAND (set_vcgn_udp_timeout_command) = {
    .path = "set vcgn udp timeout",
    .short_help = "set vcgn udp timeout active <1-65535> init <1-65535>",
    .function = set_vcgn_udp_timeout_command_fn,
};

VLIB_CLI_COMMAND (set_vcgn_icmp_timeout_command) = {
    .path = "set vcgn icmp timeout",
    .short_help = "set vcgn icmp timeout <1-65535>",
    .function = set_vcgn_icmp_timeout_command_fn,
};

VLIB_CLI_COMMAND (set_vcgn_protocol_default_timeout_command) = {
    .path = "set vcgn default timeout",
    .short_help = "set vcgn default timeout protocol <tcp/udp/icmp>",
    .function = set_vcgn_protocol_default_timeout_command_fn,
};

VLIB_CLI_COMMAND (set_vcgn_dynamic_port_start_range_command) = {
    .path = "set vcgn dynamic port start",
    .short_help = "set vcgn dynamic port start <1-65535>",
    .function = set_vcgn_dynamic_port_start_range_command_fn,
};

VLIB_CLI_COMMAND (set_vcgn_port_limit_command) = {
    .path = "set vcgn port limit",
    .short_help = "set vcgn port limit <1-65535>",
    .function = set_vcgn_port_limit_command_fn,
};

VLIB_CLI_COMMAND (set_vcgn_nfv9_logging_cofig_command) = {
    .path = "set vcgn nfv9",
    .short_help = "set vcgn nfv9 [del] inside <interface> "
                  "server <ip-addr> port <port> [refresh-rate <n>] "
                  "[timeout <n>] [pmtu <n>]",
    .function = set_vcgn_nfv9_logging_cofig_command_fn,
};


/* show CLIs */
VLIB_CLI_COMMAND (show_vcgn_config_command) = {
    .path = "show vcgn config",
    .short_help = "show vcgn config",
    .function = show_vcgn_config_command_fn,
};

VLIB_CLI_COMMAND (show_vcgn_stat_command) = {
    .path = "show vcgn statistics",
    .short_help = "show vcgn statistics",
    .function = show_vcgn_stats_command_fn,
};

VLIB_CLI_COMMAND (show_vcgn_inside_translation_command) = {
    .path = "show vcgn inside-translation",
    .short_help = "show vcgn inside-translation protocol <tcp/udp/icmp> "
                  "interface <inside-if> inside-addr <ip-addr> "
                  "[start-port <n>] [end-port <n>]",
    .function = show_vcgn_inside_translation_command_fn,
};

VLIB_CLI_COMMAND (show_vcgn_outside_translation_command) = {
    .path = "show vcgn outside-translation",
    .short_help = "show vcgn outside-translation protocol <tcp/udp/icmp> "
                  "interface <outside-if> outside-addr <ip-addr> "
                  "[start-port <n>] [end-port <n>]",
    .function = show_vcgn_outside_translation_command_fn,
};

static clib_error_t *
vcgn_init (vlib_main_t * vm)
{
  clib_error_t * error = 0;

  if ((error = vlib_call_init_function 
       (vm, vcgn_classify_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_udp_inside_input_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_udp_outside_input_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_udp_inside_input_exc_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_db_scanner_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_tcp_inside_input_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_tcp_inside_input_exc_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_tcp_outside_input_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_icmp_q_inside_input_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_icmp_q_inside_input_exc_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_icmp_q_outside_input_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_icmp_e_inside_input_init)))
    return error;
  if ((error = vlib_call_init_function 
       (vm, cnat_ipv4_icmp_e_outside_input_init)))
    return error;

  return error;
}

/* 
 * This routine exists to convince the vlib plugin framework that
 * we haven't accidentally copied a random .dll into the plugin
 * directory. This is used in lieu of VLIB_INIT_FUNCTION(vcgn_init).
 *
 * Also collects global variable pointers passed from the vpp engine
 */
clib_error_t *
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
    return vcgn_init(vm);
}
