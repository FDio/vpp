/*
 * l2_input.c : layer 2 input packet processing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vlib/cli.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_bvi.h>
#include <vnet/l2/l2_fib.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>

extern clib_error_t *
ethernet_arp_hw_interface_link_up_down (vnet_main_t * vnm,
                                        u32 hw_if_index,
                                        u32 flags);

extern clib_error_t *
ip6_discover_neighbor_hw_interface_link_up_down (vnet_main_t * vnm,
                                                 u32 hw_if_index,
                                                 u32 flags);

// Feature graph node names
static char * l2input_feat_names[] = {
#define _(sym,name) name,
  foreach_l2input_feat
#undef _
};

char **l2input_get_feat_names(void) {
  return l2input_feat_names;
}


typedef struct {
  /* per-pkt trace data */ 
  u8 src[6];
  u8 dst[6];
  u32 next_index;
  u32 sw_if_index;
} l2input_trace_t;

/* packet trace format function */
static u8 * format_l2input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2input_trace_t * t = va_arg (*args, l2input_trace_t *);
  
  s = format (s, "l2-input: sw_if_index %d dst %U src %U",
	      t->sw_if_index,
              format_ethernet_address, t->dst,
              format_ethernet_address, t->src);
  return s;
}

l2input_main_t l2input_main;

static vlib_node_registration_t l2input_node;

#define foreach_l2input_error			\
_(L2INPUT,     "L2 input packets")		\
_(DROP,        "L2 input drops")

typedef enum {
#define _(sym,str) L2INPUT_ERROR_##sym,
  foreach_l2input_error
#undef _
  L2INPUT_N_ERROR,
} l2input_error_t;

static char * l2input_error_strings[] = {
#define _(sym,string) string,
  foreach_l2input_error
#undef _
};

typedef enum {			/*  */
  L2INPUT_NEXT_LEARN,
  L2INPUT_NEXT_FWD,
  L2INPUT_NEXT_DROP,
  L2INPUT_N_NEXT,
} l2input_next_t;


static_always_inline void
classify_and_dispatch (vlib_main_t * vm,
                       vlib_node_runtime_t * node,
                       u32 cpu_index, 
                       l2input_main_t * msm,
	               vlib_buffer_t * b0,
		       u32 *next0)
{
  // Load L2 input feature struct
  // Load bridge domain struct
  // Parse ethernet header to determine unicast/mcast/broadcast
  // take L2 input stat
  // classify packet as IP/UDP/TCP, control, other
  // mask feature bitmap
  // go to first node in bitmap
  // Later: optimize VTM
  //
  // For L2XC, 
  //   set tx sw-if-handle
 
  u8 mcast_dmac; 
  __attribute__((unused)) u8 l2bcast;
  __attribute__((unused)) u8 l2mcast;
  __attribute__((unused)) u8 l2_stat_kind;
  u16 ethertype;
  u8 protocol;
  l2_input_config_t *config;
  l2_bridge_domain_t *bd_config;
  u16 bd_index0;
  u32 feature_bitmap;
  u32 feat_mask;
  ethernet_header_t * h0;
  u8 * l3h0;
  u32 sw_if_index0;
  u8 bvi_flg = 0;

#define get_u32(addr) ( *((u32 *)(addr)) )
#define get_u16(addr) ( *((u16 *)(addr)) )
#define STATS_IF_LAYER2_UCAST_INPUT_CNT 0
#define STATS_IF_LAYER2_MCAST_INPUT_CNT 1
#define STATS_IF_LAYER2_BCAST_INPUT_CNT 2

  // Check for from-BVI processing
  // When we come from ethernet-input, TX is ~0
  if (PREDICT_FALSE (vnet_buffer(b0)->sw_if_index[VLIB_TX] != ~0)) {
    // Set up for a from-bvi packet
    bvi_to_l2 (vm, 
               msm->vnet_main, 
               cpu_index, 
               b0, 
               vnet_buffer(b0)->sw_if_index[VLIB_TX]);
    bvi_flg = 1;
  }

  // The RX interface can be changed by bvi_to_l2()
  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

  h0 = vlib_buffer_get_current (b0);
  l3h0 = (u8 *)h0 + vnet_buffer(b0)->l2.l2_len;

  // Determine L3 packet type. Only need to check the common types.
  // Used to filter out features that don't apply to common packets.
  ethertype = clib_net_to_host_u16(get_u16(l3h0 - 2));
  if (ethertype == ETHERNET_TYPE_IP4) {
    protocol = ((ip4_header_t *)l3h0)->protocol;
    if ((protocol == IP_PROTOCOL_UDP) ||
        (protocol == IP_PROTOCOL_TCP)) {
      feat_mask = IP_UDP_TCP_FEAT_MASK;
    } else {
      feat_mask = IP4_FEAT_MASK;
    }
  } else if (ethertype == ETHERNET_TYPE_IP6) {
    protocol = ((ip6_header_t *)l3h0)->protocol;
    // Don't bother checking for extension headers for now
    if ((protocol == IP_PROTOCOL_UDP) ||
        (protocol == IP_PROTOCOL_TCP)) {
      feat_mask = IP_UDP_TCP_FEAT_MASK;
    } else {
      feat_mask = IP6_FEAT_MASK;
    }
  } else if (ethertype == ETHERNET_TYPE_MPLS_UNICAST) {
    feat_mask = IP6_FEAT_MASK;
  } else {
    // allow all features
    feat_mask = ~0;
  } 

  // determine layer2 kind for stat and mask
  mcast_dmac = ethernet_address_cast(h0->dst_address);
  l2bcast = 0;
  l2mcast = 0;
  l2_stat_kind = STATS_IF_LAYER2_UCAST_INPUT_CNT;
  if (PREDICT_FALSE (mcast_dmac)) {
    u32 *dsthi = (u32 *) &h0->dst_address[0];
    u32 *dstlo = (u32 *) &h0->dst_address[2];

    // Disable bridge forwarding (flooding will execute instead if not xconnect)
    feat_mask &= ~(L2INPUT_FEAT_FWD | L2INPUT_FEAT_UU_FLOOD);
    if (ethertype != ETHERNET_TYPE_ARP) // Disable ARP-term for non-ARP packet
	feat_mask &= ~(L2INPUT_FEAT_ARP_TERM);

    // dest mac is multicast or broadcast
    if ((*dstlo == 0xFFFFFFFF) && (*dsthi == 0xFFFFFFFF)) { 
      // dest mac == FF:FF:FF:FF:FF:FF
      l2_stat_kind = STATS_IF_LAYER2_BCAST_INPUT_CNT;
      l2bcast=1;
    } else {
      l2_stat_kind = STATS_IF_LAYER2_MCAST_INPUT_CNT;
      l2mcast=1;
    }
  }
  // TODO: take l2 stat

  // Get config for the input interface
  config = vec_elt_at_index(msm->configs, sw_if_index0);

  // Save split horizon group, use 0 for BVI to make sure not dropped
  vnet_buffer(b0)->l2.shg = bvi_flg ? 0 : config->shg;

  if (config->xconnect) {
    // Set the output interface
    vnet_buffer(b0)->sw_if_index[VLIB_TX] = config->output_sw_if_index;

  } else {

    // Do bridge-domain processing
    bd_index0 = config->bd_index;
    // save BD ID for next feature graph nodes
    vnet_buffer(b0)->l2.bd_index = bd_index0;

    // Get config for the bridge domain interface
    bd_config = vec_elt_at_index(msm->bd_configs, bd_index0);

    // Process bridge domain feature enables.
    // To perform learning/flooding/forwarding, the corresponding bit
    // must be enabled in both the input interface config and in the
    // bridge domain config. In the bd_bitmap, bits for features other
    // than learning/flooding/forwarding should always be set.
    feat_mask = feat_mask & bd_config->feature_bitmap;
  }

  // mask out features from bitmap using packet type and bd config
  feature_bitmap = config->feature_bitmap & feat_mask;

  // save for next feature graph nodes
  vnet_buffer(b0)->l2.feature_bitmap = feature_bitmap;

  // Determine the next node
  *next0 = feat_bitmap_get_next_node_index(msm->feat_next_node_index,
                                           feature_bitmap);
}


static uword
l2input_node_fn (vlib_main_t * vm,
	         vlib_node_runtime_t * node,
	         vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  l2input_next_t next_index;
  l2input_main_t * msm = &l2input_main;
  vlib_node_t *n = vlib_get_node (vm, l2input_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t * em = &vm->error_main;
  u32 cpu_index = os_get_cpu_number();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors; /* number of packets to process */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 6 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3, * p4 , * p5;
            u32 sw_if_index2, sw_if_index3;
            
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
            
	    // Prefetch the buffer header and packet for the N+2 loop iteration
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);

	    // Prefetch the input config for the N+1 loop iteration
            // This depends on the buffer header above
            sw_if_index2 = vnet_buffer(p2)->sw_if_index[VLIB_RX];
            sw_if_index3 = vnet_buffer(p3)->sw_if_index[VLIB_RX];
            CLIB_PREFETCH (&msm->configs[sw_if_index2], CLIB_CACHE_LINE_BYTES, LOAD);
            CLIB_PREFETCH (&msm->configs[sw_if_index3], CLIB_CACHE_LINE_BYTES, LOAD);

            // Don't bother prefetching the bridge-domain config (which 
            // depends on the input config above). Only a small number of
            // bridge domains are expected. Plus the structure is small
            // and several fit in a cache line.
          }

          /* speculatively enqueue b0 and b1 to the current next frame */
          /* bi is "buffer index", b is pointer to the buffer */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
            /* RX interface handles */
            sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
            sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

            if (b0->flags & VLIB_BUFFER_IS_TRACED) {
              ethernet_header_t * h0 = vlib_buffer_get_current (b0);
              l2input_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              memcpy(t->src, h0->src_address, 6);
              memcpy(t->dst, h0->dst_address, 6);
            }
            if (b1->flags & VLIB_BUFFER_IS_TRACED) {
              ethernet_header_t * h1 = vlib_buffer_get_current (b1);
              l2input_trace_t *t = 
                      vlib_add_trace (vm, node, b1, sizeof (*t));
              t->sw_if_index = sw_if_index1;
              memcpy(t->src, h1->src_address, 6);
              memcpy(t->dst, h1->dst_address, 6);
            }
          }

          em->counters[node_counter_base_index + L2INPUT_ERROR_L2INPUT] += 2;

	  classify_and_dispatch (vm,
                                 node,
                                 cpu_index, 
                                 msm,
				 b0,
				 &next0);

	  classify_and_dispatch (vm,
                                 node,
                                 cpu_index, 
                                 msm,
				 b1,
				 &next1);

          /* verify speculative enqueues, maybe switch current next frame */
          /* if next0==next1==next_index then nothing special needs to be done */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
      }
      
      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
 
          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            ethernet_header_t * h0 = vlib_buffer_get_current (b0);
            l2input_trace_t *t = 
               vlib_add_trace (vm, node, b0, sizeof (*t));
            sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
            t->sw_if_index = sw_if_index0;
            memcpy(t->src, h0->src_address, 6);
            memcpy(t->dst, h0->dst_address, 6);
          }

          em->counters[node_counter_base_index + L2INPUT_ERROR_L2INPUT] += 1;

	  classify_and_dispatch (vm,
                                 node,
                                 cpu_index, 
                                 msm,
				 b0,
				 &next0);

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


VLIB_REGISTER_NODE (l2input_node,static) = {
  .function = l2input_node_fn,
  .name = "l2-input",
  .vector_size = sizeof (u32),
  .format_trace = format_l2input_trace,
  .format_buffer = format_ethernet_header_with_length,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(l2input_error_strings),
  .error_strings = l2input_error_strings,

  .n_next_nodes = L2INPUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
       [L2INPUT_NEXT_LEARN] = "l2-learn",
       [L2INPUT_NEXT_FWD]   = "l2-fwd",
       [L2INPUT_NEXT_DROP]  = "error-drop",
  },
};

clib_error_t *l2input_init (vlib_main_t *vm)
{
  l2input_main_t * mp = &l2input_main;
 
  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  // Get packets RX'd from L2 interfaces
  ethernet_register_l2_input (vm, l2input_node.index);

  // Create the config vector
  vec_validate(mp->configs, 100);  
  // create 100 sw interface entries and zero them

  // Initialize the feature next-node indexes
  feat_bitmap_init_next_nodes(vm,
                              l2input_node.index,
                              L2INPUT_N_FEAT,
                              l2input_get_feat_names(),
                              mp->feat_next_node_index);

  return 0;
}

VLIB_INIT_FUNCTION (l2input_init);


// Get a pointer to the config for the given interface
l2_input_config_t * l2input_intf_config (u32 sw_if_index)
{
  l2input_main_t * mp = &l2input_main;
 
  vec_validate(mp->configs, sw_if_index);  
  return vec_elt_at_index(mp->configs, sw_if_index);
}

// Enable (or disable) the feature in the bitmap for the given interface
u32 l2input_intf_bitmap_enable (u32 sw_if_index,
                                 u32 feature_bitmap,
                                 u32 enable)
{
  l2input_main_t * mp = &l2input_main;
  l2_input_config_t *config;
 
  vec_validate(mp->configs, sw_if_index);  
  config = vec_elt_at_index(mp->configs, sw_if_index);

  if (enable) {
    config->feature_bitmap |= feature_bitmap;
  } else {
    config->feature_bitmap &= ~feature_bitmap;
  }

  return config->feature_bitmap;
}

u32 l2input_set_bridge_features(u32 bd_index,
                                 u32 feat_mask, u32 feat_value)
{
  l2_bridge_domain_t * bd_config;
  vec_validate (l2input_main.bd_configs, bd_index);
  bd_config = vec_elt_at_index(l2input_main.bd_configs, bd_index);
  bd_validate (bd_config);
  bd_config->feature_bitmap = (bd_config->feature_bitmap & ~feat_mask) | feat_value;
  return bd_config->feature_bitmap;
}

// Set the subinterface to run in l2 or l3 mode.
// for L3 mode, just the sw_if_index is specified
// for bridged mode, the bd id and bvi flag are also specified
// for xconnect mode, the peer sw_if_index is also specified
// Return 0 if ok, or non-0 if there was an error

u32 set_int_l2_mode (vlib_main_t * vm,
                     vnet_main_t * vnet_main,
                     u32 mode,
                     u32 sw_if_index,
                     u32 bd_index, // for bridged interface
                     u32 bvi,   // the bridged interface is the BVI
                     u32 shg,   // the bridged interface's split horizon group
                     u32 xc_sw_if_index) // peer interface for xconnect
{
  l2input_main_t * mp = &l2input_main;
  vnet_main_t * vnm = vnet_get_main();
  vnet_hw_interface_t * hi;
  l2_output_config_t * out_config;
  l2_input_config_t * config;
  l2_bridge_domain_t * bd_config;
  l2_flood_member_t member;
  u64 mac;
  i32 l2_if_adjust = 0; 

  hi = vnet_get_sup_hw_interface (vnet_main, sw_if_index);

  vec_validate(mp->configs, sw_if_index);  
  config = vec_elt_at_index(mp->configs, sw_if_index);

  if (config->bridge) {
    // Interface is already in bridge mode. Undo the existing config.
    bd_config = vec_elt_at_index(mp->bd_configs, config->bd_index);

    // remove interface from flood vector
    bd_remove_member (bd_config, sw_if_index);

    // undo any BVI-related config
    if (bd_config->bvi_sw_if_index == sw_if_index) {
      bd_config->bvi_sw_if_index = ~0;
      config->bvi = 0;

      // restore output node
      hi->output_node_index = bd_config->saved_bvi_output_node_index;

      // delete the l2fib entry for the bvi interface
      mac = *((u64 *)hi->hw_address);
      l2fib_del_entry (mac, config->bd_index);

      // Let ARP and NDP know that the output node index changed
      ethernet_arp_hw_interface_link_up_down(vnet_main, hi->hw_if_index, 0);
      ip6_discover_neighbor_hw_interface_link_up_down(vnet_main, hi->hw_if_index, 0);
    } 
    l2_if_adjust--;
  } else if (config->xconnect) {
    l2_if_adjust--;
  }

  // Initialize the l2-input configuration for the interface
  if (mode == MODE_L3) {
    config->xconnect = 0;
    config->bridge = 0;
    config->shg = 0;
    config->bd_index = 0;
    config->feature_bitmap = L2INPUT_FEAT_DROP;
  } else if (mode == MODE_L2_CLASSIFY) {
      config->xconnect = 1;
      config->bridge = 0;
      config->output_sw_if_index = xc_sw_if_index;

      // Make sure last-chance drop is configured
      config->feature_bitmap |= L2INPUT_FEAT_DROP | L2INPUT_FEAT_CLASSIFY;

      // Make sure bridging features are disabled
      config->feature_bitmap &= 
          ~(L2INPUT_FEAT_LEARN | L2INPUT_FEAT_FWD | L2INPUT_FEAT_FLOOD);
      shg = 0; // not used in xconnect

      // Insure all packets go to ethernet-input
      ethernet_set_rx_redirect (vnet_main, hi, 1);
  } else {

    if (mode == MODE_L2_BRIDGE) {
        /* 
         * Remove a check that the interface must be an Ethernet.
         * Specifically so we can bridge to L3 tunnel interfaces.
         * Here's the check:
         * if (hi->hw_class_index != ethernet_hw_interface_class.index)
         * 
         */
        if (!hi)
            return MODE_ERROR_ETH;  // non-ethernet

      config->xconnect = 0;
      config->bridge = 1;
      config->bd_index = bd_index;

      // Enable forwarding, flooding, learning and ARP termination by default
      // (note that ARP term is disabled on BD feature bitmap by default)
      config->feature_bitmap |= L2INPUT_FEAT_FWD | L2INPUT_FEAT_UU_FLOOD | 
	  L2INPUT_FEAT_FLOOD | L2INPUT_FEAT_LEARN | L2INPUT_FEAT_ARP_TERM;

      // Make sure last-chance drop is configured
      config->feature_bitmap |= L2INPUT_FEAT_DROP;

      // Make sure xconnect is disabled
      config->feature_bitmap &= ~L2INPUT_FEAT_XCONNECT;

      // Set up bridge domain
      vec_validate(mp->bd_configs, bd_index);  
      bd_config = vec_elt_at_index(mp->bd_configs, bd_index);
      bd_validate (bd_config);

      // TODO: think: add l2fib entry even for non-bvi interface?
 
      // Do BVI interface initializations
      if (bvi) {
        // insure BD has no bvi interface (or replace that one with this??)
        if (bd_config->bvi_sw_if_index != ~0) {
          return MODE_ERROR_BVI_DEF; // bd already has a bvi interface
        } 
        bd_config->bvi_sw_if_index = sw_if_index;
        config->bvi = 1;

        // make BVI outputs go to l2-input
        bd_config->saved_bvi_output_node_index = hi->output_node_index;
        hi->output_node_index = l2input_node.index;

        // create the l2fib entry for the bvi interface
        mac = *((u64 *)hi->hw_address);
        l2fib_add_entry (mac, bd_index, sw_if_index, 1, 0, 1);  // static + bvi

        // Disable learning by default. no use since l2fib entry is static.
        config->feature_bitmap &= ~L2INPUT_FEAT_LEARN;

        // Let ARP and NDP know that the output_index_node changed so they
        // can send requests via BVI to BD
        ethernet_arp_hw_interface_link_up_down(vnet_main, hi->hw_if_index, 0);
        ip6_discover_neighbor_hw_interface_link_up_down(vnet_main, hi->hw_if_index, 0);
      }

      // Add interface to bridge-domain flood vector
      member.sw_if_index = sw_if_index;
      member.flags = bvi ? L2_FLOOD_MEMBER_BVI : L2_FLOOD_MEMBER_NORMAL;
      member.shg = shg;
      bd_add_member (bd_config, &member);
     
    } else {
      config->xconnect = 1;
      config->bridge = 0;
      config->output_sw_if_index = xc_sw_if_index;

      // Make sure last-chance drop is configured
      config->feature_bitmap |= L2INPUT_FEAT_DROP;

      // Make sure bridging features are disabled
      config->feature_bitmap &= ~(L2INPUT_FEAT_LEARN | L2INPUT_FEAT_FWD | L2INPUT_FEAT_FLOOD);

      config->feature_bitmap |= L2INPUT_FEAT_XCONNECT;
      shg = 0; // not used in xconnect
    }

    // set up split-horizon group
    config->shg = shg;
    out_config = l2output_intf_config (sw_if_index);
    out_config->shg = shg;

    // Test: remove this when non-IP features can be configured.
    // Enable a non-IP feature to test IP feature masking
    // config->feature_bitmap |= L2INPUT_FEAT_CTRL_PKT;

    l2_if_adjust++;
  }

  // Adjust count of L2 interfaces
  hi->l2_if_count += l2_if_adjust;

  if (hi->hw_class_index == ethernet_hw_interface_class.index) {
    if ((hi->l2_if_count == 1) && (l2_if_adjust == 1)) {
      // Just added first L2 interface on this port

      // Set promiscuous mode on the l2 interface
      ethernet_set_flags (vnet_main, hi->hw_if_index,
			  ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);

      // Insure all packets go to ethernet-input
      ethernet_set_rx_redirect (vnet_main, hi, 1);

    } else if ((hi->l2_if_count == 0) && (l2_if_adjust == -1)) {
      // Just removed only L2 subinterface on this port

      // Disable promiscuous mode on the l2 interface
      ethernet_set_flags (vnet_main, hi->hw_if_index, 0);

      // Allow ip packets to go directly to ip4-input etc
      ethernet_set_rx_redirect (vnet_main, hi, 0);
    }
  }

  // Set up the L2/L3 flag in the interface parsing tables
  ethernet_sw_interface_set_l2_mode(vnm, sw_if_index, (mode!=MODE_L3));

  return 0;
}

// set subinterface in bridging mode with a bridge-domain ID
// The CLI format is:
//    set interface l2 bridge <interface> <bd> [bvi] [split-horizon-group]
static clib_error_t *
int_l2_bridge  (vlib_main_t * vm,
                unformat_input_t * input,
                vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 bd_index, bd_id;
  u32 sw_if_index;
  u32 bvi;
  u32 rc;
  u32 shg;

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
                                 format_unformat_error, input);
      goto done;
    }

  if (!unformat (input, "%d", &bd_id)) {
      error = clib_error_return (0, "expected bridge domain ID `%U'",
                                 format_unformat_error, input);
      goto done;
  }

  bd_index = bd_find_or_add_bd_index (&bd_main, bd_id);

  // optional bvi 
  bvi = unformat (input, "bvi");

  // optional split horizon group
  shg = 0;
  (void) unformat (input, "%d", &shg);

  // set the interface mode
  if ((rc = set_int_l2_mode(vm, vnm, MODE_L2_BRIDGE, sw_if_index, bd_index, bvi, shg, 0))) {
    if (rc == MODE_ERROR_ETH) {
      error = clib_error_return (0, "bridged interface must be ethernet",
                                 format_unformat_error, input);
    } else if (rc == MODE_ERROR_BVI_DEF) {
      error = clib_error_return (0, "bridge-domain already has a bvi interface",
                                 format_unformat_error, input);
    } else {
      error = clib_error_return (0, "invalid configuration for interface",
                                 format_unformat_error, input);
    }
    goto done;
  }

 done:
  return error;
}

VLIB_CLI_COMMAND (int_l2_bridge_cli, static) = {
  .path = "set interface l2 bridge",
  .short_help = "set interface to L2 bridging mode in <bridge-domain ID> [bvi] [shg]",
  .function = int_l2_bridge,
};

// set subinterface in xconnect mode with another interface
// The CLI format is:
//    set interface l2 xconnect <interface> <peer interface>
static clib_error_t *
int_l2_xc (vlib_main_t * vm,
           unformat_input_t * input,
           vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index;
  u32 xc_sw_if_index;

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
                                 format_unformat_error, input);
      goto done;
    }

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &xc_sw_if_index))
    {
      error = clib_error_return (0, "unknown peer interface `%U'",
                                 format_unformat_error, input);
      goto done;
    }

  // set the interface mode
  if (set_int_l2_mode(vm, vnm, MODE_L2_XC, sw_if_index, 0, 0, 0, xc_sw_if_index)) {
      error = clib_error_return (0, "invalid configuration for interface",
                                 format_unformat_error, input);
      goto done;
  }

 done:
  return error;
}

VLIB_CLI_COMMAND (int_l2_xc_cli, static) = {
  .path = "set interface l2 xconnect",
  .short_help = "set interface to L2 cross-connect mode with <peer interface>",
  .function = int_l2_xc,
};

// set subinterface in L3 mode
// The CLI format is:
//    set interface l3 <interface>
static clib_error_t *
int_l3  (vlib_main_t * vm,
         unformat_input_t * input,
         vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index;

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
                                 format_unformat_error, input);
      goto done;
    }

  // set the interface mode
  if (set_int_l2_mode(vm, vnm, MODE_L3, sw_if_index, 0, 0, 0, 0)) {
      error = clib_error_return (0, "invalid configuration for interface",
                                 format_unformat_error, input);
      goto done;
  }

 done:
  return error;
}

VLIB_CLI_COMMAND (int_l3_cli, static) = {
  .path = "set interface l3",
  .short_help = "set interface to L3 mode",
  .function = int_l3,
};

// The CLI format is:
//    show mode [<if-name1> <if-name2> ...]
static clib_error_t *
show_int_mode  (vlib_main_t * vm,
         unformat_input_t * input,
         vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  char * mode;
  u8 * args;
  vnet_interface_main_t * im = &vnm->interface_main;
  vnet_sw_interface_t * si, * sis = 0;
  l2input_main_t * mp = &l2input_main;
  l2_input_config_t * config;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
       u32 sw_if_index;

      /* See if user wants to show specific interface */
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  si =  pool_elt_at_index (im->sw_interfaces, sw_if_index);
	  vec_add1 (sis, si[0]);
	}
      else
        {
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
        }

    }

  if (vec_len (sis) == 0) /* Get all interfaces */
    {
      /* Gather interfaces. */
      sis = vec_new (vnet_sw_interface_t, pool_elts (im->sw_interfaces));
      _vec_len (sis) = 0;
      pool_foreach (si, im->sw_interfaces, ({ vec_add1 (sis, si[0]); }));
    }
  
  vec_foreach (si, sis)
    {
      vec_validate(mp->configs, si->sw_if_index);
      config = vec_elt_at_index(mp->configs, si->sw_if_index);
      if (config->bridge) {
          u32 bd_id;
          mode = "l2 bridge";
          bd_id = l2input_main.bd_configs[config->bd_index].bd_id;

          args = format (0, "bd_id %d%s%d", bd_id, 
                         config->bvi ? " bvi shg " : " shg ", config->shg);
      } else if (config->xconnect) {
          mode = "l2 xconnect";
          args = format (0, "%U",
          format_vnet_sw_if_index_name,
          vnm, config->output_sw_if_index);
      } else {
	mode = "l3";
        args = format (0, " ");
      }
      vlib_cli_output (vm, "%s %U %v\n",
        mode,
        format_vnet_sw_if_index_name,
        vnm, si->sw_if_index,
        args);
      vec_free (args);
  }

done:
  vec_free (sis);
  
  return error;
}

VLIB_CLI_COMMAND (show_l2_mode, static) = {
  .path = "show mode",
  .short_help = "show mode [<if-name1> <if-name2> ...]",
  .function = show_int_mode,
};

#define foreach_l2_init_function                \
_(feat_bitmap_drop_init)                        \
_(l2fib_init)                                   \
_(l2_classify_init)                             \
_(l2bd_init)                                    \
_(l2fwd_init)                                   \
_(l2_inacl_init)                                \
_(l2input_init)                                 \
_(l2_vtr_init)                                  \
_(l2_invtr_init)                                \
_(l2_efp_filter_init)                           \
_(l2learn_init)                                 \
_(l2flood_init)                                 \
_(l2_outacl_init)                               \
_(l2output_init)				\
_(l2_patch_init)				\
_(l2_xcrw_init)

clib_error_t *l2_init (vlib_main_t * vm)
{
  clib_error_t * error;
  
#define _(a) do {                                                       \
  if ((error = vlib_call_init_function (vm, a))) return error; }        \
while (0);
  foreach_l2_init_function;
#undef _
  return 0;
}

VLIB_INIT_FUNCTION (l2_init);
