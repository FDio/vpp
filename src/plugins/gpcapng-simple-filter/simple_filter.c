/*
 * simple_filter.c - Simple GENEVE filter implementation for gpcapng
 *
 * This plugin provides the original legacy filter implementation that supports
 * 5-tuple filtering and GENEVE option matching.
 *
 * Copyright (c) 2024 Cisco Systems, Inc.
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
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h>

#include <gpcapng/gpcapng.h>
#include <gpcapng/public_inlines.h>
#include "simple_filter.h"

/* Simple filter classification function (multiarch) */
void __clib_section (".gpcapng_simple_filter_classify")
CLIB_MULTIARCH_FN (gpcapng_simple_filter_classify)
(u32 api_version, vlib_buffer_t **bufs, u32 n_buffers, vlib_main_t *vm,
 vlib_node_runtime_t *node, vlib_frame_t *frame, int is_output,
 uword *capture_enabled_bitmap, u32 *dest_indices, u32 *n_matched,
 u32 *n_captured, u64 *filtering_elapsed)
{
  simple_filter_main_t *sfm = get_simple_filter_main ();
  u32 pkt_idx;
  u32 matched = 0;
  u32 captured = 0;

  /* Check API version */
  if (api_version != GPCAPNG_FILTER_API_VERSION)
    {
      /* Unsupported API version - capture nothing */
      for (pkt_idx = 0; pkt_idx < n_buffers; pkt_idx++)
	dest_indices[pkt_idx] = ~0;
      return;
    }

  /* Process each packet */
  for (pkt_idx = 0; pkt_idx < n_buffers; pkt_idx++)
    {
      {
	/* prefetch the next buffer, possibly with a "spill", which will
	 * re-prefetch the first buffer again because of the way the buffer is
	 * filled in the main function */
	vlib_buffer_t *b1 = bufs[pkt_idx + 1];
	CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
	CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, LOAD);
      }

      u64 packet_start = clib_cpu_time_now ();
      vlib_buffer_t *b0 = bufs[pkt_idx];
      u32 sw_if_index0 =
	vnet_buffer (b0)->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
      u32 destination_capture_index = ~0;
      int i;

      ip4_header_t *ip4;
      ip6_header_t *ip6;
      ethernet_header_t *ether;
      udp_header_t *udp;
      geneve_header_t *geneve;

      /* Skip interfaces where capture is not enabled, unless global filters
       * are defined */
      if (!clib_bitmap_get (capture_enabled_bitmap, sw_if_index0) &&
	  vec_len (sfm->global_filters) == 0)
	{
	  goto packet_classified;
	}

      /* Parse either IPv4 or IPv6 header */
      ether = vlib_buffer_get_current (b0);
      ip4 = (ip4_header_t *) (ether + 1);

      const u8 *outer_header = (const u8 *) ip4;
      u32 outer_header_len = sizeof (ip4_header_t);

      if ((ip4->ip_version_and_header_length & 0xF0) == 0x40)
	{
	  /* IPv4 */
	  outer_header_len = (ip4->ip_version_and_header_length & 0x0F) * 4;

	  /* Skip non-UDP packets */
	  if (ip4->protocol != IP_PROTOCOL_UDP)
	    goto packet_classified;

	  /* UDP header follows IPv4 header */
	  udp = (udp_header_t *) ((u8 *) ip4 + outer_header_len);
	  outer_header_len += sizeof (udp_header_t);
	}
      else if ((ip4->ip_version_and_header_length & 0xF0) == 0x60)
	{
	  /* IPv6 */
	  ip6 = (ip6_header_t *) ip4;
	  outer_header = (const u8 *) ip6;
	  outer_header_len = sizeof (ip6_header_t);

	  /* Skip non-UDP packets */
	  if (ip6->protocol != IP_PROTOCOL_UDP)
	    goto packet_classified;

	  /* UDP header follows IPv6 header */
	  udp = (udp_header_t *) (ip6 + 1);
	  outer_header_len += sizeof (udp_header_t);
	}
      else
	{
	  /* Neither IPv4 nor IPv6 */
	  goto packet_classified;
	}

      /* Check UDP port for GENEVE */
      if (clib_net_to_host_u16 (udp->dst_port) != GENEVE_UDP_DST_PORT)
	goto packet_classified;

      /* GENEVE header follows UDP header */
      geneve = (geneve_header_t *) (udp + 1);

      /* Calculate GENEVE header length including options */
      u32 geneve_opt_len = geneve_get_opt_len (geneve) * 4;
      u32 geneve_header_len = sizeof (geneve_header_t) + geneve_opt_len;

      /* Get inner header for inner 5-tuple filtering */
      u32 inner_header_len = 0;
      const u8 *inner_header =
	get_inner_ip_header (geneve, geneve_header_len, &inner_header_len);

      /* Check if packet matches any global filter */
      if (vec_len (sfm->global_filters) > 0)
	{
	  destination_capture_index = geneve_packet_matches_global_filter (
	    sfm, outer_header, outer_header_len, inner_header,
	    inner_header_len, geneve, geneve_header_len);
	}

      /* Check if the packet matches any per-interface filter */
      if ((destination_capture_index == ~0) &&
	  clib_bitmap_get (capture_enabled_bitmap, sw_if_index0) &&
	  sw_if_index0 < vec_len (sfm->per_interface))
	{
	  for (i = 0; i < vec_len (sfm->per_interface[sw_if_index0].filters);
	       i++)
	    {
	      u32 cap_index = geneve_packet_matches_filter (
		sfm, outer_header, outer_header_len, inner_header,
		inner_header_len, geneve, geneve_header_len,
		&sfm->per_interface[sw_if_index0].filters[i]);
	      if (cap_index != ~0)
		{
		  destination_capture_index = cap_index;
		  break;
		}
	    }
	}

      if (destination_capture_index != ~0)
	{
	  matched++;
	  captured++;
	}

    packet_classified:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (bufs[pkt_idx]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  filtering_elapsed[pkt_idx] = clib_cpu_time_now () - packet_start;
	}

      dest_indices[pkt_idx] = destination_capture_index;
    }

  /* Update statistics */
  if (n_matched)
    *n_matched = matched;
  if (n_captured)
    *n_captured = captured;
}

/* Register multiarch function */
CLIB_MARCH_FN_REGISTRATION (gpcapng_simple_filter_classify);

#ifndef CLIB_MARCH_VARIANT

/* Filter implementation instance */
gpcapng_filter_impl_t simple_filter = {
  .name = "simple",
  .description = "Simple GENEVE filter with 5-tuple and option matching",
  .api_version = GPCAPNG_FILTER_API_VERSION,
  .priority = 100, /* Default priority */
};

/*
 * Simple filter main state
 */
simple_filter_main_t simple_filter_main;

/*
 * GPCAPNG plugin method vtable
 */
static gpcapng_plugin_methods_t gpcapng_plugin;

/* Register the simple filter implementation */
static clib_error_t *
simple_filter_init (vlib_main_t *vm)
{
  clib_error_t *gpcapng_init_res =
    gpcapng_plugin_exports_init (&gpcapng_plugin);
  if (gpcapng_init_res)
    return (gpcapng_init_res);

  /* Set the function pointer to the multiarch-selected variant */
  simple_filter.selected_fn =
    CLIB_MARCH_FN_POINTER (gpcapng_simple_filter_classify);

  int rv = gpcapng_plugin.register_filter_impl (&simple_filter);
  if (rv != 0)
    {
      return clib_error_return (
	0, "Failed to register simple filter implementation (error %d)", rv);
    }

  clib_warning ("GPCAPNG Simple Filter plugin initialized");
  return 0;
}

VLIB_INIT_FUNCTION (simple_filter_init) = {
  .runs_after = VLIB_INITS ("gpcapng_filter_api_init"),
};

#endif
