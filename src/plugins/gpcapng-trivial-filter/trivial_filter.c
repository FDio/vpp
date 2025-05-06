/*
 * trivial_filter.c - Trivial filter implementation for gpcapng
 *
 * This plugin provides a simple filter implementation that can either
 * capture all packets to a specified destination or capture no packets.
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

#include <gpcapng/gpcapng.h>
#include <gpcapng/public_inlines.h>
#include "trivial_filter.h"

/* Trivial filter classification function (multiarch) */
void
CLIB_MULTIARCH_FN (gpcapng_trivial_filter_classify)
(u32 api_version, vlib_buffer_t **bufs, u32 n_buffers, vlib_main_t *vm,
 vlib_node_runtime_t *node, vlib_frame_t *frame, int is_output,
 uword *capture_enabled_bitmap, u32 *dest_indices, u32 *n_matched,
 u32 *n_captured, u64 *filtering_elapsed)
{
  trivial_filter_main_t *tfm = get_trivial_filter_main ();
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

  /* Process each packet based on trivial filter mode */
  for (pkt_idx = 0; pkt_idx < n_buffers; pkt_idx++)
    {
      u32 destination_capture_index = ~0;
      u64 packet_start = clib_cpu_time_now ();

      if (tfm->mode == TRIVIAL_FILTER_CAPTURE_ALL)
	{
	  /* Capture all packets to the configured destination */
	  destination_capture_index = tfm->destination_index;
	  matched++;
	  captured++;
	}
      /* else: mode == TRIVIAL_FILTER_CAPTURE_NONE, leave dest_index as ~0 */
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
CLIB_MARCH_FN_REGISTRATION (gpcapng_trivial_filter_classify);

#ifndef CLIB_MARCH_VARIANT

/*
 * Trivial filter main state
 */
trivial_filter_main_t trivial_filter_main;

/*
 * GPCAPNG plugin method vtable
 */
static gpcapng_plugin_methods_t gpcapng_plugin;

/* Filter implementation instance */
gpcapng_filter_impl_t trivial_filter = {
  .name = "trivial",
  .description = "Trivial filter - capture all or capture none",
  .api_version = GPCAPNG_FILTER_API_VERSION,
  .priority = 50, /* Lower priority than simple filter */
};

/* Register the trivial filter implementation */
static clib_error_t *
trivial_filter_init (vlib_main_t *vm)
{
  trivial_filter_main_t *tfm = get_trivial_filter_main ();

  clib_error_t *gpcapng_init_res =
    gpcapng_plugin_exports_init (&gpcapng_plugin);
  if (gpcapng_init_res)
    return (gpcapng_init_res);

  /* Initialize trivial filter state */
  tfm->mode = TRIVIAL_FILTER_CAPTURE_NONE;
  tfm->destination_index = ~0;

  /* Set the function pointer to the multiarch-selected variant */
  trivial_filter.selected_fn =
    CLIB_MARCH_FN_POINTER (gpcapng_trivial_filter_classify);

  int rv = gpcapng_plugin.register_filter_impl (&trivial_filter);
  if (rv != 0)
    {
      return clib_error_return (
	0, "Failed to register trivial filter implementation (error %d)", rv);
    }

  clib_warning ("GPCAPNG Trivial Filter plugin initialized");
  return 0;
}

VLIB_INIT_FUNCTION (trivial_filter_init) = {
  .runs_after = VLIB_INITS ("gpcapng_filter_api_init"),
};

#endif
