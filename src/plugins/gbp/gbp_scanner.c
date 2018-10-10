/*
 * gbp.h : Group Based Policy
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <plugins/gbp/gbp_scanner.h>
#include <plugins/gbp/gbp_endpoint.h>
#include <plugins/gbp/gbp_vxlan.h>

vlib_log_class_t gs_logger;

#define GBP_SCANNER_DBG(...)                                      \
    vlib_log_notice (gs_logger, __VA_ARGS__);

static uword
gbp_scanner (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  uword event_type, *event_data = 0;
  bool enabled = 0, do_scan = 0;

  while (1)
    {
      do_scan = 0;

      if (enabled)
	{
	  /* scan every 'inactive threshold' seconds */
	  vlib_process_wait_for_event_or_clock (vm,
						gbp_endpoint_scan_threshold
						());
	}
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      switch (event_type)
	{
	case ~0:
	  /* timer expired */
	  do_scan = 1;
	  break;

	case GBP_ENDPOINT_SCAN_START:
	  enabled = 1;
	  break;

	case GBP_ENDPOINT_SCAN_STOP:
	  enabled = 0;
	  break;

	default:
	  ASSERT (0);
	}

      if (do_scan)
	{
	  GBP_SCANNER_DBG ("start");
	  gbp_endpoint_scan (vm);
	  GBP_SCANNER_DBG ("stop");
	}
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_scanner_node) = {
    .function = gbp_scanner,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "gbp-scanner",
};
/* *INDENT-ON* */


static clib_error_t *
gbp_scanner_init (vlib_main_t * vm)
{
  gs_logger = vlib_log_register_class ("gbp", "scan");

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_scanner_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
