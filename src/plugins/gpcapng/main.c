/*
 * gpcapng.c - Generic packet capture plugin for VPP
 *
 * Captures Generic tunneled packets (IPv4/IPv6) to PCAPng files
 * with support for filtering based on tunnel options and 5-tuple.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h> /* for ethernet_header_t */
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>
#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/format_fns.h>
#include <vppinfra/atomics.h>
#include <vlib/unix/unix.h>
#include <vppinfra/random.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "gpcapng.h"

/* Global plugin state */
static gpcapng_main_t gpcapng_main;

gpcapng_main_t *
get_gpcapng_main ()
{
  return &gpcapng_main;
}

/******************************************************************************
 * API and initialization
 ******************************************************************************/

/* Legacy function - use gpcapng_set_interface_capture instead */
int
gpcapng_enable_capture (u32 sw_if_index, u8 enable)
{
  return gpcapng_set_interface_capture (sw_if_index, enable);
}

static clib_error_t *
gpcapng_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  u32 sw_if_index = ~0;
  u8 enable = 1;

  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  /* Validate inputs */
  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface required");
      goto done;
    }

  /* Enable/disable capture */
  int rv = gpcapng_enable_capture (sw_if_index, enable);
  if (rv)
    {
      error =
	clib_error_return (0, "failed to %s capture on interface %d: error %d",
			   enable ? "enable" : "disable", sw_if_index, rv);
      goto done;
    }

  vlib_cli_output (vm, "Generic packet capture %s on interface %d",
		   enable ? "enabled" : "disabled", sw_if_index);

done:
  unformat_free (line_input);
  return error;
}

/* CLI command to enable or disable capture */
VLIB_CLI_COMMAND (gpcapng_enable_command, static) = {
  .path = "gpcapng capture",
  .short_help = "gpcapng capture interface <interface> [disable]",
  .function = gpcapng_enable_command_fn,
};

extern void gpcapng_filter_init ();

static clib_error_t *
gpcapng_init (vlib_main_t *vm)
{
  gpcapng_main_t *gpm = &gpcapng_main;

  /* Allocate per-worker output contexts */
  vec_validate_init_empty (gpm->worker_output_ctx, vlib_num_workers (), 0);

  /* Allocate per-worker readiness bitmaps */
  vec_validate_init_empty (gpm->worker_output_ctx_is_ready,
			   vlib_num_workers (), 0);
  // Initialize each worker's bitmap to zero
  for (int i = 0; i <= vlib_num_workers (); i++)
    gpm->worker_output_ctx_is_ready[i] = 0;

  /* Allocate per-worker retry queues */
  vec_validate_init_empty (gpm->worker_retry_queue, vlib_num_workers (), 0);
  for (int i = 0; i <= vlib_num_workers (); i++)
    gpm->worker_retry_queue[i] = 0;

  /* Initialize per-worker structures for two-pass processing */
  vec_validate_init_empty (gpm->per_worker, vlib_num_workers (),
			   (gpcapng_per_worker_t){ 0 });
  for (int i = 0; i <= vlib_num_workers (); i++)
    {
      gpcapng_per_worker_t *pw = &gpm->per_worker[i];
      /* Pre-allocate vectors for typical frame sizes to avoid allocation in
       * data path */
      /* Add one extra item space for a "wrap-around" data: not part of vector,
	 but avoids the bounds check, same as [0] */
      vec_validate (pw->buffer_indices, VLIB_FRAME_SIZE - 1 + 1);
      vec_validate (pw->dest_indices, VLIB_FRAME_SIZE - 1 + 1);
      vec_validate (pw->bufs, VLIB_FRAME_SIZE - 1 + 1);
      vec_validate (pw->filtering_elapsed, VLIB_FRAME_SIZE - 1 + 1);

      /* Reset length to 0, but keep the allocated space */
      vec_reset_length (pw->buffer_indices);
      vec_reset_length (pw->dest_indices);
      vec_reset_length (pw->bufs);
      vec_reset_length (pw->filtering_elapsed);
      pw->n_vectors = 0;
    }

#ifdef XXXXX
  /* Register for the Generic input feature arc */
  gpm->ip4_geneve_input_arc = vlib_node_add_named_next (
    vm, vlib_get_node_by_name (vm, (u8 *) "ip4-geneve-input")->index,
    "gen-pcapng-capture");

  gpm->ip6_geneve_input_arc = vlib_node_add_named_next (
    vm, vlib_get_node_by_name (vm, (u8 *) "ip6-geneve-input")->index,
    "gen-pcapng-capture");

#endif

  return 0;
}

/* API functions for external access */
uword *
gpcapng_get_capture_enabled_bitmap (void)
{
  gpcapng_main_t *gpm = get_gpcapng_main ();
  return gpm->capture_enabled_bitmap;
}

int
gpcapng_set_interface_capture (u32 sw_if_index, u8 enable)
{
  gpcapng_main_t *gpm = get_gpcapng_main ();
  vnet_main_t *vnm = vnet_get_main ();

  /* Validate interface index */
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Update the enabled state in bitmap */
  if (enable)
    gpm->capture_enabled_bitmap =
      clib_bitmap_set (gpm->capture_enabled_bitmap, sw_if_index, 1);
  else
    gpm->capture_enabled_bitmap =
      clib_bitmap_set (gpm->capture_enabled_bitmap, sw_if_index, 0);

  /* Enable/disable the feature on this interface */
  if (enable)
    {
      vnet_feature_enable_disable (
	"interface-output", "gen-pcapng-capture-out", sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("device-input", "gen-pcapng-capture-in",
				   sw_if_index, 1, 0, 0);
    }
  else
    {
      vnet_feature_enable_disable (
	"interface-output", "gen-pcapng-capture-out", sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("device-input", "gen-pcapng-capture-in",
				   sw_if_index, 0, 0, 0);
    }

  return 0;
}

/* Register the initialization function */
VLIB_INIT_FUNCTION (gpcapng_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Generic Tunnel Packet Capture plugin",
};
