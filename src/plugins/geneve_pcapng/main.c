/*
 * geneve_pcapng.c - GENEVE packet capture plugin for VPP
 *
 * Captures GENEVE tunneled packets (IPv4/IPv6) to PCAPng files
 * with support for filtering based on GENEVE options and 5-tuple.
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
#include <zlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <isa-l/igzip_lib.h> // Using only igzip headers

#include "geneve_pcapng.h"

/* Global plugin state */
static geneve_pcapng_main_t geneve_pcapng_main;

geneve_pcapng_main_t *
get_geneve_pcapng_main ()
{
  return &geneve_pcapng_main;
}

/******************************************************************************
 * API and initialization
 ******************************************************************************/

int
geneve_pcapng_enable_capture (u32 sw_if_index, u8 enable)
{
  geneve_pcapng_main_t *gmp = &geneve_pcapng_main;
  vnet_main_t *vnm = vnet_get_main ();

  /* Validate interface index */
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Ensure we have storage for this interface */
  vec_validate (gmp->per_interface, sw_if_index);

  /* Update the enabled state */
  gmp->per_interface[sw_if_index].capture_enabled = enable;

  if (enable)
    {
      /* Enable the feature on this interface */
      vnet_feature_enable_disable ("interface-output", "geneve-pcapng-capture-out",
                                   sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("device-input", "geneve-pcapng-capture-in",
                                   sw_if_index, 1, 0, 0);
    }
  else
    {
      /* Disable the feature on this interface */
      vnet_feature_enable_disable ("interface-output", "geneve-pcapng-capture-out",
                                   sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("device-input", "geneve-pcapng-capture-in",
                                   sw_if_index, 0, 0, 0);
    }

  return 0;
}


static clib_error_t *
geneve_pcapng_enable_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
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
      if (unformat (line_input, "interface %U",
                   unformat_vnet_sw_interface, vnm, &sw_if_index))
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
  int rv = geneve_pcapng_enable_capture (sw_if_index, enable);
  if (rv)
    {
      error = clib_error_return (0, "failed to %s capture on interface %d: error %d",
                                enable ? "enable" : "disable", sw_if_index, rv);
      goto done;
    }
    
  vlib_cli_output (vm, "GENEVE packet capture %s on interface %d",
                  enable ? "enabled" : "disabled", sw_if_index);
  
done:
  unformat_free (line_input);
  return error;
}

/* CLI command to enable or disable capture */
VLIB_CLI_COMMAND (geneve_pcapng_enable_command, static) = {
  .path = "geneve pcapng capture",
  .short_help = "geneve pcapng capture interface <interface> [disable]",
  .function = geneve_pcapng_enable_command_fn,
};

/*
 * File output initialization for GENEVE PCAPng plugin
 *
 * This code needs to be added to ensure proper connection between
 * the plugin and file output functions.
 */

extern void set_pcapng_output_http(geneve_output_t *output);
extern void set_write_pcapng(geneve_output_t *output);

static void
geneve_pcapng_output_init (geneve_pcapng_main_t *gpm)
{
  // FIXME HERE
  // set_pcapng_output_http(&gpm->output);
  // set_write_pcapng(&gpm->output);
}

/* Add CLI command to select output type (e.g. file, TLS) */
static clib_error_t *
geneve_pcapng_output_command_fn (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  u8 use_file_output = 1;  /* Default to file output */

  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "file"))
        use_file_output = 1;
      /* In future, could add: else if (unformat (line_input, "tls")) */
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }

  /* Cleanup existing output contexts if any */
  /*
  if (gpm->worker_output_ctx)
    {
      u32 i;
      for (i = 0; i < vec_len (gpm->worker_output_ctx); i++)
        {
          if (gpm->worker_output_ctx[i])
            {
              if (gpm->output.cleanup)
                gpm->output.cleanup (gpm->worker_output_ctx[i]);
              gpm->worker_output_ctx[i] = NULL;
            }
        }
    }
  */

  /* Set output implementation */
  if (use_file_output)
    {
      geneve_pcapng_output_init (gpm);
      vlib_cli_output (vm, "GENEVE PCAPng capture will use file output");
    }
  /* In future: else if (use_tls_output) { tls_output_init (gpm); } */

done:
  unformat_free (line_input);
  return error;
}

/* Add CLI command definition */
VLIB_CLI_COMMAND (geneve_pcapng_output_command, static) = {
  .path = "geneve pcapng output",
  .short_help = "geneve pcapng output [file]",
  .function = geneve_pcapng_output_command_fn,
};

extern void geneve_pcapng_filter_init();

static clib_error_t *
geneve_pcapng_init (vlib_main_t * vm)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;

  /* Initialize hash tables */
  gpm->option_by_name = hash_create_string (0, sizeof (uword));
  gpm->option_by_class_type = hash_create (0, sizeof (uword));

  /* Initialize the global filter vector */
  gpm->global_filters = 0; /* Empty vector */

  /* Set up default file output implementation */
  geneve_pcapng_output_init (gpm);

  /* Allocate per-worker output contexts */
  vec_validate (gpm->worker_output_ctx, vlib_num_workers());

#ifdef XXXXX
  /* Register for the GENEVE input feature arc */
  gpm->ip4_geneve_input_arc = vlib_node_add_named_next (
      vm, vlib_get_node_by_name (vm, (u8 *) "ip4-geneve-input")->index,
      "geneve-pcapng-capture");

  gpm->ip6_geneve_input_arc = vlib_node_add_named_next (
      vm, vlib_get_node_by_name (vm, (u8 *) "ip6-geneve-input")->index,
      "geneve-pcapng-capture");

#endif

  geneve_pcapng_filter_init();

  return 0;
}

/* Register the initialization function */
VLIB_INIT_FUNCTION (geneve_pcapng_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Geneve Tunnel Packet Capture plugin",
};
