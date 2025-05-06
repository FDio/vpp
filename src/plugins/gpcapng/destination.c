/*
 * gpcapng_cli.c - VPP plugin for GENEVE PCAPNG CLI commands
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include "gpcapng.h"
#include "destination.h"

/* Enum for destination types */
typedef enum {
    PCAPNG_DEST_FILE = 0,
    PCAPNG_DEST_GZIP,
    PCAPNG_DEST_IGZIP,
    PCAPNG_DEST_HTTP,
    PCAPNG_DEST_MAX
} pcapng_destination_type_t;

extern void set_write_pcapng(gpcapng_dest_t *output); // FIXME: to be refactored out to use inlines


void *init_worker_context(gpcapng_dest_t *output, u32 worker_index)
 {
      /* Initialize the output context if not already done */
      void *output_ctx = output->init (worker_index);
      if (!output_ctx)
        {
          /* Failed to initialize output */
          return 0;
        }
      /* Write PCAPng header */
      output->write_pcapng_shb (output, output_ctx);
      static u8 *if_name = 0;
      int i;
      // FIXME: retrieve the real interfaces
      for (i=0; i<5*2; i++) {
        vec_reset_length (if_name);
        if_name = format (if_name, "vpp-if-%d-%s%c", i/2, i % 2 ? "out" : "in", 0);
        output->write_pcapng_idb (output, output_ctx, i, (char *)if_name);
      }
      return output_ctx;
    }


static u32
pcap_add_capture_destination(char *name, pcapng_destination_type_t cap_type, u8 *path_or_url)
{
    u32 rv = ~0;
    if (cap_type >= PCAPNG_DEST_MAX) {
       return rv;
    }
    gpcapng_main_t *gpm = get_gpcapng_main();
    gpcapng_dest_t *new_destination;
    vec_add2 (gpm->outputs, new_destination, 1);
    rv = new_destination - gpm->outputs;

    set_write_pcapng(new_destination);

    switch (cap_type)
    {
    case PCAPNG_DEST_FILE:
        set_pcapng_output_file(new_destination);
        break;
    case PCAPNG_DEST_GZIP:
        set_pcapng_output_gzip(new_destination);
        break;
    case PCAPNG_DEST_IGZIP:
        set_pcapng_output_igzip(new_destination);
        break;
    case PCAPNG_DEST_HTTP:
        gpcapng_ensure_session_manager();
        set_pcapng_output_http(new_destination);
        break;
    default:
        clib_error("internal error");
	break;
    }

    /* This logic needs refactoring, to work under each worker separately.
      FIXME: discuss the HTTP session establishment process with Florin
      */
    u32 worker_index;
    for(worker_index = 0; worker_index <= vlib_num_workers(); worker_index++) {
      /* ensure we have a space for storing the worker context */
      vec_validate(gpm->worker_output_ctx[worker_index], rv);
      void *output_ctx = init_worker_context(new_destination, worker_index);
      if (output_ctx) {
        /* Store the context */
        gpm->worker_output_ctx[worker_index][rv] = output_ctx;
      }
    }
  return rv;
}

/* CLI command: geneve pcapng destination add */
static clib_error_t *
gpcapng_destination_add_command_fn(vlib_main_t * vm,
                                       unformat_input_t * input,
                                       vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    u8 *name = 0;
    u8 *path_or_url = 0;
    pcapng_destination_type_t type = PCAPNG_DEST_MAX; /* Invalid default */
    int rv = 0;

    /* Get a line of input. */
    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "file %s", &path_or_url))
            type = PCAPNG_DEST_FILE;
        else if (unformat(line_input, "gzip %s", &path_or_url))
            type = PCAPNG_DEST_GZIP;
        else if (unformat(line_input, "igzip %s", &path_or_url))
            type = PCAPNG_DEST_IGZIP;
        else if (unformat(line_input, "http %s", &path_or_url)) {
            type = PCAPNG_DEST_HTTP;
	}
        else if (unformat(line_input, "name %s", &name)) {
	   /* nothing to do */
	}
        else
        {
            error = clib_error_return(0, "unknown input '%U'",
                                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (type == PCAPNG_DEST_MAX || !path_or_url)
    {
        error = clib_error_return(0, "must specify destination type and path/url");
        goto done;
    }
    rv = pcap_add_capture_destination((char *)name, type, path_or_url);
    vlib_cli_output(vm, "Added destination: %s (result: %d)", path_or_url, rv);

done:
    vec_free(path_or_url);
    unformat_free(line_input);
    return error;
}

/* CLI command: show geneve pcapng destination */
static clib_error_t *
show_gpcapng_destination_command_fn(vlib_main_t * vm,
                                        unformat_input_t * input,
                                        vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u8 *name = 0;

    gpcapng_main_t *gpm = get_gpcapng_main();
    u32 total = vec_len(gpm->outputs);
    vlib_cli_output(vm, "GENEVE PCAPNG total destinations: %d", total);

    /* Get a line of input. */
    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "name %s", &name))
            ;
        else
        {
            unformat_free(line_input);
            return clib_error_return(0, "unknown input '%U'",
                                   format_unformat_error, line_input);
        }
    }

    unformat_free(line_input);


    vlib_cli_output(vm, "GENEVE PCAPNG destination ID: %s", name);
    
    return 0;
}

/* CLI command: geneve pcapng destination del */
static clib_error_t *
gpcapng_destination_del_command_fn(vlib_main_t * vm,
                                       unformat_input_t * input,
                                       vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u8 *name = 0;
    clib_error_t *error = 0;

    /* Get a line of input. */
    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "name %s", &name))
            ;
        else
        {
            error = clib_error_return(0, "unknown input '%U'",
                                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (name == 0)
    {
        error = clib_error_return(0, "must specify destination name");
        goto done;
    }

    vlib_cli_output(vm, "Deleting GENEVE PCAPNG destination name: %s", name);

done:
    unformat_free(line_input);
    return error;
}

/* CLI command registration */
VLIB_CLI_COMMAND(gpcapng_destination_add_command, static) = {
    .path = "gpcapng destination add",
    .short_help = "gpcapng destination add name <name> {file <path> | gzip <path> | igzip <path> | http <url>}",
    .function = gpcapng_destination_add_command_fn,
};

VLIB_CLI_COMMAND(show_gpcapng_destination_command, static) = {
    .path = "show gpcapng destination",
    .short_help = "show gpcapng destination [name <name>]",
    .function = show_gpcapng_destination_command_fn,
};

VLIB_CLI_COMMAND(gpcapng_destination_del_command, static) = {
    .path = "gpcapng destination del",
    .short_help = "gpcapng destination del name <name>",
    .function = gpcapng_destination_del_command_fn,
};

