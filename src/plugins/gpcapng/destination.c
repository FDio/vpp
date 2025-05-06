/*
 * gpcapng_cli.c - VPP plugin for GPCAPNG CLI commands
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include "gpcapng.h"
#include "destination.h"

extern void set_write_pcapng(gpcapng_dest_t *output); // FIXME: to be refactored out to use inlines

/* Helper function to get destination type string */
static const char *
pcapng_destination_type_to_string(pcapng_destination_type_t type)
{
    switch (type)
    {
    case PCAPNG_DEST_FILE:
        return "file";
    case PCAPNG_DEST_GZIP:
        return "gzip";
    case PCAPNG_DEST_IGZIP:
        return "igzip";
    case PCAPNG_DEST_HTTP:
        return "http";
    default:
        return "unknown";
    }
}

void *wdi_to_worker_context(worker_dest_index_t wdi) {
   gpcapng_main_t *gpm = get_gpcapng_main ();
   u16 worker_index = wdi_to_worker_index(wdi);
   u16 destination_index = wdi_to_destination_index(wdi);
// s->thread_index == worker_index ?
  void **per_worker_ctx = gpm->worker_output_ctx[worker_index];
  void *ctx = per_worker_ctx[destination_index];
  return ctx;
}

void *init_worker_context(gpcapng_dest_t *output, u16 worker_index, u16 destination_index)
{
    /* Initialize the output context if not already done */
    void *output_ctx = output->init(output, worker_index, destination_index);
    if (!output_ctx)
    {
        /* Failed to initialize output */
        return 0;
    }
    
    /* Write PCAPng header */
    output->write_pcapng_shb(output, output_ctx);
    
    vnet_main_t *vnm = vnet_get_main();
    vnet_interface_main_t *im = &vnm->interface_main;
    
    /* Iterate through all software interfaces */
    vnet_sw_interface_t *si;
    u32 sw_if_index;
    
    /* Pool foreach to iterate through all interfaces */
    pool_foreach(si, im->sw_interfaces)
    {
        sw_if_index = si - im->sw_interfaces;
        
        /* Get the interface name */
        u8 *interface_name = format(0, "%U", format_vnet_sw_interface_name, vnm, si);
        
        /* Create RX (receive) interface name */
        u8 *rx_name = format(0, "%v(%d)-rx%c", interface_name, sw_if_index, 0);
        output->write_pcapng_idb(output, output_ctx, sw_if_index * 2, (char *)rx_name);
        vec_free(rx_name);
        
        /* Create TX (transmit) interface name */
        u8 *tx_name = format(0, "%v(%d)-tx%c", interface_name, sw_if_index, 0);
        output->write_pcapng_idb(output, output_ctx, sw_if_index * 2 + 1, (char *)tx_name);
        vec_free(tx_name);
        
        /* Free the base interface name */
        vec_free(interface_name);
    }
    
    return output_ctx;
}

/* Find destination by name */
u32
find_destination_by_name(const char *name)
{
    gpcapng_main_t *gpm = get_gpcapng_main();
    gpcapng_dest_t *dest;
    u32 dest_index;
    
    pool_foreach_index(dest_index, gpm->outputs)
    {
        dest = pool_elt_at_index(gpm->outputs, dest_index);
        if (dest->name && strcmp(dest->name, name) == 0)
        {
            return dest_index;
        }
    }
    
    return ~0; /* Not found */
}

static u32
pcap_add_capture_destination(char *name, pcapng_destination_type_t cap_type, u8 *path_or_url)
{
    u32 rv = ~0;
    if (cap_type >= PCAPNG_DEST_MAX) {
       return rv;
    }
    
    gpcapng_main_t *gpm = get_gpcapng_main();
    
    /* Check if destination with this name already exists */
    if (find_destination_by_name(name) != ~0)
    {
        clib_warning("Destination with name '%s' already exists", name);
        return rv;
    }
    
    gpcapng_dest_t *new_destination;
    
    /* Use pool_get instead of vec_add2 */
    pool_get(gpm->outputs, new_destination);
    rv = new_destination - gpm->outputs;
    
    /* Clear the structure */
    clib_memset(new_destination, 0, sizeof(*new_destination));

    set_write_pcapng(new_destination);
    new_destination->name = name;
    new_destination->arg = path_or_url;

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
        pool_put(gpm->outputs, new_destination);
        return ~0;
    }

    /* This logic needs refactoring, to work under each worker separately.
      FIXME: discuss the HTTP session establishment process with Florin
      */
    u16 worker_index;
    for(worker_index = 0; worker_index <= vlib_num_workers(); worker_index++) {
      /* ensure we have a space for storing the worker context */
      vec_validate(gpm->worker_output_ctx[worker_index], rv);
      void *output_ctx = init_worker_context(new_destination, worker_index, (u16)rv);
      if (output_ctx) {
        /* Store the context */
        gpm->worker_output_ctx[worker_index][rv] = output_ctx;
      }
    }
  return rv;
}

static u32
pcap_del_capture_destination(const char *name)
{
    gpcapng_main_t *gpm = get_gpcapng_main();
    u32 dest_index = find_destination_by_name(name);
    
    if (dest_index == ~0)
    {
        return ~0; /* Not found */
    }
    
    gpcapng_dest_t *dest = pool_elt_at_index(gpm->outputs, dest_index);
    
    /* Cleanup worker contexts */
    u16 worker_index;
    for(worker_index = 0; worker_index <= vlib_num_workers(); worker_index++) {
        if (vec_len(gpm->worker_output_ctx[worker_index]) > dest_index &&
            gpm->worker_output_ctx[worker_index][dest_index]) {
            /* Call cleanup if available */
            if (dest->cleanup) {
                dest->cleanup(gpm->worker_output_ctx[worker_index][dest_index]);
            }
            gpm->worker_output_ctx[worker_index][dest_index] = 0;
        }
    }
    
    /* Free allocated strings */
    if (dest->name) {
        vec_free(dest->name);
    }
    if (dest->arg) {
        vec_free(dest->arg);
    }
    
    /* Return the destination to the pool */
    pool_put(gpm->outputs, dest);
    
    return 0; /* Success */
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

    if (type == PCAPNG_DEST_MAX || !path_or_url || !name)
    {
        error = clib_error_return(0, "must specify destination name, type and path/url");
        goto done;
    }
    
    rv = pcap_add_capture_destination((char *)name, type, path_or_url);
    if (rv == ~0)
    {
        error = clib_error_return(0, "failed to add destination (name might already exist)");
        goto done;
    }
    
    vlib_cli_output(vm, "Added destination: %s : %s (index: %d)", name, path_or_url, rv);

done:
    if (error) {
        vec_free(name);
        vec_free(path_or_url);
    }
    unformat_free(line_input);
    return error;
}

/* CLI command: show gpcapng destination */
static clib_error_t *
show_gpcapng_destination_command_fn(vlib_main_t * vm,
                                        unformat_input_t * input,
                                        vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u8 *name = 0;
    clib_error_t *error = 0;

    gpcapng_main_t *gpm = get_gpcapng_main();
    u32 total = pool_elts(gpm->outputs);

    /* Get a line of input. */
    if (unformat_user(input, unformat_line_input, line_input))
    {
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
        unformat_free(line_input);
    }

    if (name)
    {
        /* Show specific destination */
        u32 dest_index = find_destination_by_name((char *)name);
        if (dest_index == ~0)
        {
            vlib_cli_output(vm, "Destination '%s' not found", name);
            goto done;
        }
        
        gpcapng_dest_t *dest = pool_elt_at_index(gpm->outputs, dest_index);
        vlib_cli_output(vm, "Destination Details:");
        vlib_cli_output(vm, "  Index: %u", dest_index);
        vlib_cli_output(vm, "  Name: %s", dest->name ? dest->name : "N/A");
        vlib_cli_output(vm, "  Type: %s", pcapng_destination_type_to_string(
            dest->name && strstr(dest->name, "gzip") ? 
            (strstr(dest->name, "igzip") ? PCAPNG_DEST_IGZIP : PCAPNG_DEST_GZIP) :
            (dest->arg && strstr((char*)dest->arg, "http") ? PCAPNG_DEST_HTTP : PCAPNG_DEST_FILE)));
        vlib_cli_output(vm, "  Path/URL: %s", dest->arg ? (char *)dest->arg : "N/A");
    }
    else
    {
        /* Show all destinations */
        vlib_cli_output(vm, "GPCAPNG Destinations (total: %d):", total);
        
        if (total == 0)
        {
            vlib_cli_output(vm, "  No destinations configured");
        }
        else
        {
            vlib_cli_output(vm, "%-6s %-20s %-10s %s", "Index", "Name", "Type", "Path/URL");
            vlib_cli_output(vm, "%-6s %-20s %-10s %s", "-----", "----", "----", "--------");
            
            gpcapng_dest_t *dest;
            u32 dest_index;
            
            pool_foreach_index(dest_index, gpm->outputs)
            {
                dest = pool_elt_at_index(gpm->outputs, dest_index);
                
                /* Determine type based on context - this is a simplification */
                pcapng_destination_type_t type = PCAPNG_DEST_FILE;
                if (dest->arg)
                {
                    char *arg_str = (char *)dest->arg;
                    if (strstr(arg_str, "http://") || strstr(arg_str, "https://"))
                        type = PCAPNG_DEST_HTTP;
                    else if (dest->name && strstr(dest->name, "igzip"))
                        type = PCAPNG_DEST_IGZIP;
                    else if (dest->name && strstr(dest->name, "gzip"))
                        type = PCAPNG_DEST_GZIP;
                }
                
                vlib_cli_output(vm, "%-6u %-20s %-10s %s",
                              dest_index,
                              dest->name ? dest->name : "N/A",
                              pcapng_destination_type_to_string(type),
                              dest->arg ? (char *)dest->arg : "N/A");
            }
        }
    }

done:
    vec_free(name);
    return error;
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

    u32 rv = pcap_del_capture_destination((char *)name);
    if (rv == ~0)
    {
        error = clib_error_return(0, "destination '%s' not found", name);
        goto done;
    }
    
    vlib_cli_output(vm, "Deleted GPCAPNG destination: %s", name);

done:
    vec_free(name);
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
