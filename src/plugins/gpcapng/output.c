/*
 * filter_output_cli.c - CLI commands for managing filter output destinations
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include "gpcapng.h"

/* Helper function to find filter by name in global filters */
static geneve_capture_filter_t *
find_global_filter_by_name(const char *name)
{
    gpcapng_main_t *gpm = get_gpcapng_main();
    geneve_capture_filter_t *filter;
    
    if (!name || !gpm->global_filters)
        return NULL;
    
    vec_foreach(filter, gpm->global_filters)
    {
        if (filter->name && strcmp(filter->name, name) == 0)
            return filter;
    }
    
    return NULL;
}

/* Helper function to find filter by name in per-interface filters */
static geneve_capture_filter_t *
find_interface_filter_by_name(const char *name, u32 *found_sw_if_index)
{
    gpcapng_main_t *gpm = get_gpcapng_main();
    geneve_capture_filter_t *filter;
    u32 sw_if_index;
    
    if (!name || !gpm->per_interface)
        return NULL;
    
    /* Search through all interfaces */
    for (sw_if_index = 0; sw_if_index < vec_len(gpm->per_interface); sw_if_index++)
    {
        if (!gpm->per_interface[sw_if_index].filters)
            continue;
            
        vec_foreach(filter, gpm->per_interface[sw_if_index].filters)
        {
            if (filter->name && strcmp(filter->name, name) == 0)
            {
                if (found_sw_if_index)
                    *found_sw_if_index = sw_if_index;
                return filter;
            }
        }
    }
    
    return NULL;
}

/* CLI command: gpcapng output filter <filter_name> destination <dest_name> */
static clib_error_t *
gpcapng_output_filter_destination_command_fn(vlib_main_t * vm,
                                            unformat_input_t * input,
                                            vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    u8 *filter_name = 0;
    u8 *dest_name = 0;
    geneve_capture_filter_t *filter = NULL;
    u32 dest_index;
    u32 sw_if_index = ~0;

    /* Get a line of input */
    if (!unformat_user(input, unformat_line_input, line_input))
        return clib_error_return(0, "missing arguments");

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "filter %s", &filter_name))
	    ;
        else if (unformat(line_input, "destination %s", &dest_name))
	    ;
        else
        {
            error = clib_error_return(0, "unknown input '%U'",
                                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (!filter_name || !dest_name)
    {
        error = clib_error_return(0, "must specify filter name and destination name");
        goto done;
    }

    /* Find the destination by name */
    dest_index = find_destination_by_name((char *)dest_name);
    if (dest_index == ~0)
    {
        error = clib_error_return(0, "destination '%s' not found", dest_name);
        goto done;
    }

    /* Find the filter by name - check global filters first */
    filter = find_global_filter_by_name((char *)filter_name);
    if (!filter)
    {
        /* Check per-interface filters */
        filter = find_interface_filter_by_name((char *)filter_name, &sw_if_index);
    }

    if (!filter)
    {
        error = clib_error_return(0, "filter '%s' not found", filter_name);
        goto done;
    }

    /* Set the destination index */
    filter->destination_index = dest_index;
    
    if (sw_if_index == ~0)
    {
        vlib_cli_output(vm, "Set global filter '%s' output to destination '%s' (index %u)",
                       filter_name, dest_name, dest_index);
    }
    else
    {
        vlib_cli_output(vm, "Set interface %u filter '%s' output to destination '%s' (index %u)",
                       sw_if_index, filter_name, dest_name, dest_index);
    }

done:
    vec_free(filter_name);
    vec_free(dest_name);
    unformat_free(line_input);
    return error;
}

/* CLI command: gpcapng output filter <filter_name> stop */
static clib_error_t *
gpcapng_output_filter_stop_command_fn(vlib_main_t * vm,
                                     unformat_input_t * input,
                                     vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    u8 *filter_name = 0;
    geneve_capture_filter_t *filter = NULL;
    u32 sw_if_index = ~0;

    /* Get a line of input */
    if (!unformat_user(input, unformat_line_input, line_input))
        return clib_error_return(0, "missing filter name");

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "filter %s", &filter_name))
        {
            /* Argument parsed successfully */
            break;
        }
        else
        {
            error = clib_error_return(0, "unknown input '%U'",
                                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (!filter_name)
    {
        error = clib_error_return(0, "must specify filter name");
        goto done;
    }

    /* Find the filter by name - check global filters first */
    filter = find_global_filter_by_name((char *)filter_name);
    if (!filter)
    {
        /* Check per-interface filters */
        filter = find_interface_filter_by_name((char *)filter_name, &sw_if_index);
    }

    if (!filter)
    {
        error = clib_error_return(0, "filter '%s' not found", filter_name);
        goto done;
    }

    /* Set destination index to ~0 to stop output */
    filter->destination_index = ~0;
    
    if (sw_if_index == ~0)
    {
        vlib_cli_output(vm, "Stopped output for global filter '%s'", filter_name);
    }
    else
    {
        vlib_cli_output(vm, "Stopped output for interface %u filter '%s'", 
                       sw_if_index, filter_name);
    }

done:
    vec_free(filter_name);
    unformat_free(line_input);
    return error;
}

/* CLI command registration */
VLIB_CLI_COMMAND(gpcapng_output_filter_destination_command, static) = {
    .path = "gpcapng output set",
    .short_help = "gpcapng output set filter <filter_name> destination <dest_name>",
    .function = gpcapng_output_filter_destination_command_fn,
};

VLIB_CLI_COMMAND(gpcapng_output_filter_stop_command, static) = {
    .path = "gpcapng output stop",
    .short_help = "gpcapng output stop filter <filter_name>",
    .function = gpcapng_output_filter_stop_command_fn,
};
