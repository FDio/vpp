// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include "pcap.h"

/* CLI command to start PCAP capture */
static clib_error_t *
sasc_pcap_start_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    sasc_pcap_main_t *pcm = &sasc_pcap_main;
    u8 *filename = 0;
    u32 max_packets = 1000; /* Default limit */
    bool filename_specified = false;

    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(line_input, "filename %s", &filename)) {
            filename_specified = true;
        } else if (unformat(line_input, "max-packets %d", &max_packets)) {
            ;
        } else {
            err = unformat_parse_error(line_input);
            goto done;
        }
    }

    /* Check if already enabled */
    if (pcm->enabled) {
        err = clib_error_return(0, "PCAP capture is already running. Stop it first.");
        goto done;
    }

    /* Set default filename if not specified */
    if (!filename_specified) {
        filename = format(0, "/tmp/sasc_pcap_%d.pcap", (int)vlib_time_now(vm));
    }

    /* Initialize PCAP main structure */
    clib_memset(&pcm->pcap_main, 0, sizeof(pcm->pcap_main));
    pcm->pcap_main.file_name = (char *)filename;
    pcm->pcap_main.n_packets_to_capture = max_packets;
    pcm->pcap_main.packet_type = PCAP_PACKET_TYPE_ethernet; /* Default to IP packets */
    pcm->pcap_main.n_packets_captured = 0;
    pcm->pcap_main.flags = 0;

    /* Enable the service */
    pcm->enabled = true;
    pcm->filename = (char *)filename;
    pcm->max_packets = max_packets;
    pcm->packets_captured = 0;

    /* Reset statistics */
    pcm->packets_processed = 0;
    pcm->packets_captured_total = 0;
    pcm->bytes_captured_total = 0;

    vlib_cli_output(vm, "PCAP capture started:\n");
    vlib_cli_output(vm, "  Filename: %s\n", pcm->filename);
    vlib_cli_output(vm, "  Max packets: %u\n", pcm->max_packets);
    vlib_cli_output(vm, "  Packet type: IP\n");

done:
    unformat_free(line_input);
    if (err && filename_specified) {
        vec_free(filename);
    }
    return err;
}

VLIB_CLI_COMMAND(sasc_pcap_start_command, static) = {
    .path = "sasc pcap start",
    .short_help = "sasc pcap start [filename <filename>] [max-packets <count>] - Start PCAP capture",
    .function = sasc_pcap_start_command_fn,
};

/* CLI command to stop PCAP capture */
static clib_error_t *
sasc_pcap_stop_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    sasc_pcap_main_t *pcm = &sasc_pcap_main;

    if (!pcm->enabled) {
        return clib_error_return(0, "PCAP capture is not running");
    }

    /* Write any remaining packets to file */
    if (pcm->pcap_main.n_packets_captured > 0) {
        clib_error_t *write_error = pcap_write(&pcm->pcap_main);
        if (write_error) {
            clib_warning("Error writing PCAP file: %U", format_clib_error, write_error);
            clib_error_free(write_error);
        }
    }

    /* Close the PCAP file */
    clib_error_t *close_error = pcap_close(&pcm->pcap_main);
    if (close_error) {
        clib_warning("Error closing PCAP file: %U", format_clib_error, close_error);
        clib_error_free(close_error);
    }

    /* Disable the service */
    pcm->enabled = false;

    vlib_cli_output(vm, "PCAP capture stopped:\n");
    vlib_cli_output(vm, "  Total packets captured: %u\n", pcm->packets_captured_total);
    vlib_cli_output(vm, "  Total bytes captured: %u\n", pcm->bytes_captured_total);
    vlib_cli_output(vm, "  File: %s\n", pcm->filename);

    return 0;
}

VLIB_CLI_COMMAND(sasc_pcap_stop_command, static) = {
    .path = "sasc pcap stop",
    .short_help = "sasc pcap stop - Stop PCAP capture and write file",
    .function = sasc_pcap_stop_command_fn,
};

/* CLI command to show PCAP status */
static clib_error_t *
sasc_pcap_show_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    sasc_pcap_main_t *pcm = &sasc_pcap_main;

    vlib_cli_output(vm, "SASC PCAP Service Status:\n");
    vlib_cli_output(vm, "  Enabled: %s\n", pcm->enabled ? "yes" : "no");

    if (pcm->enabled) {
        vlib_cli_output(vm, "  Filename: %s\n", pcm->filename ? pcm->filename : "not set");
        vlib_cli_output(vm, "  Max packets: %u\n", pcm->max_packets);
        vlib_cli_output(vm, "  Packets captured: %u / %u\n", pcm->pcap_main.n_packets_captured, pcm->max_packets);
        vlib_cli_output(vm, "  Current session packets: %u\n", pcm->packets_captured);
    }

    vlib_cli_output(vm, "  Total packets processed: %u\n", pcm->packets_processed);
    vlib_cli_output(vm, "  Total packets captured: %u\n", pcm->packets_captured_total);
    vlib_cli_output(vm, "  Total bytes captured: %u\n", pcm->bytes_captured_total);

    return 0;
}

VLIB_CLI_COMMAND(sasc_pcap_show_command, static) = {
    .path = "show sasc pcap",
    .short_help = "show sasc pcap - Show PCAP service status",
    .function = sasc_pcap_show_command_fn,
};