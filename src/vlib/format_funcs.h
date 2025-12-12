/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* format_funcs.h: VLIB formatting/unformating */

#ifndef included_vlib_format_h
#define included_vlib_format_h

/* Format vlib_rx_or_tx_t/vlib_read_or_write_t enum as string. */
u8 *format_vlib_rx_tx (u8 * s, va_list * args);
u8 *format_vlib_read_write (u8 * s, va_list * args);

/* Formats buffer data as printable ascii or as hex. */
u8 *format_vlib_buffer_data (u8 * s, va_list * args);

/* Formats thread name */
u8 *format_vlib_thread_name (u8 * s, va_list * args);

/* Formats thread name and thread index */
u8 *format_vlib_thread_name_and_index (u8 * s, va_list * args);

/* Enable/on => 1; disable/off => 0. */
uword unformat_vlib_enable_disable (unformat_input_t * input, va_list * args);

/* rx/tx => VLIB_RX/VLIB_TX. */
uword unformat_vlib_rx_tx (unformat_input_t * input, va_list * args);

/* Parse a-zA-Z0-9_ token and hash to value. */
uword unformat_vlib_number_by_name (unformat_input_t * input, va_list * args);

/* Parse an int either %d or 0x%x. */
uword unformat_vlib_number (unformat_input_t * input, va_list * args);

/* Parse a filename to dump debug info */
uword unformat_vlib_tmpfile (unformat_input_t * input, va_list * args);

/* Flag to format_vlib_*_header functions to tell them not to recurse
   into the next layer's header.  For example, tells format_vlib_ethernet_header
   not to format ip header. */
#define FORMAT_VLIB_HEADER_NO_RECURSION (~0)

#endif /* included_vlib_format_h */
