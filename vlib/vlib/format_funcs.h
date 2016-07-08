/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * format_funcs.h: VLIB formatting/unformating
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vlib_format_h
#define included_vlib_format_h

/* Format vlib_rx_or_tx_t/vlib_read_or_write_t enum as string. */
u8 *format_vlib_rx_tx (u8 * s, va_list * args);
u8 *format_vlib_read_write (u8 * s, va_list * args);

/* Formats buffer data as printable ascii or as hex. */
u8 *format_vlib_buffer_data (u8 * s, va_list * args);

/* Enable/on => 1; disable/off => 0. */
uword unformat_vlib_enable_disable (unformat_input_t * input, va_list * args);

/* rx/tx => VLIB_RX/VLIB_TX. */
uword unformat_vlib_rx_tx (unformat_input_t * input, va_list * args);

/* Parse a-zA-Z0-9_ token and hash to value. */
uword unformat_vlib_number_by_name (unformat_input_t * input, va_list * args);

/* Parse an int either %d or 0x%x. */
uword unformat_vlib_number (unformat_input_t * input, va_list * args);

/* Flag to format_vlib_*_header functions to tell them not to recurse
   into the next layer's header.  For example, tells format_vlib_ethernet_header
   not to format ip header. */
#define FORMAT_VLIB_HEADER_NO_RECURSION (~0)

#endif /* included_vlib_format_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
