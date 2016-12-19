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
 * ip/format.h: ip 4 and/or 6 formatting
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

#ifndef included_ip_format_h
#define included_ip_format_h

/* IP4 or IP6. */

format_function_t format_ip_protocol;
unformat_function_t unformat_ip_protocol;

format_function_t format_tcp_udp_port;
unformat_function_t unformat_tcp_udp_port;

typedef enum format_ip_adjacency_flags_t_
{
  FORMAT_IP_ADJACENCY_NONE,
  FORMAT_IP_ADJACENCY_BRIEF = FORMAT_IP_ADJACENCY_NONE,
  FORMAT_IP_ADJACENCY_DETAIL = (1 << 0),
} format_ip_adjacency_flags_t;

format_function_t format_ip_adjacency;
format_function_t format_ip_adjacency_packet_data;

format_function_t format_ip46_address;

typedef enum
{
  IP46_TYPE_ANY,
  IP46_TYPE_IP4,
  IP46_TYPE_IP6
} ip46_type_t;
/* unformat_ip46_address expects arguments (ip46_address_t *, ip46_type_t)
 * The type argument is used to enforce a particular IP version. */
unformat_function_t unformat_ip46_address;

/* IP4 */

/* Parse an IP4 address %d.%d.%d.%d. */
unformat_function_t unformat_ip4_address;

/* Format an IP4 address. */
format_function_t format_ip4_address;
format_function_t format_ip4_address_and_length;

/* Parse an IP4 header. */
unformat_function_t unformat_ip4_header;

/* Format an IP4 header. */
format_function_t format_ip4_header;

/* Parse an IP packet matching pattern. */
unformat_function_t unformat_ip4_match;

unformat_function_t unformat_pg_ip4_header;

/* IP6 */
unformat_function_t unformat_ip6_address;
format_function_t format_ip6_address;
format_function_t format_ip6_address_and_length;
unformat_function_t unformat_ip6_header;
format_function_t format_ip6_header;
unformat_function_t unformat_pg_ip6_header;

/* Format a TCP/UDP headers. */
format_function_t format_tcp_header, format_udp_header;

unformat_function_t unformat_pg_tcp_header, unformat_pg_udp_header;

#endif /* included_ip_format_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
