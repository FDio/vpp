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
 * ip/ip4_error.h: ip4 fast path errors
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

#ifndef included_ip_ip4_error_h
#define included_ip_ip4_error_h

#define foreach_ip4_error						\
  /* Must be first. */							\
  _ (NONE, "valid ip4 packets")						\
									\
  /* Errors signalled by ip4-input */					\
  _ (TOO_SHORT, "ip4 length < 20 bytes")				\
  _ (BAD_LENGTH, "ip4 length > l2 length")				\
  _ (BAD_CHECKSUM, "bad ip4 checksum")					\
  _ (VERSION, "ip4 version != 4")					\
  _ (OPTIONS, "ip4 options present")					\
  _ (FRAGMENT_OFFSET_ONE, "ip4 fragment offset == 1")			\
  _ (TIME_EXPIRED, "ip4 ttl <= 1")					\
									\
  /* Errors signalled by ip4-rewrite. */				\
  _ (MTU_EXCEEDED, "ip4 MTU exceeded and DF set")			\
  _ (DST_LOOKUP_MISS, "ip4 destination lookup miss")			\
  _ (SRC_LOOKUP_MISS, "ip4 source lookup miss")				\
  _ (DROP, "ip4 drop")                                                  \
  _ (PUNT, "ip4 punt")                                                  \
									\
  /* Errors signalled by ip4-local. */					\
  _ (UNKNOWN_PROTOCOL, "unknown ip protocol")				\
  _ (TCP_CHECKSUM, "bad tcp checksum")					\
  _ (UDP_CHECKSUM, "bad udp checksum")					\
  _ (UDP_LENGTH, "inconsistent udp/ip lengths")				\
									\
  /* Errors signalled by ip4-source-check. */				\
  _ (UNICAST_SOURCE_CHECK_FAILS, "ip4 unicast source check fails")	\
                                                                        \
  /* Spoofed packets in ip4-rewrite-local */                            \
  _(SPOOFED_LOCAL_PACKETS, "ip4 spoofed local-address packet drops")    \
                                                                        \
  /* Errors singalled by ip4-inacl */                                   \
  _ (INACL_TABLE_MISS, "input ACL table-miss drops")                    \
  _ (INACL_SESSION_DENY, "input ACL session deny drops")

typedef enum
{
#define _(sym,str) IP4_ERROR_##sym,
  foreach_ip4_error
#undef _
    IP4_N_ERROR,
} ip4_error_t;

#endif /* included_ip_ip4_error_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
