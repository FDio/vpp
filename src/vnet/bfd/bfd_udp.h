/* * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief BFD UDP transport layer declarations
 */

#ifndef __included_bfd_udp_h__
#define __included_bfd_udp_h__

#include <vppinfra/clib.h>
#include <vnet/adj/adj_types.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/bfd/bfd_api.h>

/* *INDENT-OFF* */
/** identifier of BFD session based on UDP transport only */
typedef CLIB_PACKED (struct {
  union {
    /** interface to which the session is tied - single-hop */
    u32 sw_if_index;
    /** the FIB index the peer is in - multi-hop*/
    u32 fib_index;
  };
  /** local address */
  ip46_address_t local_addr;
  /** peer address */
  ip46_address_t peer_addr;
}) bfd_udp_key_t;
/* *INDENT-ON* */

/** UDP transport specific data embedded in bfd_session's union */
typedef struct
{
  /** key identifying this session */
  bfd_udp_key_t key;
  /** adjacency index returned from adj lock call */
  adj_index_t adj_index;
} bfd_udp_session_t;

/** bfd udp echo packet trace capture */
typedef struct
{
  u32 len;
  u8 data[400];
} bfd_udp_echo_input_trace_t;

struct bfd_session_s;

/**
 * @brief add the necessary transport layer by prepending it to existing data
 *
 *
 * @param is_echo 1 if this is echo packet, 0 if control frame
 *
 * @return 1 on success, 0 on failure
 */
int bfd_add_udp4_transport (vlib_main_t * vm, u32 bi,
			    const struct bfd_session_s *bs, int is_echo);

/**
 * @brief add the necessary transport layer by prepending it to existing data
 *
 * @param is_echo 1 if this is echo packet, 0 if control frame
 *
 * @return 1 on success, 0 on failure
 */
int bfd_add_udp6_transport (vlib_main_t * vm, u32 bi,
			    const struct bfd_session_s *bs, int is_echo);

/**
 * @brief transport packet over udpv4
 *
 * @param is_echo 1 if this is echo packet, 0 if control frame
 *
 * @return 1 on success, 0 on failure
 */
int bfd_transport_udp4 (vlib_main_t * vm, u32 bi,
			const struct bfd_session_s *bs);

/**
 * @brief transport packet over udpv6
 *
 * @param is_echo 1 if this is echo packet, 0 if control frame
 *
 * @return 1 on success, 0 on failure
 */
int bfd_transport_udp6 (vlib_main_t * vm, u32 bi,
			const struct bfd_session_s *bs);

/**
 * @brief check if the bfd udp layer is echo-capable at this time
 *
 * @return 1 if available, 0 otherwise
 */
int bfd_udp_is_echo_available (bfd_transport_e transport);

/**
 * @brief get echo source information - used by CLI
 */
void bfd_udp_get_echo_source (int *is_set, u32 * sw_if_index,
			      int *have_usable_ip4, ip4_address_t * ip4,
			      int *have_usable_ip6, ip6_address_t * ip6);

#endif /* __included_bfd_udp_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
