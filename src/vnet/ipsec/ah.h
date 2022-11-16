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
#ifndef __AH_H__
#define __AH_H__

#include <vnet/ip/ip.h>
#include <vnet/ipsec/ipsec.h>

typedef struct
{
  unsigned char nexthdr;
  unsigned char hdrlen;
  unsigned short reserved;
  unsigned int spi;
  unsigned int seq_no;
  unsigned char auth_data[0];
} ah_header_t;


/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  ah_header_t ah;
}) ip4_and_ah_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  ah_header_t ah;
}) ip6_and_ah_header_t;
/* *INDENT-ON* */

always_inline void
ah_encrypt_set_next_index (vlib_buffer_t *b, vlib_node_runtime_t *node,
			   u32 thread_index, u32 err, u16 index, u16 *nexts,
			   u16 drop_next, u32 sa_index)
{
  ipsec_set_next_index (b, node, thread_index, IPSEC_SA_NODE_AH_ENCRYPT, err,
			index, nexts, drop_next, sa_index);
}

always_inline void
ah_decrypt_set_next_index (vlib_buffer_t *b, vlib_node_runtime_t *node,
			   u32 thread_index, u32 err, u16 index, u16 *nexts,
			   u16 drop_next, u32 sa_index)
{
  ipsec_set_next_index (b, node, thread_index, IPSEC_SA_NODE_AH_DECRYPT, err,
			index, nexts, drop_next, sa_index);
}

always_inline u8
ah_calc_icv_padding_len (u8 icv_size, int is_ipv6)
{
  ASSERT (0 == is_ipv6 || 1 == is_ipv6);
  const u8 req_multiple = 4 + 4 * is_ipv6;	// 4 for ipv4, 8 for ipv6
  const u8 total_size = sizeof (ah_header_t) + icv_size;
  return (req_multiple - total_size % req_multiple) % req_multiple;
}

#endif /* __AH_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
