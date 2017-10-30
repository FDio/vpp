/*
 * Copyright (c) 2017 SUSE LLC.
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
#include <vppinfra/sparse_vec.h>
#include <vnet/sctp/sctp.h>
#include <vnet/sctp/sctp_packet.h>
#include <vnet/session/session.h>
#include <math.h>

vlib_node_registration_t sctp4_input_node;
vlib_node_registration_t sctp6_input_node;

/*
static u8
sctp_lookup_is_valid (sctp_connection_t * tc, sctp_header_t * hdr)
{
  transport_connection_t *tmp = 0;
  u64 handle;

  if (!tc)
    return 1;

  u8 is_valid = (tc->c_lcl_port == hdr->dst_port
		 && (tc->state == SCTP_STATE_ESTABLISHED
		     || tc->c_rmt_port == hdr->src_port));

  if (!is_valid)
    {
      handle = session_lookup_half_open_handle (&tc->connection);
      tmp = session_lookup_half_open_connection (handle & 0xFFFFFFFF,
						 tc->c_proto, tc->c_is_ip4);

      if (tmp)
	{
	  if (tmp->lcl_port == hdr->dst_port
	      && tmp->rmt_port == hdr->src_port)
	    {
	      // ADD debuggin for VALID half-open
	    }
	}
    }
  return is_valid;
}
*/

/**
 * Lookup transport connection
 */
/*
static sctp_connection_t *
sctp_lookup_connection (u32 fib_index, vlib_buffer_t * b, u8 thread_index,
		       u8 is_ip4)
{
  sctp_header_t *sctp;
  transport_connection_t *tconn;
  sctp_connection_t *tc;
  if (is_ip4)
    {
      ip4_header_t *ip4;
      ip4 = vlib_buffer_get_current (b);
      sctp = ip4_next_header (ip4);
      tconn = session_lookup_connection_wt4 (fib_index,
					     &ip4->dst_address,
					     &ip4->src_address,
					     sctp->dst_port,
					     sctp->src_port,
					     TRANSPORT_PROTO_SCTP,
					     thread_index);
      tc = sctp_get_connection_from_transport (tconn);
      ASSERT (sctp_lookup_is_valid (tc, sctp));
    }
  else
    {
      ip6_header_t *ip6;
      ip6 = vlib_buffer_get_current (b);
      sctp = ip6_next_header (ip6);
      tconn = session_lookup_connection_wt6 (fib_index,
					     &ip6->dst_address,
					     &ip6->src_address,
					     sctp->dst_port,
					     sctp->src_port,
						 TRANSPORT_PROTO_SCTP,
					     thread_index);
      tc = sctp_get_connection_from_transport (tconn);
      ASSERT (sctp_lookup_is_valid (tc, sctp));
    }
  return tc;
}
*/

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
