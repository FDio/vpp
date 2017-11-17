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
#include <vnet/sctp/sctp.h>
#include <vnet/sctp/sctp_crc32c.h>
#include <vppinfra/random.h>

vlib_node_registration_t sctp4_output_node;
vlib_node_registration_t sctp6_output_node;

typedef enum _sctp_output_next
{
  SCTP_OUTPUT_NEXT_DROP,
  SCTP_OUTPUT_NEXT_IP_LOOKUP,
  SCTP_OUTPUT_N_NEXT
} sctp_output_next_t;

#define foreach_sctp4_output_next              	\
  _ (DROP, "error-drop")                        \
  _ (IP_LOOKUP, "ip4-lookup")

#define foreach_sctp6_output_next              	\
  _ (DROP, "error-drop")                        \
  _ (IP_LOOKUP, "ip6-lookup")

static char *sctp_error_strings[] = {
#define sctp_error(n,s) s,
#include <vnet/sctp/sctp_error.def>
#undef sctp_error
};

typedef struct
{
  sctp_header_t sctp_header;
  sctp_connection_t sctp_connection;
} sctp_tx_trace_t;

/**
 * Flush tx frame populated by retransmits and timer pops
 */
void
sctp_flush_frame_to_output (vlib_main_t * vm, u8 thread_index, u8 is_ip4)
{
  if (sctp_main.tx_frames[!is_ip4][thread_index])
    {
      u32 next_index;
      next_index = is_ip4 ? sctp4_output_node.index : sctp6_output_node.index;
      vlib_put_frame_to_node (vm, next_index,
			      sctp_main.tx_frames[!is_ip4][thread_index]);
      sctp_main.tx_frames[!is_ip4][thread_index] = 0;
    }
}

/**
 * Flush ip lookup tx frames populated by timer pops
 */
always_inline void
sctp_flush_frame_to_ip_lookup (vlib_main_t * vm, u8 thread_index, u8 is_ip4)
{
  if (sctp_main.ip_lookup_tx_frames[!is_ip4][thread_index])
    {
      u32 next_index;
      next_index = is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
      vlib_put_frame_to_node (vm, next_index,
			      sctp_main.ip_lookup_tx_frames[!is_ip4]
			      [thread_index]);
      sctp_main.ip_lookup_tx_frames[!is_ip4][thread_index] = 0;
    }
}

/**
 * Flush v4 and v6 sctp and ip-lookup tx frames for thread index
 */
void
sctp_flush_frames_to_output (u8 thread_index)
{
  vlib_main_t *vm = vlib_get_main ();
  sctp_flush_frame_to_output (vm, thread_index, 1);
  sctp_flush_frame_to_output (vm, thread_index, 0);
  sctp_flush_frame_to_ip_lookup (vm, thread_index, 1);
  sctp_flush_frame_to_ip_lookup (vm, thread_index, 0);
}

u32
ip4_sctp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
			   ip4_header_t * ip0)
{
  ip_csum_t checksum;
  u32 ip_header_length, payload_length_host_byte_order;
  u32 n_this_buffer, n_bytes_left, n_ip_bytes_this_buffer;
  void *data_this_buffer;

  /* Initialize checksum with ip header. */
  ip_header_length = ip4_header_bytes (ip0);
  payload_length_host_byte_order =
    clib_net_to_host_u16 (ip0->length) - ip_header_length;
  checksum =
    clib_host_to_net_u32 (payload_length_host_byte_order +
			  (ip0->protocol << 16));

  if (BITS (uword) == 32)
    {
      checksum =
	ip_csum_with_carry (checksum,
			    clib_mem_unaligned (&ip0->src_address, u32));
      checksum =
	ip_csum_with_carry (checksum,
			    clib_mem_unaligned (&ip0->dst_address, u32));
    }
  else
    checksum =
      ip_csum_with_carry (checksum,
			  clib_mem_unaligned (&ip0->src_address, u64));

  n_bytes_left = n_this_buffer = payload_length_host_byte_order;
  data_this_buffer = (void *) ip0 + ip_header_length;
  n_ip_bytes_this_buffer =
    p0->current_length - (((u8 *) ip0 - p0->data) - p0->current_data);
  if (n_this_buffer + ip_header_length > n_ip_bytes_this_buffer)
    {
      n_this_buffer = n_ip_bytes_this_buffer > ip_header_length ?
	n_ip_bytes_this_buffer - ip_header_length : 0;
    }
  while (1)
    {
      checksum = crc32c (checksum, data_this_buffer, n_this_buffer);
      n_bytes_left -= n_this_buffer;
      if (n_bytes_left == 0)
	break;

      ASSERT (p0->flags & VLIB_BUFFER_NEXT_PRESENT);
      p0 = vlib_get_buffer (vm, p0->next_buffer);
      data_this_buffer = vlib_buffer_get_current (p0);
      n_this_buffer = p0->current_length;
    }

  return checksum;
}

u32
ip6_sctp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
			   ip6_header_t * ip0, int *bogus_lengthp)
{
  ip_csum_t checksum;
  u16 payload_length_host_byte_order;
  u32 i, n_this_buffer, n_bytes_left;
  u32 headers_size = sizeof (ip0[0]);
  void *data_this_buffer;

  ASSERT (bogus_lengthp);
  *bogus_lengthp = 0;

  /* Initialize checksum with ip header. */
  checksum = ip0->payload_length + clib_host_to_net_u16 (ip0->protocol);
  payload_length_host_byte_order = clib_net_to_host_u16 (ip0->payload_length);
  data_this_buffer = (void *) (ip0 + 1);

  for (i = 0; i < ARRAY_LEN (ip0->src_address.as_uword); i++)
    {
      checksum = ip_csum_with_carry (checksum,
				     clib_mem_unaligned (&ip0->
							 src_address.as_uword
							 [i], uword));
      checksum =
	ip_csum_with_carry (checksum,
			    clib_mem_unaligned (&ip0->dst_address.as_uword[i],
						uword));
    }

  /* some icmp packets may come with a "router alert" hop-by-hop extension header (e.g., mldv2 packets)
   * or UDP-Ping packets */
  if (PREDICT_FALSE (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
    {
      u32 skip_bytes;
      ip6_hop_by_hop_ext_t *ext_hdr =
	(ip6_hop_by_hop_ext_t *) data_this_buffer;

      /* validate really icmp6 next */
      ASSERT ((ext_hdr->next_hdr == IP_PROTOCOL_SCTP));

      skip_bytes = 8 * (1 + ext_hdr->n_data_u64s);
      data_this_buffer = (void *) ((u8 *) data_this_buffer + skip_bytes);

      payload_length_host_byte_order -= skip_bytes;
      headers_size += skip_bytes;
    }

  n_bytes_left = n_this_buffer = payload_length_host_byte_order;
  if (p0 && n_this_buffer + headers_size > p0->current_length)
    n_this_buffer =
      p0->current_length >
      headers_size ? p0->current_length - headers_size : 0;
  while (1)
    {
      checksum =
	ip_incremental_checksum (checksum, data_this_buffer, n_this_buffer);
      n_bytes_left -= n_this_buffer;
      if (n_bytes_left == 0)
	break;

      if (!(p0->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  *bogus_lengthp = 1;
	  return 0xfefe;
	}
      p0 = vlib_get_buffer (vm, p0->next_buffer);
      data_this_buffer = vlib_buffer_get_current (p0);
      n_this_buffer = p0->current_length;
    }

  return checksum;
}

void
sctp_push_ip_hdr (sctp_main_t * tm, sctp_connection_t * tc, vlib_buffer_t * b)
{
  sctp_header_t *th = vlib_buffer_get_current (b);
  vlib_main_t *vm = vlib_get_main ();
  if (tc->c_is_ip4)
    {
      ip4_header_t *ih;
      ih = vlib_buffer_push_ip4 (vm, b, &tc->c_lcl_ip4,
				 &tc->c_rmt_ip4, IP_PROTOCOL_SCTP, 1);
      th->checksum = ip4_sctp_compute_checksum (vm, b, ih);
    }
  else
    {
      ip6_header_t *ih;
      int bogus = ~0;

      ih = vlib_buffer_push_ip6 (vm, b, &tc->c_lcl_ip6,
				 &tc->c_rmt_ip6, IP_PROTOCOL_SCTP);
      th->checksum = ip6_sctp_compute_checksum (vm, b, ih, &bogus);
      ASSERT (!bogus);
    }
}

always_inline void *
sctp_reuse_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    vlib_buffer_free_one (vm, b->next_buffer);
  /* Zero all flags but free list index and trace flag */
  b->flags &= VLIB_BUFFER_NEXT_PRESENT - 1;
  b->current_data = 0;
  b->current_length = 0;
  b->total_length_not_including_first_buffer = 0;
  vnet_buffer (b)->sctp.flags = 0;

  /* Leave enough space for headers */
  return vlib_buffer_make_headroom (b, MAX_HDRS_LEN);
}

always_inline void *
sctp_init_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  ASSERT ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
  b->flags &= VLIB_BUFFER_FREE_LIST_INDEX_MASK;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->total_length_not_including_first_buffer = 0;
  vnet_buffer (b)->sctp.flags = 0;
  /* Leave enough space for headers */
  return vlib_buffer_make_headroom (b, MAX_HDRS_LEN);
}

always_inline int
sctp_alloc_tx_buffers (sctp_main_t * tm, u8 thread_index, u32 n_free_buffers)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 current_length = vec_len (tm->tx_buffers[thread_index]);
  u32 n_allocated;

  vec_validate (tm->tx_buffers[thread_index],
		current_length + n_free_buffers - 1);
  n_allocated =
    vlib_buffer_alloc (vm, &tm->tx_buffers[thread_index][current_length],
		       n_free_buffers);
  _vec_len (tm->tx_buffers[thread_index]) = current_length + n_allocated;
  /* buffer shortage, report failure */
  if (vec_len (tm->tx_buffers[thread_index]) == 0)
    {
      clib_warning ("out of buffers");
      return -1;
    }
  return 0;
}

always_inline int
sctp_get_free_buffer_index (sctp_main_t * tm, u32 * bidx)
{
  u32 *my_tx_buffers;
  u32 thread_index = vlib_get_thread_index ();
  if (PREDICT_FALSE (vec_len (tm->tx_buffers[thread_index]) == 0))
    {
      if (sctp_alloc_tx_buffers (tm, thread_index, VLIB_FRAME_SIZE))
	return -1;
    }
  my_tx_buffers = tm->tx_buffers[thread_index];
  *bidx = my_tx_buffers[vec_len (my_tx_buffers) - 1];
  _vec_len (my_tx_buffers) -= 1;
  return 0;
}

always_inline void
sctp_enqueue_to_ip_lookup_i (vlib_main_t * vm, vlib_buffer_t * b, u32 bi,
			     u8 is_ip4, u8 flush)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  u32 thread_index = vlib_get_thread_index ();
  u32 *to_next, next_index;
  vlib_frame_t *f;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->error = 0;

  /* Default FIB for now */
  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;

  /* Send to IP lookup */
  next_index = is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
  if (VLIB_BUFFER_TRACE_TRAJECTORY > 0)
    {
      b->pre_data[0] = 2;
      b->pre_data[1] = next_index;
    }

  f = tm->ip_lookup_tx_frames[!is_ip4][thread_index];
  if (!f)
    {
      f = vlib_get_frame_to_node (vm, next_index);
      ASSERT (f);
      tm->ip_lookup_tx_frames[!is_ip4][thread_index] = f;
    }

  to_next = vlib_frame_vector_args (f);
  to_next[f->n_vectors] = bi;
  f->n_vectors += 1;
  if (flush || f->n_vectors == VLIB_FRAME_SIZE)
    {
      vlib_put_frame_to_node (vm, next_index, f);
      tm->ip_lookup_tx_frames[!is_ip4][thread_index] = 0;
    }
}

always_inline void
sctp_enqueue_to_ip_lookup (vlib_main_t * vm, vlib_buffer_t * b, u32 bi,
			   u8 is_ip4)
{
  sctp_enqueue_to_ip_lookup_i (vm, b, bi, is_ip4, 0);
}

/**
 * Convert buffer to INIT
 */
void
sctp_prepare_init (sctp_connection_t * tc, vlib_buffer_t * b)
{
  u32 random_seed = random_default_seed ();
  sctp_init_chunk_t *init_chunk =
    vlib_buffer_push_uninit (b, sizeof (sctp_init_chunk_t));

  init_chunk->sctp_hdr.src_port = tc->c_lcl_port;
  init_chunk->sctp_hdr.dst_port = tc->c_rmt_port;
  init_chunk->sctp_hdr.checksum = 0;
  init_chunk->sctp_hdr.verification_tag = tc->remote_tag;
  init_chunk->chunk_hdr.type = clib_host_to_net_u32 (INIT);
  init_chunk->initiate_tag = random_u32 (&random_seed);

  tc->local_tag = init_chunk->initiate_tag;

  vnet_buffer (b)->sctp.connection_index = tc->c_c_index;
}

u32
sctp_compute_mac ()
{
  return 0x0;
}

void
sctp_prepare_cookie_ack (sctp_connection_t * tc, vlib_buffer_t * b)
{
  vlib_main_t *vm = vlib_get_main ();

  sctp_reuse_buffer (vm, b);

  sctp_cookie_ack_chunk_t *cookie_ack_chunk =
    vlib_buffer_push_uninit (b, sizeof (sctp_cookie_ack_chunk_t));

  cookie_ack_chunk->sctp_hdr.src_port = tc->c_lcl_port;
  cookie_ack_chunk->sctp_hdr.dst_port = tc->c_rmt_port;
  cookie_ack_chunk->sctp_hdr.checksum = 0;
  cookie_ack_chunk->sctp_hdr.verification_tag = tc->remote_tag;
  cookie_ack_chunk->chunk_hdr.type = clib_host_to_net_u32 (COOKIE_ACK);

  vnet_buffer (b)->sctp.connection_index = tc->c_c_index;
}

void
sctp_prepare_cookie_echo (sctp_connection_t * tc, vlib_buffer_t * b,
			  sctp_state_cookie_param_t * sc)
{
  vlib_main_t *vm = vlib_get_main ();

  sctp_reuse_buffer (vm, b);

  /* The minimum size of the message is given by the sctp_init_ack_chunk_t */
  u16 alloc_bytes = sizeof (sctp_cookie_echo_chunk_t);

  sctp_cookie_echo_chunk_t *cookie_echo_chunk =
    vlib_buffer_push_uninit (b, alloc_bytes);

  cookie_echo_chunk->sctp_hdr.src_port = tc->c_lcl_port;
  cookie_echo_chunk->sctp_hdr.dst_port = tc->c_rmt_port;
  cookie_echo_chunk->sctp_hdr.checksum = 0;
  cookie_echo_chunk->sctp_hdr.verification_tag = 0;
  cookie_echo_chunk->chunk_hdr.type = clib_host_to_net_u32 (COOKIE_ECHO);

  clib_memcpy (&(cookie_echo_chunk->cookie), sc,
	       sizeof (sctp_state_cookie_param_t));

  vnet_buffer (b)->sctp.connection_index = tc->c_c_index;

}

/**
 * Convert buffer to INIT-ACK
 */
void
sctp_prepare_initack_chunk (sctp_connection_t * tc, vlib_buffer_t * b,
			    ip4_address_t * ip4_addr,
			    ip6_address_t * ip6_addr)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 random_seed = random_default_seed ();

  sctp_reuse_buffer (vm, b);

  /* The minimum size of the message is given by the sctp_init_ack_chunk_t */
  u16 alloc_bytes =
    sizeof (sctp_init_ack_chunk_t) + sizeof (sctp_state_cookie_param_t);

  if (PREDICT_TRUE (ip4_addr != NULL))
    {
      /* Create room for variable-length fields in the INIT_ACK chunk */
      alloc_bytes += SCTP_IPV4_ADDRESS_TYPE_LENGTH;
    }
  if (PREDICT_TRUE (ip6_addr != NULL))
    {
      /* Create room for variable-length fields in the INIT_ACK chunk */
      alloc_bytes += SCTP_IPV6_ADDRESS_TYPE_LENGTH;
    }

  sctp_init_ack_chunk_t *init_chunk =
    vlib_buffer_push_uninit (b, alloc_bytes);

  u16 pointer_offset = sizeof (init_chunk);

  /* Create State Cookie parameter */
  sctp_state_cookie_param_t *state_cookie_param =
    (sctp_state_cookie_param_t *) init_chunk + pointer_offset;
  state_cookie_param->param_hdr.type =
    clib_host_to_net_u32 (SCTP_STATE_COOKIE_TYPE);
  state_cookie_param->param_hdr.length =
    clib_host_to_net_u32 (sizeof (sctp_state_cookie_param_t));
  state_cookie_param->creation_time = clib_host_to_net_u32 (sctp_time_now ());
  state_cookie_param->cookie_lifespan =
    clib_host_to_net_u32 (SCTP_VALID_COOKIE_LIFE);
  state_cookie_param->mac = clib_host_to_net_u32 (sctp_compute_mac ());

  pointer_offset += sizeof (sctp_state_cookie_param_t);

  if (PREDICT_TRUE (ip4_addr != NULL))
    {
      sctp_ipv4_addr_param_t *ipv4_addr =
	(sctp_ipv4_addr_param_t *) init_chunk + pointer_offset;

      ipv4_addr->param_hdr.type =
	clib_host_to_net_u16 (SCTP_IPV4_ADDRESS_TYPE);
      ipv4_addr->param_hdr.length =
	clib_host_to_net_u16 (SCTP_IPV4_ADDRESS_TYPE_LENGTH);
      ipv4_addr->address.as_u32 = ip4_addr->as_u32;

      pointer_offset += SCTP_IPV4_ADDRESS_TYPE_LENGTH;
    }
  if (PREDICT_TRUE (ip6_addr != NULL))
    {
      sctp_ipv6_addr_param_t *ipv6_addr =
	(sctp_ipv6_addr_param_t *) init_chunk + sizeof (sctp_init_chunk_t) +
	pointer_offset;

      ipv6_addr->param_hdr.type =
	clib_host_to_net_u16 (SCTP_IPV6_ADDRESS_TYPE);
      ipv6_addr->param_hdr.length =
	clib_host_to_net_u16 (SCTP_IPV6_ADDRESS_TYPE_LENGTH);
      ipv6_addr->address.as_u64[0] = ip6_addr->as_u64[0];
      ipv6_addr->address.as_u64[1] = ip6_addr->as_u64[1];

      pointer_offset += SCTP_IPV6_ADDRESS_TYPE_LENGTH;
    }

  /* src_port & dst_port are already in network byte-order */
  init_chunk->sctp_hdr.checksum = 0;
  init_chunk->sctp_hdr.src_port = tc->c_lcl_port;
  init_chunk->sctp_hdr.dst_port = tc->c_rmt_port;
  /* the tc->verification_tag is already in network byte-order (being a copy of the init_tag coming with the INIT chunk) */
  init_chunk->sctp_hdr.verification_tag = tc->remote_tag;

  init_chunk->chunk_hdr.type = clib_host_to_net_u32 (INIT_ACK);
  init_chunk->chunk_hdr.length = clib_host_to_net_u32 (alloc_bytes);

  init_chunk->initiate_tag = random_u32 (&random_seed);
  init_chunk->a_rwnd = 0x0;
  init_chunk->inboud_streams_count = 0x0;
  init_chunk->outbound_streams_count = 0x0;
  init_chunk->initial_tsn = 0x0;

  vnet_buffer (b)->sctp.connection_index = tc->c_c_index;
}

/**
 *  Send INIT
 */
void
sctp_send_init (sctp_connection_t * tc)
{
  vlib_buffer_t *b;
  u32 bi;
  sctp_main_t *tm = vnet_get_sctp_main ();
  vlib_main_t *vm = vlib_get_main ();

  if (PREDICT_FALSE (sctp_get_free_buffer_index (tm, &bi)))
    return;

  b = vlib_get_buffer (vm, bi);
  sctp_init_buffer (vm, b);
  sctp_prepare_init (tc, b);

  /* Measure RTT with this */
  tc->rtt_ts = sctp_time_now ();
  tc->rtt_seq = tc->snd_nxt;
  tc->rto_boff = 0;

  sctp_push_ip_hdr (tm, tc, b);
  sctp_enqueue_to_ip_lookup (vm, b, bi, tc->c_is_ip4);

  /* Start the T1_INIT timer */
  sctp_timer_set (tc, SCTP_TIMER_T1_INIT, SCTP_RTO_INIT);
  /* Change state to COOKIE_WAIT */
  tc->state = SCTP_STATE_COOKIE_WAIT;
}

/**
 * Push SCTP header and update connection variables
 */
static void
sctp_push_hdr_i (sctp_connection_t * tc, vlib_buffer_t * b,
		 sctp_state_t next_state, u8 compute_opts)
{
  /* TODO */
}

u32
sctp_push_header (transport_connection_t * tconn, vlib_buffer_t * b)
{
  sctp_connection_t *tc;

  tc = (sctp_connection_t *) tconn;
  sctp_push_hdr_i (tc, b, SCTP_STATE_ESTABLISHED, 0);

  tc->rtt_ts = sctp_time_now ();
  tc->rtt_seq = tc->snd_nxt;

  return 0;
}

always_inline uword
sctp46_output_inline (vlib_main_t * vm,
		      vlib_node_runtime_t * node,
		      vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  sctp_set_time_now (my_thread_index);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  sctp_connection_t *tc0;
	  sctp_tx_trace_t *t0;
	  sctp_header_t *th0 = 0;
	  u32 error0 = SCTP_ERROR_PKTS_SENT, next0 =
	    SCTP_OUTPUT_NEXT_IP_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  tc0 = sctp_connection_get (vnet_buffer (b0)->sctp.connection_index,
				     my_thread_index);

	  th0 = vlib_buffer_get_current (b0);

	  if (is_ip4)
	    {
	      vlib_buffer_push_ip4 (vm, b0, &tc0->c_lcl_ip4, &tc0->c_rmt_ip4,
				    IP_PROTOCOL_SCTP, 1);
	      b0->flags |= VNET_BUFFER_F_OFFLOAD_SCTP_CKSUM;
	      vnet_buffer (b0)->l4_hdr_offset = (u8 *) th0 - b0->data;
	      th0->checksum = 0;
	    }
	  else
	    {
	      ip6_header_t *ih0;
	      ih0 = vlib_buffer_push_ip6 (vm, b0, &tc0->c_lcl_ip6,
					  &tc0->c_rmt_ip6, IP_PROTOCOL_SCTP);
	      b0->flags |= VNET_BUFFER_F_OFFLOAD_SCTP_CKSUM;
	      vnet_buffer (b0)->l3_hdr_offset = (u8 *) ih0 - b0->data;
	      vnet_buffer (b0)->l4_hdr_offset = (u8 *) th0 - b0->data;
	      th0->checksum = 0;
	    }

	  /* EXTRA LOGIC TO BE IMPLEMENTED TO DEAL WITH PROTOCOL HANDLING */
	  switch (tc0->state)
	    {
	      /* An end-point receiving a request to establish a new session remains
	       * in CLOSED state until a connection is ESTABLISHED.
	       * In the SCTP_STATE_CLOSED we still have to handle the sending of the:
	       * - INIT_ACK chunk
	       * - COOKIE_ACK chunk
	       * However, the protocol clearly states not to allocate any resources to
	       * the connection until it has been fully established (e.g. no timers, etc.).
	       */
	    case SCTP_STATE_CLOSED:
	      {
		/* TODO: Add a debugging message here but no protocol code to be implemented */
		break;
	      }
	    case SCTP_STATE_COOKIE_WAIT:
	      {

		break;
	      }
	    case SCTP_STATE_ESTABLISHED:
	      {
		break;
	      }
	    }

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

	  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  //done:
	  b0->error = node->errors[error0];
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      if (th0)
		{
		  clib_memcpy (&t0->sctp_header, th0,
			       sizeof (t0->sctp_header));
		}
	      else
		{
		  memset (&t0->sctp_header, 0, sizeof (t0->sctp_header));
		}
	      clib_memcpy (&t0->sctp_connection, tc0,
			   sizeof (t0->sctp_connection));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static uword
sctp4_output (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  return sctp46_output_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
sctp6_output (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  return sctp46_output_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp4_output_node) =
{
  .function = sctp4_output,.name = "sctp4-output",
    /* Takes a vector of packets. */
    .vector_size = sizeof (u32),
    .n_errors = SCTP_N_ERROR,
    .error_strings = sctp_error_strings,
    .n_next_nodes = SCTP_OUTPUT_N_NEXT,
    .next_nodes = {
#define _(s,n) [SCTP_OUTPUT_NEXT_##s] = n,
    foreach_sctp4_output_next
#undef _
    },
    .format_buffer = format_sctp_header,
    .format_trace = format_sctp_tx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp4_output_node, sctp4_output);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_output_node) =
{
  .function = sctp6_output,
  .name = "sctp6-output",
    /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [SCTP_OUTPUT_NEXT_##s] = n,
    foreach_sctp6_output_next
#undef _
  },
  .format_buffer = format_sctp_header,
  .format_trace = format_sctp_tx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp6_output_node, sctp6_output);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
