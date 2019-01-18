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
#include <vnet/sctp/sctp_debug.h>
#include <vppinfra/random.h>
#include <openssl/hmac.h>

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
      checksum =
	ip_incremental_checksum (checksum, data_this_buffer, n_this_buffer);
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
sctp_push_ip_hdr (sctp_main_t * tm, sctp_sub_connection_t * sctp_sub_conn,
		  vlib_buffer_t * b)
{
  sctp_header_t *th = vlib_buffer_get_current (b);
  vlib_main_t *vm = vlib_get_main ();
  if (sctp_sub_conn->c_is_ip4)
    {
      ip4_header_t *ih;
      ih = vlib_buffer_push_ip4 (vm, b, &sctp_sub_conn->c_lcl_ip4,
				 &sctp_sub_conn->c_rmt_ip4, IP_PROTOCOL_SCTP,
				 1);
      th->checksum = ip4_sctp_compute_checksum (vm, b, ih);
    }
  else
    {
      ip6_header_t *ih;
      int bogus = ~0;

      ih = vlib_buffer_push_ip6 (vm, b, &sctp_sub_conn->c_lcl_ip6,
				 &sctp_sub_conn->c_rmt_ip6, IP_PROTOCOL_SCTP);
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
  vnet_buffer (b)->sctp.subconn_idx = MAX_SCTP_CONNECTIONS;

  /* Leave enough space for headers */
  return vlib_buffer_make_headroom (b, MAX_HDRS_LEN);
}

always_inline void *
sctp_init_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  ASSERT ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->total_length_not_including_first_buffer = 0;
  vnet_buffer (b)->sctp.flags = 0;
  vnet_buffer (b)->sctp.subconn_idx = MAX_SCTP_CONNECTIONS;
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
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
sctp_enqueue_to_output_i (vlib_main_t * vm, vlib_buffer_t * b, u32 bi,
			  u8 is_ip4, u8 flush)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  u32 thread_index = vlib_get_thread_index ();
  u32 *to_next, next_index;
  vlib_frame_t *f;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->error = 0;

  /* Decide where to send the packet */
  next_index = is_ip4 ? sctp4_output_node.index : sctp6_output_node.index;
  sctp_trajectory_add_start (b, 2);

  /* Get frame to v4/6 output node */
  f = tm->tx_frames[!is_ip4][thread_index];
  if (!f)
    {
      f = vlib_get_frame_to_node (vm, next_index);
      ASSERT (f);
      tm->tx_frames[!is_ip4][thread_index] = f;
    }
  to_next = vlib_frame_vector_args (f);
  to_next[f->n_vectors] = bi;
  f->n_vectors += 1;
  if (flush || f->n_vectors == VLIB_FRAME_SIZE)
    {
      vlib_put_frame_to_node (vm, next_index, f);
      tm->tx_frames[!is_ip4][thread_index] = 0;
    }
}

always_inline void
sctp_enqueue_to_output_now (vlib_main_t * vm, vlib_buffer_t * b, u32 bi,
			    u8 is_ip4)
{
  sctp_enqueue_to_output_i (vm, b, bi, is_ip4, 1);
}

always_inline void
sctp_enqueue_to_ip_lookup_i (vlib_main_t * vm, vlib_buffer_t * b, u32 bi,
			     u8 is_ip4, u32 fib_index, u8 flush)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  u32 thread_index = vlib_get_thread_index ();
  u32 *to_next, next_index;
  vlib_frame_t *f;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->error = 0;

  vnet_buffer (b)->sw_if_index[VLIB_TX] = fib_index;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;

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
			   u8 is_ip4, u32 fib_index)
{
  sctp_enqueue_to_ip_lookup_i (vm, b, bi, is_ip4, fib_index, 0);
  if (vm->thread_index == 0 && vlib_num_workers ())
    session_flush_frames_main_thread (vm);
}

/**
 * Convert buffer to INIT
 */
void
sctp_prepare_init_chunk (sctp_connection_t * sctp_conn, u8 idx,
			 vlib_buffer_t * b)
{
  u32 random_seed = random_default_seed ();
  u16 alloc_bytes = sizeof (sctp_init_chunk_t);
  sctp_sub_connection_t *sub_conn = &sctp_conn->sub_conn[idx];

  sctp_ipv4_addr_param_t *ip4_param = 0;
  sctp_ipv6_addr_param_t *ip6_param = 0;

  if (sub_conn->c_is_ip4)
    alloc_bytes += sizeof (sctp_ipv4_addr_param_t);
  else
    alloc_bytes += sizeof (sctp_ipv6_addr_param_t);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_init_chunk_t *init_chunk = vlib_buffer_push_uninit (b, alloc_bytes);

  u16 pointer_offset = sizeof (init_chunk);
  if (sub_conn->c_is_ip4)
    {
      ip4_param = (sctp_ipv4_addr_param_t *) init_chunk + pointer_offset;
      ip4_param->address.as_u32 = sub_conn->c_lcl_ip.ip4.as_u32;

      pointer_offset += sizeof (sctp_ipv4_addr_param_t);
    }
  else
    {
      ip6_param = (sctp_ipv6_addr_param_t *) init_chunk + pointer_offset;
      ip6_param->address.as_u64[0] = sub_conn->c_lcl_ip.ip6.as_u64[0];
      ip6_param->address.as_u64[1] = sub_conn->c_lcl_ip.ip6.as_u64[1];

      pointer_offset += sizeof (sctp_ipv6_addr_param_t);
    }

  init_chunk->sctp_hdr.src_port = sub_conn->c_lcl_port;	/* No need of host_to_net conversion, already in net-byte order */
  init_chunk->sctp_hdr.dst_port = sub_conn->c_rmt_port;	/* No need of host_to_net conversion, already in net-byte order */
  init_chunk->sctp_hdr.checksum = 0;
  /* The sender of an INIT must set the VERIFICATION_TAG to 0 as per RFC 4960 Section 8.5.1 */
  init_chunk->sctp_hdr.verification_tag = 0x0;

  vnet_sctp_set_chunk_type (&init_chunk->chunk_hdr, INIT);
  vnet_sctp_set_chunk_length (&init_chunk->chunk_hdr, chunk_len);
  vnet_sctp_common_hdr_params_host_to_net (&init_chunk->chunk_hdr);

  sctp_init_cwnd (sctp_conn);

  init_chunk->a_rwnd = clib_host_to_net_u32 (sctp_conn->sub_conn[idx].cwnd);
  init_chunk->initiate_tag = clib_host_to_net_u32 (random_u32 (&random_seed));
  init_chunk->inboud_streams_count =
    clib_host_to_net_u16 (INBOUND_STREAMS_COUNT);
  init_chunk->outbound_streams_count =
    clib_host_to_net_u16 (OUTBOUND_STREAMS_COUNT);

  init_chunk->initial_tsn =
    clib_host_to_net_u32 (sctp_conn->local_initial_tsn);
  SCTP_CONN_TRACKING_DBG ("sctp_conn->local_initial_tsn = %u",
			  sctp_conn->local_initial_tsn);

  sctp_conn->local_tag = init_chunk->initiate_tag;

  vnet_buffer (b)->sctp.connection_index = sub_conn->c_c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;

  SCTP_DBG_STATE_MACHINE ("CONN_INDEX = %u, CURR_CONN_STATE = %u (%s), "
			  "CHUNK_TYPE = %s, "
			  "SRC_PORT = %u, DST_PORT = %u",
			  sub_conn->connection.c_index,
			  sctp_conn->state,
			  sctp_state_to_string (sctp_conn->state),
			  sctp_chunk_to_string (INIT),
			  init_chunk->sctp_hdr.src_port,
			  init_chunk->sctp_hdr.dst_port);
}

void
sctp_compute_mac (sctp_connection_t * sctp_conn,
		  sctp_state_cookie_param_t * state_cookie)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX *ctx;
#else
  HMAC_CTX ctx;
#endif
  unsigned int len = 0;
  const EVP_MD *md = EVP_sha1 ();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  ctx = HMAC_CTX_new ();
  HMAC_Init_ex (ctx, &state_cookie->creation_time,
		sizeof (state_cookie->creation_time), md, NULL);
  HMAC_Update (ctx, (const unsigned char *) &sctp_conn, sizeof (sctp_conn));
  HMAC_Final (ctx, state_cookie->mac, &len);
#else
  HMAC_CTX_init (&ctx);
  HMAC_Init_ex (&ctx, &state_cookie->creation_time,
		sizeof (state_cookie->creation_time), md, NULL);
  HMAC_Update (&ctx, (const unsigned char *) &sctp_conn, sizeof (sctp_conn));
  HMAC_Final (&ctx, state_cookie->mac, &len);
  HMAC_CTX_cleanup (&ctx);
#endif

  ENDIANESS_SWAP (state_cookie->mac);
}

void
sctp_prepare_cookie_ack_chunk (sctp_connection_t * sctp_conn, u8 idx,
			       vlib_buffer_t * b)
{
  vlib_main_t *vm = vlib_get_main ();

  sctp_reuse_buffer (vm, b);

  u16 alloc_bytes = sizeof (sctp_cookie_ack_chunk_t);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_cookie_ack_chunk_t *cookie_ack_chunk =
    vlib_buffer_push_uninit (b, alloc_bytes);

  cookie_ack_chunk->sctp_hdr.checksum = 0;
  cookie_ack_chunk->sctp_hdr.src_port =
    sctp_conn->sub_conn[idx].connection.lcl_port;
  cookie_ack_chunk->sctp_hdr.dst_port =
    sctp_conn->sub_conn[idx].connection.rmt_port;
  cookie_ack_chunk->sctp_hdr.verification_tag = sctp_conn->remote_tag;
  vnet_sctp_set_chunk_type (&cookie_ack_chunk->chunk_hdr, COOKIE_ACK);
  vnet_sctp_set_chunk_length (&cookie_ack_chunk->chunk_hdr, chunk_len);

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

void
sctp_prepare_cookie_echo_chunk (sctp_connection_t * sctp_conn, u8 idx,
				vlib_buffer_t * b, u8 reuse_buffer)
{
  vlib_main_t *vm = vlib_get_main ();

  if (reuse_buffer)
    sctp_reuse_buffer (vm, b);

  /* The minimum size of the message is given by the sctp_init_ack_chunk_t */
  u16 alloc_bytes = sizeof (sctp_cookie_echo_chunk_t);
  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);
  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);
  sctp_cookie_echo_chunk_t *cookie_echo_chunk =
    vlib_buffer_push_uninit (b, alloc_bytes);
  cookie_echo_chunk->sctp_hdr.checksum = 0;
  cookie_echo_chunk->sctp_hdr.src_port =
    sctp_conn->sub_conn[idx].connection.lcl_port;
  cookie_echo_chunk->sctp_hdr.dst_port =
    sctp_conn->sub_conn[idx].connection.rmt_port;
  cookie_echo_chunk->sctp_hdr.verification_tag = sctp_conn->remote_tag;
  vnet_sctp_set_chunk_type (&cookie_echo_chunk->chunk_hdr, COOKIE_ECHO);
  vnet_sctp_set_chunk_length (&cookie_echo_chunk->chunk_hdr, chunk_len);
  clib_memcpy_fast (&(cookie_echo_chunk->cookie), &sctp_conn->cookie_param,
		    sizeof (sctp_state_cookie_param_t));

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}


/*
 *  Send COOKIE_ECHO
 */
void
sctp_send_cookie_echo (sctp_connection_t * sctp_conn)
{
  vlib_buffer_t *b;
  u32 bi;
  sctp_main_t *tm = vnet_get_sctp_main ();
  vlib_main_t *vm = vlib_get_main ();

  if (PREDICT_FALSE (sctp_conn->init_retransmit_err > SCTP_MAX_INIT_RETRANS))
    {
      clib_warning ("Reached MAX_INIT_RETRANS times. Aborting connection.");

      session_stream_connect_notify (&sctp_conn->sub_conn
				     [SCTP_PRIMARY_PATH_IDX].connection, 1);

      sctp_connection_timers_reset (sctp_conn);

      sctp_connection_cleanup (sctp_conn);
    }

  if (PREDICT_FALSE (sctp_get_free_buffer_index (tm, &bi)))
    return;

  b = vlib_get_buffer (vm, bi);
  u8 idx = SCTP_PRIMARY_PATH_IDX;

  sctp_init_buffer (vm, b);
  sctp_prepare_cookie_echo_chunk (sctp_conn, idx, b, 0);
  sctp_enqueue_to_output_now (vm, b, bi, sctp_conn->sub_conn[idx].c_is_ip4);

  /* Start the T1_INIT timer */
  sctp_timer_set (sctp_conn, idx, SCTP_TIMER_T1_INIT,
		  sctp_conn->sub_conn[idx].RTO);

  /* Change state to COOKIE_WAIT */
  sctp_conn->state = SCTP_STATE_COOKIE_WAIT;

  /* Measure RTT with this */
  sctp_conn->sub_conn[idx].rtt_ts = sctp_time_now ();
}


/**
 * Convert buffer to ERROR
 */
void
sctp_prepare_operation_error (sctp_connection_t * sctp_conn, u8 idx,
			      vlib_buffer_t * b, u8 err_cause)
{
  vlib_main_t *vm = vlib_get_main ();

  sctp_reuse_buffer (vm, b);

  /* The minimum size of the message is given by the sctp_operation_error_t */
  u16 alloc_bytes =
    sizeof (sctp_operation_error_t) + sizeof (sctp_err_cause_param_t);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_operation_error_t *err_chunk =
    vlib_buffer_push_uninit (b, alloc_bytes);

  /* src_port & dst_port are already in network byte-order */
  err_chunk->sctp_hdr.checksum = 0;
  err_chunk->sctp_hdr.src_port = sctp_conn->sub_conn[idx].connection.lcl_port;
  err_chunk->sctp_hdr.dst_port = sctp_conn->sub_conn[idx].connection.rmt_port;
  /* As per RFC4960 Section 5.2.2: copy the INITIATE_TAG into the VERIFICATION_TAG of the ABORT chunk */
  err_chunk->sctp_hdr.verification_tag = sctp_conn->local_tag;

  err_chunk->err_causes[0].param_hdr.length =
    clib_host_to_net_u16 (sizeof (err_chunk->err_causes[0].param_hdr.type) +
			  sizeof (err_chunk->err_causes[0].param_hdr.length));
  err_chunk->err_causes[0].param_hdr.type = clib_host_to_net_u16 (err_cause);

  vnet_sctp_set_chunk_type (&err_chunk->chunk_hdr, OPERATION_ERROR);
  vnet_sctp_set_chunk_length (&err_chunk->chunk_hdr, chunk_len);

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

/**
 * Convert buffer to ABORT
 */
void
sctp_prepare_abort_for_collision (sctp_connection_t * sctp_conn, u8 idx,
				  vlib_buffer_t * b, ip4_address_t * ip4_addr,
				  ip6_address_t * ip6_addr)
{
  vlib_main_t *vm = vlib_get_main ();

  sctp_reuse_buffer (vm, b);

  /* The minimum size of the message is given by the sctp_abort_chunk_t */
  u16 alloc_bytes = sizeof (sctp_abort_chunk_t);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_abort_chunk_t *abort_chunk = vlib_buffer_push_uninit (b, alloc_bytes);

  /* src_port & dst_port are already in network byte-order */
  abort_chunk->sctp_hdr.checksum = 0;
  abort_chunk->sctp_hdr.src_port =
    sctp_conn->sub_conn[idx].connection.lcl_port;
  abort_chunk->sctp_hdr.dst_port =
    sctp_conn->sub_conn[idx].connection.rmt_port;
  /* As per RFC4960 Section 5.2.2: copy the INITIATE_TAG into the VERIFICATION_TAG of the ABORT chunk */
  abort_chunk->sctp_hdr.verification_tag = sctp_conn->local_tag;

  vnet_sctp_set_chunk_type (&abort_chunk->chunk_hdr, ABORT);
  vnet_sctp_set_chunk_length (&abort_chunk->chunk_hdr, chunk_len);

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

/**
 * Convert buffer to INIT-ACK
 */
void
sctp_prepare_initack_chunk_for_collision (sctp_connection_t * sctp_conn,
					  u8 idx, vlib_buffer_t * b,
					  ip4_address_t * ip4_addr,
					  ip6_address_t * ip6_addr)
{
  vlib_main_t *vm = vlib_get_main ();
  sctp_ipv4_addr_param_t *ip4_param = 0;
  sctp_ipv6_addr_param_t *ip6_param = 0;

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

  if (sctp_conn->sub_conn[idx].connection.is_ip4)
    alloc_bytes += sizeof (sctp_ipv4_addr_param_t);
  else
    alloc_bytes += sizeof (sctp_ipv6_addr_param_t);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_init_ack_chunk_t *init_ack_chunk =
    vlib_buffer_push_uninit (b, alloc_bytes);

  u16 pointer_offset = sizeof (sctp_init_ack_chunk_t);

  /* Create State Cookie parameter */
  sctp_state_cookie_param_t *state_cookie_param =
    (sctp_state_cookie_param_t *) ((char *) init_ack_chunk + pointer_offset);

  state_cookie_param->param_hdr.type =
    clib_host_to_net_u16 (SCTP_STATE_COOKIE_TYPE);
  state_cookie_param->param_hdr.length =
    clib_host_to_net_u16 (sizeof (sctp_state_cookie_param_t));
  state_cookie_param->creation_time = clib_host_to_net_u64 (sctp_time_now ());
  state_cookie_param->cookie_lifespan =
    clib_host_to_net_u32 (SCTP_VALID_COOKIE_LIFE);

  sctp_compute_mac (sctp_conn, state_cookie_param);

  pointer_offset += sizeof (sctp_state_cookie_param_t);

  if (PREDICT_TRUE (ip4_addr != NULL))
    {
      sctp_ipv4_addr_param_t *ipv4_addr =
	(sctp_ipv4_addr_param_t *) init_ack_chunk + pointer_offset;

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
	(sctp_ipv6_addr_param_t *) init_ack_chunk + pointer_offset;

      ipv6_addr->param_hdr.type =
	clib_host_to_net_u16 (SCTP_IPV6_ADDRESS_TYPE);
      ipv6_addr->param_hdr.length =
	clib_host_to_net_u16 (SCTP_IPV6_ADDRESS_TYPE_LENGTH);
      ipv6_addr->address.as_u64[0] = ip6_addr->as_u64[0];
      ipv6_addr->address.as_u64[1] = ip6_addr->as_u64[1];

      pointer_offset += SCTP_IPV6_ADDRESS_TYPE_LENGTH;
    }

  if (sctp_conn->sub_conn[idx].connection.is_ip4)
    {
      ip4_param = (sctp_ipv4_addr_param_t *) init_ack_chunk + pointer_offset;
      ip4_param->address.as_u32 =
	sctp_conn->sub_conn[idx].connection.lcl_ip.ip4.as_u32;

      pointer_offset += sizeof (sctp_ipv4_addr_param_t);
    }
  else
    {
      ip6_param = (sctp_ipv6_addr_param_t *) init_ack_chunk + pointer_offset;
      ip6_param->address.as_u64[0] =
	sctp_conn->sub_conn[idx].connection.lcl_ip.ip6.as_u64[0];
      ip6_param->address.as_u64[1] =
	sctp_conn->sub_conn[idx].connection.lcl_ip.ip6.as_u64[1];

      pointer_offset += sizeof (sctp_ipv6_addr_param_t);
    }

  /* src_port & dst_port are already in network byte-order */
  init_ack_chunk->sctp_hdr.checksum = 0;
  init_ack_chunk->sctp_hdr.src_port =
    sctp_conn->sub_conn[idx].connection.lcl_port;
  init_ack_chunk->sctp_hdr.dst_port =
    sctp_conn->sub_conn[idx].connection.rmt_port;
  /* the sctp_conn->verification_tag is already in network byte-order (being a copy of the init_tag coming with the INIT chunk) */
  init_ack_chunk->sctp_hdr.verification_tag = sctp_conn->remote_tag;
  init_ack_chunk->initial_tsn =
    clib_host_to_net_u32 (sctp_conn->local_initial_tsn);
  SCTP_CONN_TRACKING_DBG ("init_ack_chunk->initial_tsn = %u",
			  init_ack_chunk->initial_tsn);

  vnet_sctp_set_chunk_type (&init_ack_chunk->chunk_hdr, INIT_ACK);
  vnet_sctp_set_chunk_length (&init_ack_chunk->chunk_hdr, chunk_len);

  init_ack_chunk->initiate_tag = sctp_conn->local_tag;

  init_ack_chunk->a_rwnd =
    clib_host_to_net_u32 (sctp_conn->sub_conn[idx].cwnd);
  init_ack_chunk->inboud_streams_count =
    clib_host_to_net_u16 (INBOUND_STREAMS_COUNT);
  init_ack_chunk->outbound_streams_count =
    clib_host_to_net_u16 (OUTBOUND_STREAMS_COUNT);

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

/**
 * Convert buffer to INIT-ACK
 */
void
sctp_prepare_initack_chunk (sctp_connection_t * sctp_conn, u8 idx,
			    vlib_buffer_t * b, ip4_address_t * ip4_addr,
			    u8 add_ip4, ip6_address_t * ip6_addr, u8 add_ip6)
{
  vlib_main_t *vm = vlib_get_main ();
  sctp_ipv4_addr_param_t *ip4_param = 0;
  sctp_ipv6_addr_param_t *ip6_param = 0;
  u32 random_seed = random_default_seed ();

  sctp_reuse_buffer (vm, b);

  /* The minimum size of the message is given by the sctp_init_ack_chunk_t */
  u16 alloc_bytes =
    sizeof (sctp_init_ack_chunk_t) + sizeof (sctp_state_cookie_param_t);

  if (PREDICT_FALSE (add_ip4 == 1))
    {
      /* Create room for variable-length fields in the INIT_ACK chunk */
      alloc_bytes += SCTP_IPV4_ADDRESS_TYPE_LENGTH;
    }
  if (PREDICT_FALSE (add_ip6 == 1))
    {
      /* Create room for variable-length fields in the INIT_ACK chunk */
      alloc_bytes += SCTP_IPV6_ADDRESS_TYPE_LENGTH;
    }

  if (sctp_conn->sub_conn[idx].connection.is_ip4)
    alloc_bytes += sizeof (sctp_ipv4_addr_param_t);
  else
    alloc_bytes += sizeof (sctp_ipv6_addr_param_t);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_init_ack_chunk_t *init_ack_chunk =
    vlib_buffer_push_uninit (b, alloc_bytes);

  u16 pointer_offset = sizeof (sctp_init_ack_chunk_t);

  /* Create State Cookie parameter */
  sctp_state_cookie_param_t *state_cookie_param =
    (sctp_state_cookie_param_t *) ((char *) init_ack_chunk + pointer_offset);

  state_cookie_param->param_hdr.type =
    clib_host_to_net_u16 (SCTP_STATE_COOKIE_TYPE);
  state_cookie_param->param_hdr.length =
    clib_host_to_net_u16 (sizeof (sctp_state_cookie_param_t));
  state_cookie_param->creation_time = clib_host_to_net_u64 (sctp_time_now ());
  state_cookie_param->cookie_lifespan =
    clib_host_to_net_u32 (SCTP_VALID_COOKIE_LIFE);

  sctp_compute_mac (sctp_conn, state_cookie_param);

  pointer_offset += sizeof (sctp_state_cookie_param_t);

  if (PREDICT_TRUE (ip4_addr != NULL))
    {
      sctp_ipv4_addr_param_t *ipv4_addr =
	(sctp_ipv4_addr_param_t *) init_ack_chunk + pointer_offset;

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
	(sctp_ipv6_addr_param_t *) init_ack_chunk + pointer_offset;

      ipv6_addr->param_hdr.type =
	clib_host_to_net_u16 (SCTP_IPV6_ADDRESS_TYPE);
      ipv6_addr->param_hdr.length =
	clib_host_to_net_u16 (SCTP_IPV6_ADDRESS_TYPE_LENGTH);
      ipv6_addr->address.as_u64[0] = ip6_addr->as_u64[0];
      ipv6_addr->address.as_u64[1] = ip6_addr->as_u64[1];

      pointer_offset += SCTP_IPV6_ADDRESS_TYPE_LENGTH;
    }

  if (sctp_conn->sub_conn[idx].connection.is_ip4)
    {
      ip4_param = (sctp_ipv4_addr_param_t *) init_ack_chunk + pointer_offset;
      ip4_param->address.as_u32 =
	sctp_conn->sub_conn[idx].connection.lcl_ip.ip4.as_u32;

      pointer_offset += sizeof (sctp_ipv4_addr_param_t);
    }
  else
    {
      ip6_param = (sctp_ipv6_addr_param_t *) init_ack_chunk + pointer_offset;
      ip6_param->address.as_u64[0] =
	sctp_conn->sub_conn[idx].connection.lcl_ip.ip6.as_u64[0];
      ip6_param->address.as_u64[1] =
	sctp_conn->sub_conn[idx].connection.lcl_ip.ip6.as_u64[1];

      pointer_offset += sizeof (sctp_ipv6_addr_param_t);
    }

  /* src_port & dst_port are already in network byte-order */
  init_ack_chunk->sctp_hdr.checksum = 0;
  init_ack_chunk->sctp_hdr.src_port =
    sctp_conn->sub_conn[idx].connection.lcl_port;
  init_ack_chunk->sctp_hdr.dst_port =
    sctp_conn->sub_conn[idx].connection.rmt_port;
  /* the sctp_conn->verification_tag is already in network byte-order (being a copy of the init_tag coming with the INIT chunk) */
  init_ack_chunk->sctp_hdr.verification_tag = sctp_conn->remote_tag;
  init_ack_chunk->initial_tsn =
    clib_host_to_net_u32 (sctp_conn->local_initial_tsn);
  SCTP_CONN_TRACKING_DBG ("init_ack_chunk->initial_tsn = %u",
			  init_ack_chunk->initial_tsn);

  vnet_sctp_set_chunk_type (&init_ack_chunk->chunk_hdr, INIT_ACK);
  vnet_sctp_set_chunk_length (&init_ack_chunk->chunk_hdr, chunk_len);

  init_ack_chunk->initiate_tag =
    clib_host_to_net_u32 (random_u32 (&random_seed));

  init_ack_chunk->a_rwnd =
    clib_host_to_net_u32 (sctp_conn->sub_conn[idx].cwnd);
  init_ack_chunk->inboud_streams_count =
    clib_host_to_net_u16 (INBOUND_STREAMS_COUNT);
  init_ack_chunk->outbound_streams_count =
    clib_host_to_net_u16 (OUTBOUND_STREAMS_COUNT);

  sctp_conn->local_tag = init_ack_chunk->initiate_tag;

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

/**
 * Convert buffer to SHUTDOWN
 */
void
sctp_prepare_shutdown_chunk (sctp_connection_t * sctp_conn, u8 idx,
			     vlib_buffer_t * b)
{
  u16 alloc_bytes = sizeof (sctp_shutdown_association_chunk_t);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_shutdown_association_chunk_t *shutdown_chunk =
    vlib_buffer_push_uninit (b, alloc_bytes);

  shutdown_chunk->sctp_hdr.checksum = 0;
  /* No need of host_to_net conversion, already in net-byte order */
  shutdown_chunk->sctp_hdr.src_port =
    sctp_conn->sub_conn[idx].connection.lcl_port;
  shutdown_chunk->sctp_hdr.dst_port =
    sctp_conn->sub_conn[idx].connection.rmt_port;
  shutdown_chunk->sctp_hdr.verification_tag = sctp_conn->remote_tag;
  vnet_sctp_set_chunk_type (&shutdown_chunk->chunk_hdr, SHUTDOWN);
  vnet_sctp_set_chunk_length (&shutdown_chunk->chunk_hdr, chunk_len);

  shutdown_chunk->cumulative_tsn_ack = sctp_conn->last_rcvd_tsn;

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

/*
 * Send SHUTDOWN
 */
void
sctp_send_shutdown (sctp_connection_t * sctp_conn)
{
  vlib_buffer_t *b;
  u32 bi;
  sctp_main_t *tm = vnet_get_sctp_main ();
  vlib_main_t *vm = vlib_get_main ();

  if (sctp_check_outstanding_data_chunks (sctp_conn) > 0)
    return;

  if (PREDICT_FALSE (sctp_get_free_buffer_index (tm, &bi)))
    return;

  u8 idx = SCTP_PRIMARY_PATH_IDX;

  b = vlib_get_buffer (vm, bi);
  sctp_init_buffer (vm, b);
  sctp_prepare_shutdown_chunk (sctp_conn, idx, b);

  sctp_enqueue_to_output_now (vm, b, bi,
			      sctp_conn->sub_conn[idx].connection.is_ip4);
}

/**
 * Convert buffer to SHUTDOWN_ACK
 */
void
sctp_prepare_shutdown_ack_chunk (sctp_connection_t * sctp_conn, u8 idx,
				 vlib_buffer_t * b)
{
  u16 alloc_bytes = sizeof (sctp_shutdown_association_chunk_t);
  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  sctp_shutdown_ack_chunk_t *shutdown_ack_chunk =
    vlib_buffer_push_uninit (b, alloc_bytes);

  shutdown_ack_chunk->sctp_hdr.checksum = 0;
  /* No need of host_to_net conversion, already in net-byte order */
  shutdown_ack_chunk->sctp_hdr.src_port =
    sctp_conn->sub_conn[idx].connection.lcl_port;
  shutdown_ack_chunk->sctp_hdr.dst_port =
    sctp_conn->sub_conn[idx].connection.rmt_port;
  shutdown_ack_chunk->sctp_hdr.verification_tag = sctp_conn->remote_tag;

  vnet_sctp_set_chunk_type (&shutdown_ack_chunk->chunk_hdr, SHUTDOWN_ACK);
  vnet_sctp_set_chunk_length (&shutdown_ack_chunk->chunk_hdr, chunk_len);

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

/*
 * Send SHUTDOWN_ACK
 */
void
sctp_send_shutdown_ack (sctp_connection_t * sctp_conn, u8 idx,
			vlib_buffer_t * b)
{
  vlib_main_t *vm = vlib_get_main ();

  if (sctp_check_outstanding_data_chunks (sctp_conn) > 0)
    return;

  sctp_reuse_buffer (vm, b);

  sctp_prepare_shutdown_ack_chunk (sctp_conn, idx, b);
}

/**
 * Convert buffer to SACK
 */
void
sctp_prepare_sack_chunk (sctp_connection_t * sctp_conn, u8 idx,
			 vlib_buffer_t * b)
{
  vlib_main_t *vm = vlib_get_main ();

  sctp_reuse_buffer (vm, b);

  u16 alloc_bytes = sizeof (sctp_selective_ack_chunk_t);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_selective_ack_chunk_t *sack = vlib_buffer_push_uninit (b, alloc_bytes);

  sack->sctp_hdr.checksum = 0;
  sack->sctp_hdr.src_port = sctp_conn->sub_conn[idx].connection.lcl_port;
  sack->sctp_hdr.dst_port = sctp_conn->sub_conn[idx].connection.rmt_port;
  sack->sctp_hdr.verification_tag = sctp_conn->remote_tag;
  vnet_sctp_set_chunk_type (&sack->chunk_hdr, SACK);
  vnet_sctp_set_chunk_length (&sack->chunk_hdr, chunk_len);

  sack->cumulative_tsn_ack = sctp_conn->next_tsn_expected;

  sctp_conn->ack_state = 0;

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

/**
 * Convert buffer to HEARTBEAT_ACK
 */
void
sctp_prepare_heartbeat_ack_chunk (sctp_connection_t * sctp_conn, u8 idx,
				  vlib_buffer_t * b)
{
  vlib_main_t *vm = vlib_get_main ();

  u16 alloc_bytes = sizeof (sctp_hb_ack_chunk_t);

  sctp_reuse_buffer (vm, b);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_hb_ack_chunk_t *hb_ack = vlib_buffer_push_uninit (b, alloc_bytes);

  hb_ack->sctp_hdr.checksum = 0;
  /* No need of host_to_net conversion, already in net-byte order */
  hb_ack->sctp_hdr.src_port = sctp_conn->sub_conn[idx].connection.lcl_port;
  hb_ack->sctp_hdr.dst_port = sctp_conn->sub_conn[idx].connection.rmt_port;
  hb_ack->sctp_hdr.verification_tag = sctp_conn->remote_tag;
  hb_ack->hb_info.param_hdr.type = clib_host_to_net_u16 (1);
  hb_ack->hb_info.param_hdr.length =
    clib_host_to_net_u16 (sizeof (hb_ack->hb_info.hb_info));

  vnet_sctp_set_chunk_type (&hb_ack->chunk_hdr, HEARTBEAT_ACK);
  vnet_sctp_set_chunk_length (&hb_ack->chunk_hdr, chunk_len);

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

/**
 * Convert buffer to HEARTBEAT
 */
void
sctp_prepare_heartbeat_chunk (sctp_connection_t * sctp_conn, u8 idx,
			      vlib_buffer_t * b)
{
  u16 alloc_bytes = sizeof (sctp_hb_req_chunk_t);

  /* As per RFC 4960 the chunk_length value does NOT contemplate
   * the size of the first header (see sctp_header_t) and any padding
   */
  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  sctp_hb_req_chunk_t *hb_req = vlib_buffer_push_uninit (b, alloc_bytes);

  hb_req->sctp_hdr.checksum = 0;
  /* No need of host_to_net conversion, already in net-byte order */
  hb_req->sctp_hdr.src_port = sctp_conn->sub_conn[idx].connection.lcl_port;
  hb_req->sctp_hdr.dst_port = sctp_conn->sub_conn[idx].connection.rmt_port;
  hb_req->sctp_hdr.verification_tag = sctp_conn->remote_tag;
  hb_req->hb_info.param_hdr.type = clib_host_to_net_u16 (1);
  hb_req->hb_info.param_hdr.length =
    clib_host_to_net_u16 (sizeof (hb_req->hb_info.hb_info));

  vnet_sctp_set_chunk_type (&hb_req->chunk_hdr, HEARTBEAT);
  vnet_sctp_set_chunk_length (&hb_req->chunk_hdr, chunk_len);

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

void
sctp_send_heartbeat (sctp_connection_t * sctp_conn)
{
  vlib_buffer_t *b;
  u32 bi;
  sctp_main_t *tm = vnet_get_sctp_main ();
  vlib_main_t *vm = vlib_get_main ();

  u8 i;
  u64 now = sctp_time_now ();

  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      if (sctp_conn->sub_conn[i].state == SCTP_SUBCONN_STATE_DOWN)
	continue;

      if (now > (sctp_conn->sub_conn[i].last_seen + SCTP_HB_INTERVAL))
	{
	  if (PREDICT_FALSE (sctp_get_free_buffer_index (tm, &bi)))
	    return;

	  b = vlib_get_buffer (vm, bi);
	  sctp_init_buffer (vm, b);
	  sctp_prepare_heartbeat_chunk (sctp_conn, i, b);

	  sctp_enqueue_to_output_now (vm, b, bi,
				      sctp_conn->sub_conn[i].
				      connection.is_ip4);

	  sctp_conn->sub_conn[i].unacknowledged_hb += 1;
	}
    }
}

/**
 * Convert buffer to SHUTDOWN_COMPLETE
 */
void
sctp_prepare_shutdown_complete_chunk (sctp_connection_t * sctp_conn, u8 idx,
				      vlib_buffer_t * b)
{
  u16 alloc_bytes = sizeof (sctp_shutdown_association_chunk_t);
  alloc_bytes += vnet_sctp_calculate_padding (alloc_bytes);

  u16 chunk_len = alloc_bytes - sizeof (sctp_header_t);

  sctp_shutdown_complete_chunk_t *shutdown_complete =
    vlib_buffer_push_uninit (b, alloc_bytes);

  shutdown_complete->sctp_hdr.checksum = 0;
  /* No need of host_to_net conversion, already in net-byte order */
  shutdown_complete->sctp_hdr.src_port =
    sctp_conn->sub_conn[idx].connection.lcl_port;
  shutdown_complete->sctp_hdr.dst_port =
    sctp_conn->sub_conn[idx].connection.rmt_port;
  shutdown_complete->sctp_hdr.verification_tag = sctp_conn->remote_tag;

  vnet_sctp_set_chunk_type (&shutdown_complete->chunk_hdr, SHUTDOWN_COMPLETE);
  vnet_sctp_set_chunk_length (&shutdown_complete->chunk_hdr, chunk_len);

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;
  vnet_buffer (b)->sctp.subconn_idx = idx;
}

void
sctp_send_shutdown_complete (sctp_connection_t * sctp_conn, u8 idx,
			     vlib_buffer_t * b0)
{
  vlib_main_t *vm = vlib_get_main ();

  if (sctp_check_outstanding_data_chunks (sctp_conn) > 0)
    return;

  sctp_reuse_buffer (vm, b0);

  sctp_prepare_shutdown_complete_chunk (sctp_conn, idx, b0);
}

/*
 *  Send INIT
 */
void
sctp_send_init (sctp_connection_t * sctp_conn)
{
  vlib_buffer_t *b;
  u32 bi;
  sctp_main_t *tm = vnet_get_sctp_main ();
  vlib_main_t *vm = vlib_get_main ();

  if (PREDICT_FALSE (sctp_conn->init_retransmit_err > SCTP_MAX_INIT_RETRANS))
    {
      clib_warning ("Reached MAX_INIT_RETRANS times. Aborting connection.");

      session_stream_connect_notify (&sctp_conn->sub_conn
				     [SCTP_PRIMARY_PATH_IDX].connection, 1);

      sctp_connection_timers_reset (sctp_conn);

      sctp_connection_cleanup (sctp_conn);

      return;
    }

  if (PREDICT_FALSE (sctp_get_free_buffer_index (tm, &bi)))
    return;

  b = vlib_get_buffer (vm, bi);
  u8 idx = SCTP_PRIMARY_PATH_IDX;

  sctp_init_buffer (vm, b);
  sctp_prepare_init_chunk (sctp_conn, idx, b);

  sctp_push_ip_hdr (tm, &sctp_conn->sub_conn[idx], b);
  sctp_enqueue_to_ip_lookup (vm, b, bi, sctp_conn->sub_conn[idx].c_is_ip4,
			     sctp_conn->sub_conn[idx].c_fib_index);

  /* Start the T1_INIT timer */
  sctp_timer_set (sctp_conn, idx, SCTP_TIMER_T1_INIT,
		  sctp_conn->sub_conn[idx].RTO);

  /* Change state to COOKIE_WAIT */
  sctp_conn->state = SCTP_STATE_COOKIE_WAIT;

  /* Measure RTT with this */
  sctp_conn->sub_conn[idx].rtt_ts = sctp_time_now ();
}

/**
 * Push SCTP header and update connection variables
 */
static void
sctp_push_hdr_i (sctp_connection_t * sctp_conn, vlib_buffer_t * b,
		 sctp_state_t next_state)
{
  u16 data_len =
    b->current_length + b->total_length_not_including_first_buffer;

  ASSERT (!b->total_length_not_including_first_buffer
	  || (b->flags & VLIB_BUFFER_NEXT_PRESENT));

  SCTP_ADV_DBG_OUTPUT ("b->current_length = %u, "
		       "b->current_data = %p "
		       "data_len = %u",
		       b->current_length, b->current_data, data_len);

  u16 data_padding = vnet_sctp_calculate_padding (b->current_length);
  if (data_padding > 0)
    {
      u8 *p_tail = vlib_buffer_put_uninit (b, data_padding);
      clib_memset_u8 (p_tail, 0, data_padding);
    }

  u16 bytes_to_add = sizeof (sctp_payload_data_chunk_t);
  u16 chunk_length = data_len + bytes_to_add - sizeof (sctp_header_t);

  sctp_payload_data_chunk_t *data_chunk =
    vlib_buffer_push_uninit (b, bytes_to_add);

  u8 idx = sctp_data_subconn_select (sctp_conn);
  SCTP_DBG_OUTPUT
    ("SCTP_CONN = %p, IDX = %u, S_INDEX = %u, C_INDEX = %u, sctp_conn->[...].LCL_PORT = %u, sctp_conn->[...].RMT_PORT = %u",
     sctp_conn, idx, sctp_conn->sub_conn[idx].connection.s_index,
     sctp_conn->sub_conn[idx].connection.c_index,
     sctp_conn->sub_conn[idx].connection.lcl_port,
     sctp_conn->sub_conn[idx].connection.rmt_port);
  data_chunk->sctp_hdr.checksum = 0;
  data_chunk->sctp_hdr.src_port =
    sctp_conn->sub_conn[idx].connection.lcl_port;
  data_chunk->sctp_hdr.dst_port =
    sctp_conn->sub_conn[idx].connection.rmt_port;
  data_chunk->sctp_hdr.verification_tag = sctp_conn->remote_tag;

  data_chunk->tsn = clib_host_to_net_u32 (sctp_conn->next_tsn);
  data_chunk->stream_id = clib_host_to_net_u16 (0);
  data_chunk->stream_seq = clib_host_to_net_u16 (0);

  vnet_sctp_set_chunk_type (&data_chunk->chunk_hdr, DATA);
  vnet_sctp_set_chunk_length (&data_chunk->chunk_hdr, chunk_length);

  vnet_sctp_set_bbit (&data_chunk->chunk_hdr);
  vnet_sctp_set_ebit (&data_chunk->chunk_hdr);

  SCTP_ADV_DBG_OUTPUT ("POINTER_WITH_DATA = %p, DATA_OFFSET = %u",
		       b->data, b->current_data);

  if (sctp_conn->sub_conn[idx].state != SCTP_SUBCONN_AWAITING_SACK)
    {
      sctp_conn->sub_conn[idx].state = SCTP_SUBCONN_AWAITING_SACK;
      sctp_conn->last_unacked_tsn = sctp_conn->next_tsn;
    }

  sctp_conn->next_tsn += data_len;

  u32 inflight = sctp_conn->next_tsn - sctp_conn->last_unacked_tsn;
  /* Section 7.2.2; point (3) */
  if (sctp_conn->sub_conn[idx].partially_acked_bytes >=
      sctp_conn->sub_conn[idx].cwnd
      && inflight >= sctp_conn->sub_conn[idx].cwnd)
    {
      sctp_conn->sub_conn[idx].cwnd += sctp_conn->sub_conn[idx].PMTU;
      sctp_conn->sub_conn[idx].partially_acked_bytes -=
	sctp_conn->sub_conn[idx].cwnd;
    }

  sctp_conn->sub_conn[idx].last_data_ts = sctp_time_now ();

  vnet_buffer (b)->sctp.connection_index =
    sctp_conn->sub_conn[idx].connection.c_index;

  vnet_buffer (b)->sctp.subconn_idx = idx;
}

u32
sctp_push_header (transport_connection_t * trans_conn, vlib_buffer_t * b)
{
  sctp_connection_t *sctp_conn =
    sctp_get_connection_from_transport (trans_conn);

  SCTP_DBG_OUTPUT ("TRANS_CONN = %p, SCTP_CONN = %p, "
		   "S_INDEX = %u, C_INDEX = %u,"
		   "trans_conn->LCL_PORT = %u, trans_conn->RMT_PORT = %u",
		   trans_conn,
		   sctp_conn,
		   trans_conn->s_index,
		   trans_conn->c_index,
		   trans_conn->lcl_port, trans_conn->rmt_port);

  sctp_push_hdr_i (sctp_conn, b, SCTP_STATE_ESTABLISHED);

  sctp_trajectory_add_start (b, 3);

  return 0;
}

u32
sctp_prepare_data_retransmit (sctp_connection_t * sctp_conn,
			      u8 idx,
			      u32 offset,
			      u32 max_deq_bytes, vlib_buffer_t ** b)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  vlib_main_t *vm = vlib_get_main ();
  int n_bytes = 0;
  u32 bi, available_bytes, seg_size;
  u8 *data;

  ASSERT (sctp_conn->state >= SCTP_STATE_ESTABLISHED);
  ASSERT (max_deq_bytes != 0);

  /*
   * Make sure we can retransmit something
   */
  available_bytes =
    session_tx_fifo_max_dequeue (&sctp_conn->sub_conn[idx].connection);
  ASSERT (available_bytes >= offset);
  available_bytes -= offset;
  if (!available_bytes)
    return 0;
  max_deq_bytes = clib_min (sctp_conn->sub_conn[idx].cwnd, max_deq_bytes);
  max_deq_bytes = clib_min (available_bytes, max_deq_bytes);

  seg_size = max_deq_bytes;

  /*
   * Allocate and fill in buffer(s)
   */

  if (PREDICT_FALSE (sctp_get_free_buffer_index (tm, &bi)))
    return 0;
  *b = vlib_get_buffer (vm, bi);
  data = sctp_init_buffer (vm, *b);

  /* Easy case, buffer size greater than mss */
  if (PREDICT_TRUE (seg_size <= tm->bytes_per_buffer))
    {
      n_bytes =
	stream_session_peek_bytes (&sctp_conn->sub_conn[idx].connection, data,
				   offset, max_deq_bytes);
      ASSERT (n_bytes == max_deq_bytes);
      b[0]->current_length = n_bytes;
      sctp_push_hdr_i (sctp_conn, *b, sctp_conn->state);
    }

  return n_bytes;
}

void
sctp_data_retransmit (sctp_connection_t * sctp_conn)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *b = 0;
  u32 bi, n_bytes = 0;

  u8 idx = sctp_data_subconn_select (sctp_conn);

  SCTP_DBG_OUTPUT
    ("SCTP_CONN = %p, IDX = %u, S_INDEX = %u, C_INDEX = %u, sctp_conn->[...].LCL_PORT = %u, sctp_conn->[...].RMT_PORT = %u",
     sctp_conn, idx, sctp_conn->sub_conn[idx].connection.s_index,
     sctp_conn->sub_conn[idx].connection.c_index,
     sctp_conn->sub_conn[idx].connection.lcl_port,
     sctp_conn->sub_conn[idx].connection.rmt_port);

  if (sctp_conn->state >= SCTP_STATE_ESTABLISHED)
    {
      return;
    }

  n_bytes =
    sctp_prepare_data_retransmit (sctp_conn, idx, 0,
				  sctp_conn->sub_conn[idx].cwnd, &b);
  if (n_bytes > 0)
    SCTP_DBG_OUTPUT ("We have data (%u bytes) to retransmit", n_bytes);

  bi = vlib_get_buffer_index (vm, b);

  sctp_enqueue_to_output_now (vm, b, bi,
			      sctp_conn->sub_conn[idx].connection.is_ip4);

  return;
}

#if SCTP_DEBUG_STATE_MACHINE
always_inline u8
sctp_validate_output_state_machine (sctp_connection_t * sctp_conn,
				    u8 chunk_type)
{
  u8 result = 0;
  switch (sctp_conn->state)
    {
    case SCTP_STATE_CLOSED:
      if (chunk_type != INIT && chunk_type != INIT_ACK)
	result = 1;
      break;
    case SCTP_STATE_ESTABLISHED:
      if (chunk_type != DATA && chunk_type != HEARTBEAT &&
	  chunk_type != HEARTBEAT_ACK && chunk_type != SACK &&
	  chunk_type != COOKIE_ACK && chunk_type != SHUTDOWN)
	result = 1;
      break;
    case SCTP_STATE_COOKIE_WAIT:
      if (chunk_type != COOKIE_ECHO)
	result = 1;
      break;
    case SCTP_STATE_SHUTDOWN_SENT:
      if (chunk_type != SHUTDOWN_COMPLETE)
	result = 1;
      break;
    case SCTP_STATE_SHUTDOWN_RECEIVED:
      if (chunk_type != SHUTDOWN_ACK)
	result = 1;
      break;
    }
  return result;
}
#endif

always_inline u8
sctp_is_retransmitting (sctp_connection_t * sctp_conn, u8 idx)
{
  return sctp_conn->sub_conn[idx].is_retransmitting;
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
	  sctp_header_t *sctp_hdr = 0;
	  sctp_connection_t *sctp_conn;
	  sctp_tx_trace_t *t0;
	  sctp_header_t *th0 = 0;
	  u32 error0 = SCTP_ERROR_PKTS_SENT, next0 =
	    SCTP_OUTPUT_NEXT_IP_LOOKUP;

#if SCTP_DEBUG_STATE_MACHINE
	  u16 packet_length = 0;
#endif

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sctp_conn =
	    sctp_connection_get (vnet_buffer (b0)->sctp.connection_index,
				 my_thread_index);

	  if (PREDICT_FALSE (sctp_conn == 0))
	    {
	      error0 = SCTP_ERROR_INVALID_CONNECTION;
	      next0 = SCTP_OUTPUT_NEXT_DROP;
	      goto done;
	    }

	  u8 idx = vnet_buffer (b0)->sctp.subconn_idx;

	  th0 = vlib_buffer_get_current (b0);

	  if (is_ip4)
	    {
	      ip4_header_t *iph4 = vlib_buffer_push_ip4 (vm,
							 b0,
							 &sctp_conn->sub_conn
							 [idx].connection.
							 lcl_ip.ip4,
							 &sctp_conn->
							 sub_conn
							 [idx].connection.
							 rmt_ip.ip4,
							 IP_PROTOCOL_SCTP, 1);

	      u32 checksum = ip4_sctp_compute_checksum (vm, b0, iph4);

	      sctp_hdr = ip4_next_header (iph4);
	      sctp_hdr->checksum = checksum;

	      vnet_buffer (b0)->l4_hdr_offset = (u8 *) th0 - b0->data;

#if SCTP_DEBUG_STATE_MACHINE
	      packet_length = clib_net_to_host_u16 (iph4->length);
#endif
	    }
	  else
	    {
	      ip6_header_t *iph6 = vlib_buffer_push_ip6 (vm,
							 b0,
							 &sctp_conn->sub_conn
							 [idx].
							 connection.lcl_ip.
							 ip6,
							 &sctp_conn->sub_conn
							 [idx].
							 connection.rmt_ip.
							 ip6,
							 IP_PROTOCOL_SCTP);

	      int bogus = ~0;
	      u32 checksum = ip6_sctp_compute_checksum (vm, b0, iph6, &bogus);
	      ASSERT (!bogus);

	      sctp_hdr = ip6_next_header (iph6);
	      sctp_hdr->checksum = checksum;

	      vnet_buffer (b0)->l3_hdr_offset = (u8 *) iph6 - b0->data;
	      vnet_buffer (b0)->l4_hdr_offset = (u8 *) th0 - b0->data;

#if SCTP_DEBUG_STATE_MACHINE
	      packet_length = clib_net_to_host_u16 (iph6->payload_length);
#endif
	    }

	  sctp_full_hdr_t *full_hdr = (sctp_full_hdr_t *) sctp_hdr;
	  u8 chunk_type = vnet_sctp_get_chunk_type (&full_hdr->common_hdr);
	  if (chunk_type >= UNKNOWN)
	    {
	      clib_warning
		("Trying to send an unrecognized chunk... something is really bad.");
	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = SCTP_OUTPUT_NEXT_DROP;
	      goto done;
	    }

#if SCTP_DEBUG_STATE_MACHINE
	  u8 is_valid =
	    (sctp_conn->sub_conn[idx].connection.lcl_port ==
	     sctp_hdr->src_port
	     || sctp_conn->sub_conn[idx].connection.lcl_port ==
	     sctp_hdr->dst_port)
	    && (sctp_conn->sub_conn[idx].connection.rmt_port ==
		sctp_hdr->dst_port
		|| sctp_conn->sub_conn[idx].connection.rmt_port ==
		sctp_hdr->src_port);

	  if (!is_valid)
	    {
	      SCTP_DBG_STATE_MACHINE ("BUFFER IS INCORRECT: conn_index = %u, "
				      "packet_length = %u, "
				      "chunk_type = %u [%s], "
				      "connection.lcl_port = %u, sctp_hdr->src_port = %u, "
				      "connection.rmt_port = %u, sctp_hdr->dst_port = %u",
				      sctp_conn->sub_conn[idx].
				      connection.c_index, packet_length,
				      chunk_type,
				      sctp_chunk_to_string (chunk_type),
				      sctp_conn->sub_conn[idx].
				      connection.lcl_port, sctp_hdr->src_port,
				      sctp_conn->sub_conn[idx].
				      connection.rmt_port,
				      sctp_hdr->dst_port);

	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = SCTP_OUTPUT_NEXT_DROP;
	      goto done;
	    }
#endif
	  SCTP_DBG_STATE_MACHINE
	    ("SESSION_INDEX = %u, CONN_INDEX = %u, CURR_CONN_STATE = %u (%s), "
	     "CHUNK_TYPE = %s, " "SRC_PORT = %u, DST_PORT = %u",
	     sctp_conn->sub_conn[idx].connection.s_index,
	     sctp_conn->sub_conn[idx].connection.c_index,
	     sctp_conn->state, sctp_state_to_string (sctp_conn->state),
	     sctp_chunk_to_string (chunk_type), full_hdr->hdr.src_port,
	     full_hdr->hdr.dst_port);

	  /* Let's make sure the state-machine does not send anything crazy */
#if SCTP_DEBUG_STATE_MACHINE
	  if (sctp_validate_output_state_machine (sctp_conn, chunk_type) != 0)
	    {
	      SCTP_DBG_STATE_MACHINE
		("Sending the wrong chunk (%s) based on state-machine status (%s)",
		 sctp_chunk_to_string (chunk_type),
		 sctp_state_to_string (sctp_conn->state));

	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = SCTP_OUTPUT_NEXT_DROP;
	      goto done;

	    }
#endif

	  /* Karn's algorithm: RTT measurements MUST NOT be made using
	   * packets that were retransmitted
	   */
	  if (!sctp_is_retransmitting (sctp_conn, idx))
	    {
	      /* Measure RTT with this */
	      if (chunk_type == DATA
		  && sctp_conn->sub_conn[idx].RTO_pending == 0)
		{
		  sctp_conn->sub_conn[idx].RTO_pending = 1;
		  sctp_conn->sub_conn[idx].rtt_ts = sctp_time_now ();
		}
	      else
		sctp_conn->sub_conn[idx].rtt_ts = sctp_time_now ();
	    }

	  /* Let's take care of TIMERS */
	  switch (chunk_type)
	    {
	    case COOKIE_ECHO:
	      {
		sctp_conn->state = SCTP_STATE_COOKIE_ECHOED;
		break;
	      }
	    case DATA:
	      {
		SCTP_ADV_DBG_OUTPUT ("PACKET_LENGTH = %u", packet_length);

		sctp_timer_update (sctp_conn, idx, SCTP_TIMER_T3_RXTX,
				   sctp_conn->sub_conn[idx].RTO);
		break;
	      }
	    case SHUTDOWN:
	      {
		/* Start the SCTP_TIMER_T2_SHUTDOWN timer */
		sctp_timer_set (sctp_conn, idx, SCTP_TIMER_T2_SHUTDOWN,
				sctp_conn->sub_conn[idx].RTO);
		sctp_conn->state = SCTP_STATE_SHUTDOWN_SENT;
		break;
	      }
	    case SHUTDOWN_ACK:
	      {
		/* Start the SCTP_TIMER_T2_SHUTDOWN timer */
		sctp_timer_set (sctp_conn, idx, SCTP_TIMER_T2_SHUTDOWN,
				sctp_conn->sub_conn[idx].RTO);
		sctp_conn->state = SCTP_STATE_SHUTDOWN_ACK_SENT;
		break;
	      }
	    case SHUTDOWN_COMPLETE:
	      {
		sctp_conn->state = SCTP_STATE_CLOSED;
		break;
	      }
	    }

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
	    sctp_conn->sub_conn[idx].c_fib_index;

	  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

	  SCTP_DBG_STATE_MACHINE
	    ("SESSION_INDEX = %u, CONNECTION_INDEX = %u, " "NEW_STATE = %s, "
	     "CHUNK_SENT = %s", sctp_conn->sub_conn[idx].connection.s_index,
	     sctp_conn->sub_conn[idx].connection.c_index,
	     sctp_state_to_string (sctp_conn->state),
	     sctp_chunk_to_string (chunk_type));

	  vnet_sctp_common_hdr_params_host_to_net (&full_hdr->common_hdr);

	done:
	  b0->error = node->errors[error0];
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      if (th0)
		{
		  clib_memcpy_fast (&t0->sctp_header, th0,
				    sizeof (t0->sctp_header));
		}
	      else
		{
		  clib_memset (&t0->sctp_header, 0, sizeof (t0->sctp_header));
		}
	      clib_memcpy_fast (&t0->sctp_connection, sctp_conn,
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
