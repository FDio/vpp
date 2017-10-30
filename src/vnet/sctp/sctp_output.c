#include "sctp.h"
#include "sctp_crc32c.h"

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
  return 0;
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
sctp_make_init (sctp_connection_t * tc, vlib_buffer_t * b)
{
  vlib_buffer_push_sctp (b, tc->c_lcl_port, tc->c_rmt_port, tc->iss,
			 tc->rcv_nxt, sizeof (sctp_header_t));
  vnet_buffer (b)->sctp.connection_index = tc->c_c_index;
}

/**
 *  Send INIT
 *
 *  Builds a INIT packet for a half-open connection and sends it to ipx_lookup.
 *  The packet is not forwarded through tcpx_output to avoid doing lookups
 *  in the half_open pool.
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
  sctp_make_init (tc, b);

  /* Measure RTT with this */
  tc->rtt_ts = sctp_time_now ();
  tc->rtt_seq = tc->snd_nxt;
  tc->rto_boff = 0;

  /* Set the connection establishment timer */
  sctp_timer_set (tc, SCTP_TIMER_T1_INIT, SCTP_RTO_INIT);

  sctp_push_ip_hdr (tm, tc, b);
  sctp_enqueue_to_ip_lookup (vm, b, bi, tc->c_is_ip4);
}

u32
stcp_push_header (transport_connection_t * tconn, vlib_buffer_t * b)
{
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
