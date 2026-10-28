/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016-2020 Cisco and/or its affiliates.
 */

#include <math.h>
#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

udp_main_t udp_main;

static void
udp_connection_register_port (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = &udp_main;
  u16 *n;

  /* Setup udp protocol -> next index sparse vector mapping. Do not setup
   * udp_dst_port_info_t as that is used to distinguish between external
   * and transport consumed ports */

  n = udp_dst_port_get_slot (um, lcl_port, is_ip4);

  n[0] = um->local_to_input_edge[is_ip4];

  __atomic_add_fetch (&um->transport_ports_refcnt[is_ip4][lcl_port], 1,
		      __ATOMIC_RELAXED);
}

void
udp_connection_share_port (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = &udp_main;
  __atomic_add_fetch (&um->transport_ports_refcnt[is_ip4][lcl_port], 1,
		      __ATOMIC_RELAXED);
}

static void
udp_connection_unregister_port (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = &udp_main;
  u16 *n;

  /* Needed because listeners are not tracked as local endpoints */
  if (__atomic_sub_fetch (&um->transport_ports_refcnt[is_ip4][lcl_port], 1,
			  __ATOMIC_RELAXED))
    return;

  n = udp_dst_port_get_slot (um, lcl_port, is_ip4);

  n[0] = UDP_NO_NODE_SET;
}

udp_connection_t *
udp_connection_alloc (clib_thread_index_t thread_index)
{
  udp_worker_t *wrk = udp_worker_get (thread_index);
  udp_connection_t *uc;

  pool_get_aligned_safe (wrk->connections, uc, CLIB_CACHE_LINE_BYTES);

  clib_memset (uc, 0, sizeof (*uc));
  uc->c_c_index = uc - wrk->connections;
  uc->c_thread_index = thread_index;
  uc->c_proto = TRANSPORT_PROTO_UDP;
  return uc;
}

void
udp_connection_free (udp_connection_t * uc)
{
  udp_worker_t *wrk = udp_worker_get (uc->c_thread_index);

  clib_spinlock_free (&uc->rx_lock);
  if (CLIB_DEBUG)
    clib_memset (uc, 0xFA, sizeof (*uc));
  pool_put (wrk->connections, uc);
}

static void
udp_connection_cleanup (udp_connection_t * uc)
{
  transport_release_local_endpoint (TRANSPORT_PROTO_UDP, uc->c_fib_index,
				    &uc->c_lcl_ip, uc->c_lcl_port);
  udp_connection_unregister_port (uc->c_lcl_port, uc->c_is_ip4);
  udp_connection_free (uc);
}

void
udp_connection_delete (udp_connection_t * uc)
{
  session_transport_delete_request (&uc->connection, udp_connection_cleanup);
}

static void
udp_handle_cleanups (void *args)
{
  clib_thread_index_t thread_index = (u32) pointer_to_uword (args);
  udp_connection_t *uc;
  udp_worker_t *wrk;
  u32 *uc_index;

  wrk = udp_worker_get (thread_index);
  vec_foreach (uc_index, wrk->pending_cleanups)
    {
      uc = udp_connection_get (*uc_index, thread_index);
      udp_connection_delete (uc);
    }
  vec_reset_length (wrk->pending_cleanups);
}

static void
udp_connection_program_cleanup (udp_connection_t *uc)
{
  uword thread_index = uc->c_thread_index;
  udp_worker_t *wrk;

  wrk = udp_worker_get (uc->c_thread_index);
  vec_add1 (wrk->pending_cleanups, uc->c_c_index);

  if (vec_len (wrk->pending_cleanups) == 1)
    session_send_rpc_evt_to_thread_force (
      thread_index, udp_handle_cleanups,
      uword_to_pointer (thread_index, void *));
}

static u8
udp_connection_port_used_extern (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = vnet_get_udp_main ();
  udp_dst_port_info_t *pi;

  pi = udp_get_dst_port_info (um, lcl_port, is_ip4);
  return (pi && udp_is_valid_dst_port (lcl_port, is_ip4));
}

static u16
udp_default_mtu (udp_main_t * um, u8 is_ip4)
{
  u16 ip_hlen = is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t);
  return (um->default_mtu - sizeof (udp_header_t) - ip_hlen);
}

static u32
udp_session_bind (u32 session_index, transport_endpoint_cfg_t *lcl)
{
  udp_main_t *um = vnet_get_udp_main ();
  transport_endpoint_cfg_t *lcl_ext;
  udp_connection_t *listener;
  void *iface_ip;

  if (udp_connection_port_used_extern (clib_net_to_host_u16 (lcl->port),
				       lcl->is_ip4))
    {
      clib_warning ("port already used");
      return SESSION_E_PORTINUSE;
    }

  listener = udp_connection_alloc (0);
  listener->c_lcl_port = lcl->port;

  /* If we are provided a sw_if_index, bind using one of its ips */
  if (ip_is_zero (&lcl->ip, 1) && lcl->sw_if_index != ENDPOINT_INVALID_INDEX)
    {
      if ((iface_ip = ip_interface_get_first_ip (lcl->sw_if_index,
						 lcl->is_ip4)))
	ip_set (&lcl->ip, iface_ip, lcl->is_ip4);
    }
  ip_copy (&listener->c_lcl_ip, &lcl->ip, lcl->is_ip4);
  listener->c_is_ip4 = lcl->is_ip4;
  listener->c_proto = TRANSPORT_PROTO_UDP;
  listener->c_s_index = session_index;
  listener->c_fib_index = lcl->fib_index;
  listener->c_dscp = lcl->dscp;
  listener->mss =
    lcl->mss ? lcl->mss : udp_default_mtu (um, listener->c_is_ip4);
  listener->flags |= UDP_CONN_F_OWNS_PORT | UDP_CONN_F_LISTEN;
  lcl_ext = (transport_endpoint_cfg_t *) lcl;
  if (lcl_ext->transport_flags & TRANSPORT_CFG_F_CONNECTED)
    listener->flags |= UDP_CONN_F_CONNECTED;
  else
    listener->c_flags |= TRANSPORT_CONNECTION_F_CLESS;
  clib_spinlock_init (&listener->rx_lock);
  if (!um->csum_offload)
    listener->cfg_flags |= UDP_CFG_F_NO_CSUM_OFFLOAD;
  listener->start_ts = transport_time_now (listener->c_thread_index);

  udp_connection_register_port (listener->c_lcl_port, lcl->is_ip4);
  return listener->c_c_index;
}

static u32
udp_session_unbind (u32 listener_index)
{
  udp_connection_t *listener;

  listener = udp_listener_get (listener_index);
  udp_connection_unregister_port (listener->c_lcl_port, listener->c_is_ip4);
  clib_spinlock_free (&listener->rx_lock);
  udp_connection_free (listener);
  return 0;
}

static transport_connection_t *
udp_session_get_listener (u32 listener_index)
{
  udp_connection_t *us;

  us = udp_listener_get (listener_index);
  return &us->connection;
}

always_inline u16
udp_compute_checksum (vlib_main_t *vm, vlib_buffer_t *b, u8 csum_offload,
		      u8 is_ip4)
{
  u16 csum = 0;

  if (csum_offload)
    vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
  else
    {
      if (is_ip4)
	csum =
	  ip4_tcp_udp_compute_checksum (vm, b, vlib_buffer_get_current (b));
      else
	{
	  int bogus = 0;
	  csum = ip6_tcp_udp_icmp_compute_checksum (
	    vm, b, vlib_buffer_get_current (b), &bogus);
	}
    }

  return csum;
}

always_inline u32
udp_push_one_header (vlib_main_t *vm, udp_connection_t *uc, vlib_buffer_t *b,
		     u8 is_cless)
{
  udp_header_t *uh;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  /* reuse tcp medatada for now */
  vnet_buffer (b)->tcp.connection_index = uc->c_c_index;

  uc->bytes_out += vlib_buffer_length_in_chain (vm, b);
  uc->dgrams_out += 1;

  if (!is_cless)
    {
      uh = vlib_buffer_push_udp (b, uc->c_lcl_port, uc->c_rmt_port);

      if (uc->c_is_ip4)
	vlib_buffer_push_ip4_custom (vm, b, &uc->c_lcl_ip4, &uc->c_rmt_ip4,
				     IP_PROTOCOL_UDP, udp_csum_offload (uc),
				     0 /* is_df */, uc->c_dscp);
      else
	vlib_buffer_push_ip6 (vm, b, &uc->c_lcl_ip6, &uc->c_rmt_ip6,
			      IP_PROTOCOL_UDP);

      vnet_buffer (b)->tcp.flags = 0;
    }
  else
    {
      u8 *data = vlib_buffer_get_current (b);
      session_dgram_hdr_t hdr;

      hdr = *(session_dgram_hdr_t *) (data - sizeof (hdr));

      /* Local port assumed to be bound, not overwriting it */
      uh = vlib_buffer_push_udp (b, uc->c_lcl_port, hdr.rmt_port);

      if (uc->c_is_ip4)
	vlib_buffer_push_ip4_custom (vm, b, &hdr.lcl_ip.ip4, &hdr.rmt_ip.ip4,
				     IP_PROTOCOL_UDP, udp_csum_offload (uc),
				     0 /* is_df */, uc->c_dscp);
      else
	vlib_buffer_push_ip6 (vm, b, &hdr.lcl_ip.ip6, &hdr.rmt_ip.ip6,
			      IP_PROTOCOL_UDP);

      /* Not connected udp session. Mark buffer for custom handling in
       * udp_output */
      vnet_buffer (b)->tcp.flags |= UDP_CONN_F_LISTEN;
    }

  uh->checksum =
    udp_compute_checksum (vm, b, udp_csum_offload (uc), uc->c_is_ip4);

  return 0;
}

always_inline void
udp_push_header_batch (udp_connection_t *uc, vlib_buffer_t **bs, u32 n_bufs,
		       u8 is_cless)
{
  vlib_main_t *vm = vlib_get_main ();

  while (n_bufs >= 4)
    {
      vlib_prefetch_buffer_header (bs[2], STORE);
      vlib_prefetch_buffer_header (bs[3], STORE);

      udp_push_one_header (vm, uc, bs[0], is_cless);
      udp_push_one_header (vm, uc, bs[1], is_cless);

      n_bufs -= 2;
      bs += 2;
    }
  while (n_bufs)
    {
      if (n_bufs > 1)
	vlib_prefetch_buffer_header (bs[1], STORE);

      udp_push_one_header (vm, uc, bs[0], is_cless);

      n_bufs -= 1;
      bs += 1;
    }
}

static u32
udp_push_header (transport_connection_t *tc, vlib_buffer_t **bs, u32 n_bufs, u32 available_bytes)
{
  udp_connection_t *uc;

  uc = udp_connection_from_transport (tc);
  if (uc->flags & UDP_CONN_F_CONNECTED)
    udp_push_header_batch (uc, bs, n_bufs, 0 /* is_cless */);
  else
    udp_push_header_batch (uc, bs, n_bufs, 1 /* is_cless */);

  if (PREDICT_FALSE (uc->flags & UDP_CONN_F_CLOSING))
    {
      if (!transport_tx_fifo_has_dgram (&uc->connection))
	udp_connection_program_cleanup (uc);
    }

  return 0;
}

static transport_connection_t *
udp_session_get (u32 connection_index, clib_thread_index_t thread_index)
{
  udp_connection_t *uc;
  uc = udp_connection_get (connection_index, thread_index);
  if (uc)
    return &uc->connection;
  return 0;
}

static void
udp_session_close (u32 connection_index, clib_thread_index_t thread_index)
{
  udp_connection_t *uc;

  uc = udp_connection_get (connection_index, thread_index);
  if (!uc || (uc->flags & UDP_CONN_F_MIGRATED))
    return;

  if (!transport_tx_fifo_has_dgram (&uc->connection))
    udp_connection_program_cleanup (uc);
  else
    uc->flags |= UDP_CONN_F_CLOSING;
}

static void
udp_session_cleanup (u32 connection_index, clib_thread_index_t thread_index)
{
  udp_connection_t *uc;
  uc = udp_connection_get (connection_index, thread_index);
  if (!uc)
    return;
  if (uc->flags & UDP_CONN_F_MIGRATED)
    udp_connection_free (uc);
  else
    udp_connection_cleanup (uc);
}

static int
udp_session_send_params (transport_connection_t * tconn,
			 transport_send_params_t * sp)
{
  udp_connection_t *uc;

  uc = udp_connection_from_transport (tconn);

  /* No constraint on TX window */
  sp->snd_space = ~0;
  /* TODO figure out MTU of output interface */
  sp->snd_mss = uc->mss;
  sp->tx_offset = 0;
  sp->flags = 0;
  return 0;
}

/*
 * Datagram tx
 */

typedef struct udp_tx_burst_
{
  session_t *s;
  transport_send_params_t *sp;
  session_dgram_hdr_t hdr;
  u32 max_dequeue;
  u32 left_to_snd;
  u32 max_len_to_snd;
  u16 deq_per_first_buf;
  u16 deq_per_buf;
  u16 n_segs;
  u16 n_bufs_needed;
  u8 n_bufs_per_seg;
} udp_tx_burst_t;

/* Size a burst of at most max_segs segments from the first dgram in the tx
 * fifo and the dgrams of the same length that follow it */
static void
udp_tx_burst_init (vlib_main_t *vm, udp_tx_burst_t *tb, u32 max_segs)
{
  u32 n_bytes_per_buf, n_bytes_per_seg, len, chain_limit;
  transport_send_params_t *sp = tb->sp;
  svm_fifo_t *f = tb->s->tx_fifo;

  n_bytes_per_buf = vlib_buffer_get_default_data_size (vm);
  tb->max_dequeue = svm_fifo_max_dequeue_cons (f);

  if (tb->max_dequeue <= sizeof (tb->hdr))
    {
      tb->max_len_to_snd = 0;
      return;
    }

  svm_fifo_peek (f, 0, sizeof (tb->hdr), (u8 *) &tb->hdr);
  /* Zero length dgrams not supported */
  if (PREDICT_FALSE (tb->hdr.data_length == 0))
    {
      svm_fifo_dequeue_drop (f, sizeof (tb->hdr));
      tb->max_len_to_snd = 0;
      return;
    }
  /* We cannot be sure apps have not enqueued incomplete dgrams */
  if (PREDICT_FALSE (tb->max_dequeue < tb->hdr.data_length + sizeof (tb->hdr)))
    {
      tb->max_len_to_snd = 0;
      return;
    }
  ASSERT (tb->hdr.data_length > tb->hdr.data_offset);
  len = tb->hdr.data_length - tb->hdr.data_offset;
  sp->snd_mss = clib_min (sp->snd_mss, len);

  if (tb->hdr.gso_size)
    {
      sp->snd_mss = clib_min (sp->snd_mss, tb->hdr.gso_size);
    }

  /* Process multiple dgrams if smaller than min (buf_space, mss).
   * This avoids handling multiple dgrams if they require buffer
   * chains */
  chain_limit = clib_min (n_bytes_per_buf - TRANSPORT_MAX_HDRS_LEN, sp->snd_mss);
  if (tb->hdr.data_length <= chain_limit)
    {
      u32 first_dgram_len, dgram_len, offset, max_offset;
      session_dgram_hdr_t hdr;

      sp->snd_mss = clib_min (sp->snd_mss, len);
      offset = tb->hdr.data_length + sizeof (session_dgram_hdr_t);
      first_dgram_len = len;
      max_offset = clib_min (tb->max_dequeue, 32 << 10);

      while (offset < max_offset)
	{
	  svm_fifo_peek (f, offset, sizeof (tb->hdr), (u8 *) &hdr);
	  dgram_len = hdr.data_length - hdr.data_offset;
	  if (offset + sizeof (hdr) + hdr.data_length > tb->max_dequeue ||
	      first_dgram_len != dgram_len)
	    break;
	  /* Assert here to allow test above with zero length dgrams */
	  ASSERT (hdr.data_length > hdr.data_offset);
	  len += dgram_len;
	  offset += sizeof (hdr) + hdr.data_length;
	}
    }

  tb->max_dequeue = len;

  /* Ensure we're not writing more than transport window allows */
  if (tb->max_dequeue < sp->snd_space)
    {
      /* Constrained by tx queue. Try to send only fully formed segments */
      tb->max_len_to_snd = (tb->max_dequeue > sp->snd_mss) ?
			     (tb->max_dequeue - (tb->max_dequeue % sp->snd_mss)) :
			     tb->max_dequeue;
    }
  else
    {
      tb->max_len_to_snd = sp->snd_space;
    }

  /* Check if we're tx constrained by the node */
  tb->n_segs = ceil ((f64) tb->max_len_to_snd / sp->snd_mss);
  if (tb->n_segs > max_segs)
    {
      tb->n_segs = max_segs;
      tb->max_len_to_snd = max_segs * sp->snd_mss;
    }

  ASSERT (n_bytes_per_buf > TRANSPORT_MAX_HDRS_LEN);
  if (tb->n_segs > 1)
    {
      u32 n_bytes_last_seg, n_bufs_last_seg;

      n_bytes_per_seg = TRANSPORT_MAX_HDRS_LEN + sp->snd_mss;
      n_bytes_last_seg =
	TRANSPORT_MAX_HDRS_LEN + tb->max_len_to_snd - ((tb->n_segs - 1) * sp->snd_mss);
      tb->n_bufs_per_seg = ceil ((f64) n_bytes_per_seg / n_bytes_per_buf);
      n_bufs_last_seg = ceil ((f64) n_bytes_last_seg / n_bytes_per_buf);
      tb->n_bufs_needed = ((tb->n_segs - 1) * tb->n_bufs_per_seg) + n_bufs_last_seg;
    }
  else
    {
      n_bytes_per_seg = TRANSPORT_MAX_HDRS_LEN + tb->max_len_to_snd;
      tb->n_bufs_per_seg = ceil ((f64) n_bytes_per_seg / n_bytes_per_buf);
      tb->n_bufs_needed = tb->n_bufs_per_seg;
    }

  tb->deq_per_buf = clib_min (sp->snd_mss, n_bytes_per_buf);
  tb->deq_per_first_buf = clib_min (sp->snd_mss, n_bytes_per_buf - TRANSPORT_MAX_HDRS_LEN);
}

static_always_inline void
udp_tx_burst_chain_tail (vlib_main_t *vm, udp_worker_t *wrk, udp_tx_burst_t *tb, vlib_buffer_t *b,
			 u16 *n_bufs)
{
  session_dgram_hdr_t *hdr = &tb->hdr;
  svm_fifo_t *f = tb->s->tx_fifo;
  vlib_buffer_t *chain_b, *prev_b;
  u32 chain_bi0, to_deq, left_from_seg;
  int len_to_deq, n_bytes_read;
  u16 deq_now;
  u32 offset;
  u8 *data, j;

  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  b->total_length_not_including_first_buffer = 0;

  chain_b = b;
  left_from_seg = clib_min (tb->sp->snd_mss - b->current_length, tb->left_to_snd);
  to_deq = left_from_seg;
  for (j = 1; j < tb->n_bufs_per_seg; j++)
    {
      prev_b = chain_b;
      len_to_deq = clib_min (to_deq, tb->deq_per_buf);

      *n_bufs -= 1;
      chain_bi0 = wrk->tx_buffers[*n_bufs];
      chain_b = vlib_get_buffer (vm, chain_bi0);
      chain_b->current_data = 0;
      data = vlib_buffer_get_current (chain_b);

      deq_now = clib_min (hdr->data_length - hdr->data_offset, len_to_deq);
      offset = hdr->data_offset + SESSION_CONN_HDR_LEN;
      n_bytes_read = svm_fifo_peek (f, offset, deq_now, data);
      ASSERT (n_bytes_read > 0);

      hdr->data_offset += n_bytes_read;
      if (hdr->data_offset == hdr->data_length)
	{
	  offset = hdr->data_length + SESSION_CONN_HDR_LEN;
	  svm_fifo_dequeue_drop (f, offset);
	  if (to_deq > n_bytes_read)
	    svm_fifo_peek (f, 0, sizeof (*hdr), (u8 *) hdr);
	}
      else if (to_deq == n_bytes_read)
	svm_fifo_overwrite_head (f, (u8 *) hdr, sizeof (session_dgram_pre_hdr_t));

      ASSERT (n_bytes_read == len_to_deq);
      chain_b->current_length = n_bytes_read;
      b->total_length_not_including_first_buffer += chain_b->current_length;

      /* update previous buffer */
      prev_b->next_buffer = chain_bi0;
      prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

      /* update current buffer */
      chain_b->next_buffer = 0;

      to_deq -= n_bytes_read;
      if (to_deq == 0)
	break;
    }
  ASSERT (to_deq == 0 && b->total_length_not_including_first_buffer == left_from_seg);
  tb->left_to_snd -= left_from_seg;
}

static_always_inline void
udp_tx_burst_fill_buffer (vlib_main_t *vm, udp_worker_t *wrk, udp_tx_burst_t *tb, vlib_buffer_t *b,
			  u16 *n_bufs, u8 is_cless)
{
  session_dgram_hdr_t *hdr = &tb->hdr;
  svm_fifo_t *f = tb->s->tx_fifo;
  u32 len_to_deq, offset;
  int n_bytes_read;
  u16 deq_now;
  u8 *data0;

  /*
   * Start with the first buffer in chain
   */
  b->error = 0;
  b->flags = VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->current_data = 0;

  data0 = vlib_buffer_make_headroom (b, TRANSPORT_MAX_HDRS_LEN);
  len_to_deq = clib_min (tb->left_to_snd, tb->deq_per_first_buf);

  ASSERT (hdr->data_length > hdr->data_offset);
  deq_now = clib_min (hdr->data_length - hdr->data_offset, len_to_deq);
  offset = hdr->data_offset + SESSION_CONN_HDR_LEN;
  n_bytes_read = svm_fifo_peek (f, offset, deq_now, data0);
  ASSERT (n_bytes_read > 0);

  /* Peer address for udp_push_one_header */
  if (is_cless)
    clib_memcpy_fast (data0 - sizeof (session_dgram_hdr_t), hdr, sizeof (*hdr));

  hdr->data_offset += n_bytes_read;
  if (hdr->data_offset == hdr->data_length)
    {
      offset = hdr->data_length + SESSION_CONN_HDR_LEN;
      svm_fifo_dequeue_drop (f, offset);
      if (tb->left_to_snd > n_bytes_read)
	{
	  svm_fifo_peek (f, 0, sizeof (*hdr), (u8 *) hdr);
	  ASSERT (hdr->data_length > hdr->data_offset);
	}
    }
  else if (tb->left_to_snd == n_bytes_read)
    svm_fifo_overwrite_head (f, (u8 *) hdr, sizeof (session_dgram_pre_hdr_t));

  b->current_length = n_bytes_read;
  tb->left_to_snd -= n_bytes_read;

  /*
   * Fill in the remaining buffers in the chain, if any
   */
  if (PREDICT_FALSE (tb->n_bufs_per_seg > 1 && tb->left_to_snd))
    udp_tx_burst_chain_tail (vm, wrk, tb, b, n_bufs);
}

/* Send dgrams from the tx fifo in up to max_burst_size packets */
static int
udp_session_custom_tx (void *session, transport_send_params_t *sp)
{
  session_t *s = (session_t *) session;
  udp_worker_t *wrk = udp_worker_get (s->thread_index);
  session_worker_t *swrk = session_main_get_worker (s->thread_index);
  u32 n_left, pbi, bi0, bi1, next_index;
  udp_tx_burst_t _tb, *tb = &_tb;
  vlib_buffer_t *pb, *b0, *b1;
  vlib_main_t *vm = swrk->vm;
  udp_connection_t *uc;
  u16 n_bufs;
  u8 is_cless;

  if (s->session_state == SESSION_STATE_LISTENING)
    uc = udp_listener_get (s->connection_index);
  else
    uc = udp_connection_get (s->connection_index, s->thread_index);

  tb->s = s;
  tb->sp = sp;
  next_index = session_tx_next_index (s);
  is_cless = transport_connection_is_cless (&uc->connection);

  /* No tx window or pacing, so there is always room for a burst */
  udp_session_send_params (&uc->connection, sp);

  /* Check how much we can pull. */
  udp_tx_burst_init (vm, tb, sp->max_burst_size);

  if (PREDICT_FALSE (!tb->max_len_to_snd))
    return 0;

  vec_validate_aligned (wrk->tx_buffers, tb->n_bufs_needed - 1, CLIB_CACHE_LINE_BYTES);
  n_bufs = vlib_buffer_alloc (vm, wrk->tx_buffers, tb->n_bufs_needed);
  if (PREDICT_FALSE (n_bufs < tb->n_bufs_needed))
    {
      if (n_bufs)
	vlib_buffer_free (vm, wrk->tx_buffers, n_bufs);
      sp->flags |= TRANSPORT_SND_F_NO_BUFFERS;
      return 0;
    }

  tb->left_to_snd = tb->max_len_to_snd;
  n_left = tb->n_segs;

  vec_validate (wrk->tx_data_bufs, n_left);

  while (n_left >= 4)
    {
      pbi = wrk->tx_buffers[n_bufs - 3];
      pb = vlib_get_buffer (vm, pbi);
      vlib_prefetch_buffer_header (pb, STORE);
      pbi = wrk->tx_buffers[n_bufs - 4];
      pb = vlib_get_buffer (vm, pbi);
      vlib_prefetch_buffer_header (pb, STORE);

      bi0 = wrk->tx_buffers[--n_bufs];
      bi1 = wrk->tx_buffers[--n_bufs];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      udp_tx_burst_fill_buffer (vm, wrk, tb, b0, &n_bufs, is_cless);
      udp_tx_burst_fill_buffer (vm, wrk, tb, b1, &n_bufs, is_cless);

      wrk->tx_data_bufs[tb->n_segs - n_left] = b0;
      wrk->tx_data_bufs[tb->n_segs - n_left + 1] = b1;
      n_left -= 2;

      session_tx_add_data_buffer (swrk, bi0, next_index, 0 /* dma */);
      session_tx_add_data_buffer (swrk, bi1, next_index, 0 /* dma */);
    }
  while (n_left)
    {
      if (n_left > 1)
	{
	  pbi = wrk->tx_buffers[n_bufs - 2];
	  pb = vlib_get_buffer (vm, pbi);
	  vlib_prefetch_buffer_header (pb, STORE);
	}

      bi0 = wrk->tx_buffers[--n_bufs];
      b0 = vlib_get_buffer (vm, bi0);
      udp_tx_burst_fill_buffer (vm, wrk, tb, b0, &n_bufs, is_cless);

      wrk->tx_data_bufs[tb->n_segs - n_left] = b0;
      n_left -= 1;

      session_tx_add_data_buffer (swrk, bi0, next_index, 0 /* dma */);
    }

  udp_push_header (&uc->connection, wrk->tx_data_bufs, tb->n_segs, tb->max_dequeue);

  if (PREDICT_FALSE (n_bufs))
    vlib_buffer_free (vm, wrk->tx_buffers, n_bufs);

  SESSION_EVT (SESSION_EVT_DEQ, s, tb->max_len_to_snd, tb->max_dequeue,
	       s->tx_fifo->signals->has_event, swrk->last_vlib_time);

  ASSERT (tb->left_to_snd == 0);

  /* If we couldn't send all bytes, reschedule as old flow */
  if (tb->max_len_to_snd < tb->max_dequeue)
    sp->flags |= TRANSPORT_SND_F_POSTPONE;

  sp->bytes_dequeued = tb->max_len_to_snd + tb->n_segs * SESSION_CONN_HDR_LEN;

  return tb->n_segs;
}

static int
udp_open_connection (transport_endpoint_cfg_t * rmt)
{
  udp_main_t *um = &udp_main;
  ip46_address_t lcl_addr;
  udp_connection_t *uc;
  clib_thread_index_t thread_index;
  u16 lcl_port;
  int rv;

  rv = transport_alloc_local_endpoint (TRANSPORT_PROTO_UDP, rmt, &lcl_addr,
				       &lcl_port);
  if (rv)
    return rv;

  if (udp_connection_port_used_extern (clib_net_to_host_u16 (lcl_port),
				       rmt->is_ip4))
    {
      /* If specific source port was requested abort */
      if (rmt->peer.port)
	{
	  transport_release_local_endpoint (
	    TRANSPORT_PROTO_UDP, rmt->fib_index, &lcl_addr, lcl_port);
	  return SESSION_E_PORTINUSE;
	}

      /* Try to find a port that's not used */
      while (udp_connection_port_used_extern (clib_net_to_host_u16 (lcl_port),
					      rmt->is_ip4))
	{
	  transport_release_local_endpoint (
	    TRANSPORT_PROTO_UDP, rmt->fib_index, &lcl_addr, lcl_port);
	  lcl_port =
	    transport_alloc_local_port (TRANSPORT_PROTO_UDP, &lcl_addr, rmt);
	  if ((int) lcl_port < 1)
	    return SESSION_E_PORTINUSE;
	}
    }

  /* We don't poll main thread if we have workers */
  thread_index = transport_cl_thread ();

  uc = udp_connection_alloc (thread_index);
  ip_copy (&uc->c_rmt_ip, &rmt->ip, rmt->is_ip4);
  ip_copy (&uc->c_lcl_ip, &lcl_addr, rmt->is_ip4);
  uc->c_rmt_port = rmt->port;
  uc->c_lcl_port = lcl_port;
  uc->c_is_ip4 = rmt->is_ip4;
  uc->c_proto = TRANSPORT_PROTO_UDP;
  uc->c_fib_index = rmt->fib_index;
  uc->c_dscp = rmt->dscp;
  uc->mss = rmt->mss ? rmt->mss : udp_default_mtu (um, uc->c_is_ip4);
  if (rmt->peer.sw_if_index != ENDPOINT_INVALID_INDEX)
    uc->sw_if_index = rmt->peer.sw_if_index;
  uc->flags |= UDP_CONN_F_OWNS_PORT | UDP_CONN_F_CONNECTED;
  if (!um->csum_offload)
    uc->cfg_flags |= UDP_CFG_F_NO_CSUM_OFFLOAD;
  uc->next_node_index = rmt->next_node_index;
  uc->next_node_opaque = rmt->next_node_opaque;
  uc->start_ts = transport_time_now (thread_index);

  udp_connection_register_port (uc->c_lcl_port, rmt->is_ip4);

  return uc->c_c_index;
}

static transport_connection_t *
udp_session_get_half_open (u32 conn_index)
{
  udp_connection_t *uc;
  clib_thread_index_t thread_index;

  /* We don't poll main thread if we have workers */
  thread_index = transport_cl_thread ();
  uc = udp_connection_get (conn_index, thread_index);
  if (!uc)
    return 0;
  return &uc->connection;
}

static u8 *
format_udp_session (u8 * s, va_list * args)
{
  u32 uci = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  udp_connection_t *uc;

  uc = udp_connection_get (uci, thread_index);
  return format (s, "%U", format_udp_connection, uc, verbose);
}

static u8 *
format_udp_half_open_session (u8 * s, va_list * args)
{
  u32 __clib_unused tci = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  transport_fmt_req_t __clib_unused fmt = { .as_u32 = va_arg (*args, u32) };
  clib_warning ("BUG");
  return 0;
}

static u8 *
format_udp_listener_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  transport_fmt_req_t fmt = { .as_u32 = va_arg (*args, u32) };
  udp_connection_t *uc = udp_listener_get (tci);
  return format (s, "%U", format_udp_connection, uc, fmt.as_u32);
}

static void
udp_connection_icmp_cleanup_rpc (void *args)
{
  session_handle_t sh = pointer_to_uword (args);
  udp_connection_t *uc;
  session_t *s;

  s = session_get_from_handle (sh);
  if (!s || s->session_state > SESSION_STATE_TRANSPORT_CLOSING)
    return;

  uc = udp_connection_get (s->connection_index, s->thread_index);
  if (!uc)
    return;

  session_transport_reset_notify (&uc->connection);
  session_transport_closed_notify (&uc->connection);
  udp_connection_program_cleanup (uc);
}

void
udp_connection_handle_icmp (transport_connection_t *tc, u8 icmp_type,
			    u8 icmp_code)
{
  udp_connection_t *uc;
  session_t *s;

  uc = udp_connection_from_transport (tc);
  if (tc->is_ip4)
    {
      switch (icmp_type)
	{
	case ICMP4_destination_unreachable:
	  s = session_get (uc->c_s_index, uc->c_thread_index);

	  /* Ignore connectionless UDP and sessions that have already been
	   * closed */
	  if (s->session_state == SESSION_STATE_LISTENING ||
	      s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
	    break;

	  /* ICMPs will probably not hash identically to original connection */
	  session_send_rpc_evt_to_thread (s->thread_index,
					  udp_connection_icmp_cleanup_rpc,
					  (void *) session_handle (s));

	  break;
	default:
	  break;
	}
    }
  else
    {
      /* not handled yet */
    }
}

static void
udp_dst_port_table_to_dense (u16 **tablep)
{
  u16 *sparse_table = *tablep;
  u16 *dense_table = 0;

  vec_validate_init_empty (dense_table, (u16) ~0, UDP_NO_NODE_SET);

  for (u32 port = 0; port <= (u16) ~0; port++)
    {
      uword index = sparse_vec_index (sparse_table, port);

      if (index != SPARSE_VEC_INVALID_INDEX)
	dense_table[port] = sparse_table[index];
    }

  sparse_vec_free (sparse_table);
  *tablep = dense_table;
}

static clib_error_t *
udp_enable_disable (vlib_main_t *vm, u8 is_en)
{
  udp_main_t *um = &udp_main;

  if (!is_en || um->is_init)
    return 0;

  /* Keep the small sparse tables for deployments that do not use the host
   * stack. UDP transport can consume every port in a non-monotonic order, so
   * switch once to direct-indexed tables when it is enabled. */
  udp_dst_port_table_to_dense (&um->next_by_dst_port4);
  udp_dst_port_table_to_dense (&um->next_by_dst_port6);
  um->next_by_dst_port_is_dense = 1;

  vec_validate (um->transport_ports_refcnt[0], 65535);
  vec_validate (um->transport_ports_refcnt[1], 65535);
  um->is_init = 1;

  return 0;
}

static const transport_proto_vft_t udp_proto = {
  .enable = udp_enable_disable,
  .start_listen = udp_session_bind,
  .connect = udp_open_connection,
  .stop_listen = udp_session_unbind,
  .push_header = udp_push_header,
  .get_connection = udp_session_get,
  .get_listener = udp_session_get_listener,
  .get_half_open = udp_session_get_half_open,
  .close = udp_session_close,
  .cleanup = udp_session_cleanup,
  .send_params = udp_session_send_params,
  .custom_tx = udp_session_custom_tx,
  .format_connection = format_udp_session,
  .format_half_open = format_udp_half_open_session,
  .format_listener = format_udp_listener_session,
  .transport_options = {
    .name = "udp",
    .short_name = "U",
    .tx_type = TRANSPORT_TX_DGRAM,
    .service_type = TRANSPORT_SERVICE_CL,
  },
};

static clib_error_t *
udp_init (vlib_main_t * vm)
{
  udp_main_t *um = vnet_get_udp_main ();
  ip_main_t *im = &ip_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 num_threads;
  ip_protocol_info_t *pi;

  /*
   * Registrations
   */

  /* IP registration */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_UDP);
  if (pi == 0)
    return clib_error_return (0, "UDP protocol info AWOL");
  pi->format_header = format_udp_header;
  pi->unformat_pg_edit = unformat_pg_udp_header;

  /* Register as transport with session layer */
  transport_register_protocol (TRANSPORT_PROTO_UDP, &udp_proto,
			       FIB_PROTOCOL_IP4, udp4_output_node.index);
  transport_register_protocol (TRANSPORT_PROTO_UDP, &udp_proto,
			       FIB_PROTOCOL_IP6, udp6_output_node.index);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */  + tm->n_threads;
  vec_validate (um->wrk, num_threads - 1);

  um->local_to_input_edge[UDP_IP4] =
    vlib_node_add_next (vm, udp4_local_node.index, udp4_input_node.index);
  um->local_to_input_edge[UDP_IP6] =
    vlib_node_add_next (vm, udp6_local_node.index, udp6_input_node.index);

  um->default_mtu = 1500;
  um->csum_offload = 1;
  return 0;
}

VLIB_INIT_FUNCTION (udp_init) = {
  .runs_after = VLIB_INITS ("ip_main_init", "ip4_lookup_init",
			    "ip6_lookup_init"),
};
