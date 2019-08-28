/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019, LabN Consulting, L.L.C.
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * May 24 2019, Christian Hopps <chopps@labn.net>
 */

/*
 * Red Side Timed Sender -- this runs on same thread as SA input encap so that
 * they do not need to have locks between them. This allows easily sending
 * partial complete packets at the correct time. These packets are then
 * enqueued to the ouptut thread routine using a lockless ring.
 *
 * The output core then sends pads for any packets it does not have present
 * that it also fetches from a lockless ring so there is never a time that it
 * has to wait for packets to send.
 */

#include <math.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vppinfra/ring.h>
#include <vppinfra/time.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <iptfs/ipsec_iptfs.h>
#include <iptfs/iptfs_zpool.h>

///* XXX: disable this for now */
// #undef iptfs_pkt_debug_s
// #undef IPTFS_DEBUG_CORRUPTION
// #define iptfs_pkt_debug_s(x, ...)

#define foreach_iptfs_pacer_error                                                                  \
  _ (TX_PAD_INPROGRESS_DROP, "IPTFS-pacer-err drop in-progress no pad buffer")                     \
  _ (TX_NO_PAD_BUF, "IPTFS-pacer-err out-of-buffers for all pad packet")                           \
  _ (TX_Q_DROPS, "IPTFS-pacer-err no output queue space")                                          \
  _ (TX_CATCHUP_DROPS, "IPTFS-pacer-err packets dropped to catch up.")

typedef enum
{
#define _(sym, str) IPTFS_PACER_ERROR_##sym,
  foreach_iptfs_pacer_error
#undef _
    IPTFS_PACER_N_ERROR,
} iptfs_pacer_error_t;

static char *iptfs_pacer_error_strings[] = {
#define _(sym, string) string,
  foreach_iptfs_pacer_error
#undef _
};

static inline void
iptfs_pacer_trace_buffers (vlib_main_t *vm, vlib_node_runtime_t *node, u32 *bi, u32 n, u32 gen,
			   u16 ord, u16 last_ord)
{
  /*
   * XXX This is wrong, but it's expensive to check otherwise
   * Instead encap (which feeds us) should maybe add a counter
   * to the ring of the number of traced packets added which is
   * decremented when the buffer is processed here
   */
  uword trace_count = vlib_get_trace_count (vm, node);
  if (PREDICT_FALSE (trace_count))
    {
      uword n_trace = clib_min (trace_count, n);
      uint i;
      for (i = 0; i < n_trace; i++)
	{
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi[i]);
	  iptfs_encapped_packet_trace_store (vm, node, b0, gen, ord + i, last_ord, false);
	}
      vlib_set_trace_count (vm, node, trace_count - i);
    }
}

static inline u32
iptfs_pacer_get_pad_buffer (vlib_main_t *vm, u32 sa_index, iptfs_sa_data_t *satd, u16 pad_len)
{
  u32 bi0 = iptfs_zpool_get_buffer (satd->tfs_encap.zpool);
  if (bi0 == ~0u)
    {
      vlib_node_increment_counter (vm, iptfs_pacer_node.index, IPTFS_PACER_ERROR_TX_NO_PAD_BUF, 1);
      /* Log an event with our data for this run */
      ELOG_TYPE_DECLARE (e) = {
	.format = "iptfs-pacer-nopad sa_index %d",
	.format_args = "i4",
      };
      u32 *data = IPTFS_ELOG (e, satd->tfs_error_track);
      *data++ = sa_index;

      return ~0u;
    }
  /* pad, including any header if used that way, already zero'd */
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  ASSERT ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
  /* This used to not be true from zpool, but now is */
  ASSERT (b0->current_data == 0);
  b0->current_length = pad_len;
  return bi0;
}

/*
 * Finish off an inprogress packet.
 */
static inline bool
finish_inprogress (vlib_main_t *vm, u32 sa_index, iptfs_sa_data_t *satd, u32 thread_index,
		   vlib_buffer_t *b0, u32 *insize)
{
  vlib_buffer_t *lastb0 = satd->tfs_encap.inlastb;
  bool use_chaining = satd->tfs_encap_chaining;
  u16 avail = satd->tfs_encap.q_packet_avail;
  u16 mtu = satd->tfs_encap.tfs_ipsec_payload_size;

  /* We keep this up-to-date so it should be fast. */
  ASSERT (vlib_buffer_length_in_chain (vm, b0) + avail == mtu);
  ASSERT (avail);

  iptfs_pkt_debug_t (IPTFS_PT_DBG_PACER, "avail %u, mtu %u", avail, mtu);

  if (use_chaining)
    {
      u32 padbi = iptfs_pacer_get_pad_buffer (vm, sa_index, satd, avail);
      if (padbi == ~0u)
	{
	  /* This represents packet loss and it's bad! */
	  vlib_node_increment_counter (vm, iptfs_pacer_node.index,
				       IPTFS_PACER_ERROR_TX_PAD_INPROGRESS_DROP, 1);
	  iptfs_debug ("failed to get pad buffer");
	  return false;
	}

      ASSERT ((lastb0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
      lastb0->next_buffer = padbi;
      lastb0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      if (lastb0 != b0)
	{
	  b0->total_length_not_including_first_buffer += avail;
	  ASSERT (b0->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID);
	}
      else
	{
	  b0->total_length_not_including_first_buffer = avail;
	  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	}

      iptfs_inc_counter (IPTFS_CNT_OUTPUT_TX_PAD_ADD, thread_index, sa_index, 1);
      iptfs_pkt_debug_t (IPTFS_PT_DBG_PACER,
			 "%s: chained pad buffer (len: %u) to "
			 "indirect in-progress",
			 __func__, avail);
      iptfs_pkt_debug_s (dbg,
			 "%s: chained pad buffer (len: %u) to "
			 "indirect in-progress",
			 __func__, avail);
    }
  else
    {
      /* Eliminate side-channel, zero all the pad */

#ifdef IPTFS_DEBUG
#define _vlib_buffer_can_put(vm, b, size)                                                          \
  (b->current_data + b->current_length + size <= vm->buffer_main->default_data_size)

      if (!_vlib_buffer_can_put (vm, lastb0, avail))
	{
	  /*
	   * This should never really happen and we don't
	   * expect it b/c we need enough room in the packet
	   * not just for 'avail' but also for the ESP footer
	   * and the ICV. The indirect buffer should end and
	   * any buffer should be able to hold 9k + slop.
	   */
	  ASSERT (0);
	  return false;
	}
#endif
      /*
       * If this is a re-used buffer, must zero all the pad bytes or we create
       * a side-channel for viewing traffic from other sources
       */
      if (iptfs_private (b0)->encap.iptfs_reused_user)
	clib_memset (vlib_buffer_put_uninit (lastb0, avail), 0, avail);
      else
	{
	  /* This is a zeroed buffer */
	  u8 *pad = vlib_buffer_put_uninit (lastb0, avail);
	  ASSERT (*pad == 0);
	}

      if (b0 != lastb0)
	{
	  ASSERT (b0->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID);
	  b0->total_length_not_including_first_buffer += avail;
	}
      iptfs_inc_counter (IPTFS_CNT_OUTPUT_TX_PAD_INS, thread_index, sa_index, 1);

      iptfs_pkt_debug_t (IPTFS_PT_DBG_PACER,
			 "%s: added pad (len: %u) to "
			 "direct in-progress",
			 __func__, avail);
      iptfs_pkt_debug_s (dbg,
			 "%s: added pad (len: %u) to "
			 "direct in-progress",
			 __func__, avail);
    }

  /* Return the actual data size for later accounting */
  *insize = iptfs_private (b0)->encap.tfs_actual_data;

  /* Detach the inprogress as we are sending it now. */
  satd->tfs_encap.infirst = ~0u;
  satd->tfs_encap.inlastb = NULL;
  satd->tfs_encap.q_packet_avail = 0;
  return true;
}

typedef struct
{
  u32 sa_index, avail, qopen;
  u16 slots, want, sent;
} __attribute__ ((__packed__)) iptfs_pacer_event_send_data_t;

#define PACK_SLOTS_PACKETS(slots, pkts) (((u64) (slots) << 32) | (u64) (pkts))
#define UNPACK_SLOTS_PACKETS(rv, s, p)                                                             \
  do                                                                                               \
    {                                                                                              \
      (s) = (((rv) >> 32) & 0xFFFFFFFF);                                                           \
      (p) = ((rv) & 0xFFFFFFFF);                                                                   \
    }                                                                                              \
  while (0)

static inline u64
iptfs_pacer_queue_packets (vlib_main_t *vm, vlib_node_runtime_t *node, u32 thread_index,
			   u32 sa_index, i32 missed, bool maybe_finish)
{
  IPTFS_DBG_ARG (u8 * *dbg) = iptfs_next_debug_string ();
  u32 bi[VLIB_FRAME_SIZE + 1];
  u32 sizes[VLIB_FRAME_SIZE + 1];
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
  uint count;

  iptfs_prefetch_pcounter (IPTFS_PCNT_PACER_RX, thread_index, sa_index);
  iptfs_prefetch_pcounter (IPTFS_PCNT_PACER_TX, thread_index, sa_index);

  /*
   * missed can be as low as -1 to indicate that we are going faster for
   * min-rate
   */
  ASSERT (missed + 1 <= IPTFS_PACER_MAX_MISSED);

  /* We don't try and handle more than VLIB_FRAME_SIZE per call */
  if (missed >= VLIB_FRAME_SIZE)
    {
      iptfs_debug ("%s: more than frame size output requested: total: %u", __func__, missed);
      missed = VLIB_FRAME_SIZE - 1;
    }

  u32 n_avail = iptfs_bufq_n_enq (&satd->tfs_encap.outq);

#if IPTFS_ENABLE_PACER_EVENT_LOGS
  /* Log an event with our data for this run */
  iptfs_pacer_event_send_data_t *esd = NULL;
  ELOG_TYPE_DECLARE (event_send) = {
    .format = "iptfs-pacer send sai %d uavail %d qopen %d "
	      "tslots %d want %d sent %d",
    .format_args = "i4i4i4i2i2i2",
  };

  esd = IPTFS_ELOG (event_send, satd->tfs_encap.pacer_track);
  esd->sa_index = sa_index;
  esd->slots = missed + 1;
  esd->sent = 0;
  esd->avail = n_avail;
#endif

  /* Prefetch the buffer header for in progress incase we use it */
  vlib_buffer_t *inpb = NULL;
  u32 inprogress = satd->tfs_encap.infirst;
  if (maybe_finish && inprogress != ~0u)
    {
      inpb = vlib_get_buffer (vm, inprogress);
      vlib_prefetch_buffer_header (inpb, STORE);
    }

  u32 q_open = SRING_OPEN (&satd->tfs_tx.q);
#if IPTFS_ENABLE_PACER_EVENT_LOGS
  esd->qopen = q_open;
#endif
  if (!q_open)
    {
      /* This is bad we need to alert the condition */
      iptfs_warn ("ZERO open tx q slots (%u avail to send)", n_avail);
      return PACK_SLOTS_PACKETS (missed + 1, 0);
    }

  if (missed < 0)
    {
      ASSERT (satd->tfs_encap.limit.size > satd->tfs_encap.limit.max_size);
      u32 over = satd->tfs_encap.limit.size - satd->tfs_encap.limit.max_size;
      over = (over + satd->tfs_encap.tfs_payload_size - 1) / satd->tfs_encap.tfs_payload_size;
      ASSERT (missed + 1 + over <= 0xFFFF);
      missed += over;
    }

#if IPTFS_ENABLE_PACER_EVENT_LOGS
  esd->want = missed + 1;
#endif
  u32 n_req = clib_min (q_open, missed + 1);
  n_req = clib_min (n_req, VLIB_FRAME_SIZE);
  count = iptfs_bufq_ndequeue (&satd->tfs_encap.outq, bi, sizes, n_req);

  /* We have no packets or in-progress packet */
  if (!count && !inpb)
    return PACK_SLOTS_PACKETS (missed + 1, 0);

  if (PREDICT_TRUE (count < q_open))
    {
      /*
       * If we have a slot and an in progress, send it. This may initially
       * waste some bandwidth but if the user is sending at or above full
       * tunnel rate we should fall behind and then we will have full packets
       * queued on future trips through here.
       *
       * Make sure if we are bursting min-rate that we don't finish a packet
       * when we had full packets left on the queue (count < n_avail)
       */
      if (count == n_avail && count <= missed && inpb)
	{
	  if (finish_inprogress (vm, sa_index, satd, thread_index, inpb, &sizes[count]))
	    bi[count++] = inprogress;
	}
    }

#ifdef IPTFS_DEBUG_CORRUPTION
  for (uint i = 0; i < count; i++)
    {
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi[i]);
      /* Note this sequence numer will get out of sync when all-pads are sent
       */
      iptfs_private (b0)->encap.esp_seq_debug = satd->tfs_tx.encap_seq++;
    }
#endif

  u32 total_actual_data = 0;
  for (uint i = 0; i < count; i++)
    total_actual_data += sizes[i];
  ASSERT (satd->tfs_encap.limit.size >= total_actual_data);
  satd->tfs_encap.limit.size -= total_actual_data;

  /* Record the received packets and the data length */
  iptfs_inc_pcounter (IPTFS_PCNT_PACER_RX, thread_index, sa_index, count, total_actual_data);
  /*
   * Queue the packets to the output thread
   */
  /* Reacheck for open slots to cover any in-progress we are trying to add */

  q_open = SRING_OPEN (&satd->tfs_tx.q);
  ASSERT (q_open >= count);

  /* We may end up tracing packets here that we drop in SRING_PUT */
  iptfs_pacer_trace_buffers (vm, node, bi, count, satd->tfs_tx.output_gen, 0, count - 1);

  /* Put them on the queue, they will be available immediately so dont use!
   */
#if IPTFS_PACER_DEBUG_SRING_PUT
  {
    iptfs_debug ("putting %u precount %u missed %u inpb %d", count, precount, missed, inpb != NULL);
  }
#endif
  u32 actual = SRING_PUT (&satd->tfs_tx.q, bi, count);

  /* XXX remove this? we want to see if we run differently for now though */
  iptfs_assert (actual == count);
  iptfs_pkt_debug_s (dbg, "enqueued: %u to iptfs-output", actual);

  iptfs_inc_pcounter (IPTFS_PCNT_PACER_TX, thread_index, sa_index, actual,
		      actual * satd->tfs_encap.tfs_ipsec_payload_size);

#if IPTFS_ENABLE_PACER_EVENT_LOGS
  if (esd)
    esd->sent = actual;
#endif

  /* Return the number of slots we serviced */
  return PACK_SLOTS_PACKETS (missed + 1, actual);
}

static inline f64
iptfs_pacer_cc_initial_rate (iptfs_sa_data_t *satd)
{
  u32 our_rtt = satd->tfs_encap.pd_our_rtt;
  if (!our_rtt)
    return IPTFS_CC_MIN_PPS;

  f64 W_init = clib_min (4, clib_max (2, 4380 / satd->tfs_mtu));
  return iptfs_cc_check_min_rate (W_init / ((f64) our_rtt / 1e6));
}

static inline f64
iptfs_cc_estimate_x_recv (f64 x, u64 loss_rate)
{
  if (!loss_rate)
    return x;

  if ((u64) x <= loss_rate)
    return x;

  /* Is fp div too expensive so we should only do this once? */
  /* XXX use of +1 is correct here, why don't we use it everywhere? */
  f64 p = 1.0 / (loss_rate + 1);
  x *= (1.0 - p);
  if (x < IPTFS_CC_MIN_PPS)
    x = IPTFS_CC_MIN_PPS;

  return x;
}

static inline f64
iptfs_pacer_cc_update_limits (iptfs_sa_data_t *satd, f64 timer_limit, u64 now)
{
  vec_reset_length (satd->tfs_encap.cc_x_recv_set);
  vec_reset_length (satd->tfs_encap.cc_x_recv_set_ts);
  /* Make sure we don't go below min rate when 1/2 the value */
  timer_limit = iptfs_cc_check_min_rate (timer_limit / 2);
  vec_add1 (satd->tfs_encap.cc_x_recv_set, timer_limit);
  vec_add1 (satd->tfs_encap.cc_x_recv_set_ts, now);
  return satd->tfs_encap.cc_x_recv_set[0];
}

/*
 * RFC5348: Section 4.3 Maximize X_recv_set
 */
static inline void
iptfs_pacer_max_x_recv_set (iptfs_sa_data_t *satd, u64 now, f64 x_recv)
{
  uint i, len = vec_len (satd->tfs_encap.cc_x_recv_set);
  f64 largest = x_recv;

  /* What about an infinity value? */
  for (i = 0; i < len; i++)
    if (satd->tfs_encap.cc_x_recv_set[i] > largest)
      largest = satd->tfs_encap.cc_x_recv_set[i];

  vec_reset_length (satd->tfs_encap.cc_x_recv_set);
  vec_reset_length (satd->tfs_encap.cc_x_recv_set_ts);
  vec_add1 (satd->tfs_encap.cc_x_recv_set, largest);
  vec_add1 (satd->tfs_encap.cc_x_recv_set_ts, now);
}

/*
 * RFC5348: Section 4.3 Update X_recv_set
 *
 * returns the maximum value of the set
 */
static inline f64
iptfs_pacer_update_x_recv_set (iptfs_sa_data_t *satd, u64 now, u64 rtt_clks, f64 x_recv)
{
  f64 penultimate_max_value = x_recv, max_value = x_recv;
  u64 too_old = now - (rtt_clks * 2);
  u64 oldest = 0;
  int oldest_i = 0;
  uint i = 0;
  while (i < vec_len (satd->tfs_encap.cc_x_recv_set))
    {
      f64 this = satd->tfs_encap.cc_x_recv_set[i];
      u64 this_ts = satd->tfs_encap.cc_x_recv_set_ts[i];
      if (this_ts < too_old)
	{
	  vec_delete (satd->tfs_encap.cc_x_recv_set, 1, i);
	  vec_delete (satd->tfs_encap.cc_x_recv_set_ts, 1, i);
	  continue;
	}
      if (!oldest || this_ts < oldest)
	{
	  oldest = this_ts;
	  oldest_i = i;
	}
      if (this > max_value)
	{
	  penultimate_max_value = max_value;
	  max_value = this;
	}
      i++;
    }
  /*
   * Limit the number of entries to 8, algorithmically I think this is probably
   * limited to 2 currently since we only run the algorithm every RTT time, but
   * if we change that to run more often this will backstop.
   */
  if (vec_len (satd->tfs_encap.cc_x_recv_set) > 7)
    {
      if (satd->tfs_encap.cc_x_recv_set[oldest_i] == max_value)
	max_value = penultimate_max_value;
      satd->tfs_encap.cc_x_recv_set[oldest_i] = x_recv;
      satd->tfs_encap.cc_x_recv_set_ts[oldest_i] = now;
    }
  else
    {
      vec_add1 (satd->tfs_encap.cc_x_recv_set, x_recv);
      vec_add1 (satd->tfs_encap.cc_x_recv_set_ts, now);
    }
  return max_value;
}

static inline f64
iptfs_pacer_cc_recalc_pps (vlib_main_t *vm, iptfs_sa_data_t *satd, f64 x, f64 recv_limit, u64 now)
{

  u32 our_rtt = satd->tfs_encap.pd_our_rtt;
  u32 our_rtt_clks = satd->tfs_encap.pd_our_rtt_clks;
  u32 loss_rate = satd->tfs_encap.pd_loss_rate;
  f64 frtt = (f64) our_rtt / (f64) 1e6;
  f64 pps;

  f64 full_rate_pps = iptfs_conf_pps (satd->tfs_config);
  if (!loss_rate)
    {
      // initial slow-start, or return to trying for full-rate
      if (x != full_rate_pps && (now - satd->tfs_encap.pd_tld) >= our_rtt_clks)
	{
	  f64 initial_rate = iptfs_pacer_cc_initial_rate (satd);
	  pps = clib_max (clib_min (2 * x, recv_limit), initial_rate);
	  satd->tfs_encap.pd_tld = now;
	  if (pps > full_rate_pps)
	    {
#if IPTFS_CC_DEBUG
	      iptfs_debug ("CC slow-start/recover pps %f > full rate pps %f, "
			   "going full-rate",
			   pps, full_rate_pps);
#endif
	      pps = full_rate_pps;
	    }
#if IPTFS_CC_DEBUG
	  iptfs_debug ("slow-start new pps %f", pps);
#endif
	}
      else
	pps = x;
    }
  else
    {
      /*
       * Calculate new pps
       */

      /*
       *                              1
       *  X_Pps = -----------------------------------------------
       *         R * (sqrt(2*p/3) + 12*sqrt(3*p/8)*p*(1+32*p^2))
       */
      f64 p = (f64) 1 / (f64) loss_rate;
      pps = 1 / (frtt * (sqrt ((2 * p) / 3) + 12 * sqrt ((3 * p) / 8) * p * (1 + 32 * (p * p))));
      if (pps > full_rate_pps)
	{
#if IPTFS_CC_DEBUG
	  iptfs_debug ("CC calculated pps %f > full rate pps %f", pps, full_rate_pps);
#endif
	  pps = full_rate_pps;
	}
      else
	{
	  pps = iptfs_cc_check_min_rate (pps);
#if IPTFS_CC_DEBUG
	  iptfs_debug ("CC calculated new pps %f (full rate pps %f)", pps, full_rate_pps);
#endif
	}
    }
  pps = clib_min (pps, recv_limit);
  return pps;
}

static inline void
iptfs_pacer_sa_rto_timer (vlib_main_t *vm, iptfs_sa_data_t *in_satd, iptfs_sa_data_t *satd, u64 now)
{
  /*
   * RFC5348: Section 4.4 Expiration of RTO timer
   */
#if IPTFS_CC_DEBUG
  iptfs_debug ("RTO: timeout");
#endif

  u32 our_rtt = satd->tfs_encap.pd_our_rtt;
  u32 loss_rate = satd->tfs_encap.pd_loss_rate;

  /* Update the timer set time */
  u64 old_timer_ts = satd->tfs_encap.cc_rto_ts;
  satd->tfs_encap.cc_rto_ts = now;

  /* Update the clocks while we're here */
  iptfs_update_clocks_per_usec (vm, satd);

  /* Have we been idle since the last RTO */
  bool have_been_idle = satd->tfs_encap.lastdue < old_timer_ts;

  /*
   * RFC5248: S4.4, first condition
   */
  f64 x = satd->tfs_encap.cc_x;
  f64 x_recv = iptfs_cc_estimate_x_recv (x, loss_rate);
  if (!our_rtt && !in_satd->tfs_rx.cc_lossinfo_ts && have_been_idle)
    x = x / 2;
  else
    {
      /* Estimate X_recv based on what we have been sending */

      f64 recover_rate = iptfs_pacer_cc_initial_rate (satd);
      if (((loss_rate > 0 && x_recv < recover_rate) || (!loss_rate && x_recv < 2 * recover_rate)) &&
	  have_been_idle)
	; /* do nothing */
      else if (!loss_rate)
	x = x / 2;
      else
	{
	  f64 recv_limit;
	  if (x > 2 * x_recv)
	    /* This will never happen b/c x == x_recv */
	    recv_limit = iptfs_pacer_cc_update_limits (satd, x_recv, now);
	  else
	    recv_limit = iptfs_pacer_cc_update_limits (satd, x / 2, now);
	  x = iptfs_pacer_cc_recalc_pps (vm, satd, x, recv_limit, now);
	}
    }

  x = iptfs_cc_check_min_rate (x);
  if (satd->tfs_encap.cc_x != x)
    {
#if IPTFS_CC_DEBUG
      iptfs_debug ("CC calculated new pps rate %0.1f", x);
#endif
      satd->tfs_encap.cc_x = x;

      iptfs_set_counter (IPTFS_CNT_PPS, vlib_get_thread_index (), iptfs_sa_data_to_index (satd),
			 (u64) x);
    }
#if IPTFS_ENABLE_CC_EVENT_LOGS
  ELOG_TYPE_DECLARE (cc_rto) = {
    .format = "cc-rto timeout new X (pps) %f",
    .format_args = "f8",
  };
  f64 *esd = IPTFS_ELOG_CURRENT_THREAD (cc_rto);
  *esd++ = x;
#endif

  satd->tfs_tx.pdelay = (u64) (vm->clib_time.clocks_per_second / x);
}

static inline void
iptfs_pacer_sa_congestion_check (vlib_main_t *vm, iptfs_sa_data_t *satd)
{
  u64 now = clib_cpu_time_now ();
  iptfs_sa_data_t *in_satd = iptfs_get_sa_data (satd->tfs_encap.cc_inb_sa_index);

  /*
   * See if we have not received new CC info
   */
  {
    u64 last_info_ts = in_satd->tfs_rx.cc_lossinfo_ts;
    if (last_info_ts == satd->tfs_encap.pd_lastinfo_ts)
      {
	/*
	 * The info may have just been updated prior to the timestamp, but
	 * we'll catch it next time around, next time around we could race
	 * again and get even newer info with an old but still newer time
	 * stamp, in this case CC info is coming so quickly this doesn't
	 * matter.
	 */

	/*
	 * We also need to check for the RTO timeout here, if none we are done
	 * for now.
	 */
	if (now > (satd->tfs_encap.cc_rto_ts + satd->tfs_encap.cc_rto))
	  iptfs_pacer_sa_rto_timer (vm, in_satd, satd, now);
	return;
      }
    satd->tfs_encap.pd_lastinfo_ts = last_info_ts;
  }

  u32 our_rtt = satd->tfs_encap.pd_our_rtt;
  u32 old_loss_rate = satd->tfs_encap.pd_loss_rate;
  u32 rtt_sample, new_loss_rate;
  iptfs_rx_get_loss_info (in_satd, &rtt_sample, &new_loss_rate);

#if IPTFS_PACER_FAILED_CONGESTION_CHECK_EXPERIMENT
  /*
   * This seems like a good idea; however, it really messes up the input to
   * the filter as new similar small values are needed to drive down an initial
   * large value. Also we can end up with an RTO timeout when we should not.
   */
  /*
   * Check if CC info remains the same, We allow for small variations in the
   * RTT estimate w/o updating it.
   */
  if (old_loss_rate == new_loss_rate && rtt_sample && our_rtt)
    {
      if (((rtt_sample < our_rtt) && (our_rtt - rtt_sample) < (our_rtt >> 10)) ||
	  ((rtt_sample >= our_rtt) && ((rtt_sample - our_rtt) < (our_rtt >> 10))))
	{
	  iptfs_debug ("rtt_sample %u withing 1/1024 of old value %u", rtt_sample, our_rtt);
	  return;
	}
    }
#endif

  /*
   * Only run the algorithm every RTT, this will be based on previous RTT
   * estimate.
   */
  if (PREDICT_TRUE (satd->tfs_encap.cc_next_check) && now < satd->tfs_encap.cc_next_check)
    return;

  /* Update the clocks while we're here */
  iptfs_update_clocks_per_usec (vm, satd);

  if (!rtt_sample)
    {
      return;
    }

  /*
   * RFC5348: Section 4.3 Sender Behavior When a Feedback Packet Is Received
   */

  /*
   * Sections 4.3, 1) Calculate a new RTT sample -- already done in decap
   */

  /*
   * Sections 4.3, 2) Update the RTT estimate.
   */
  // iptfs_debug ("Old RTT: %u", our_rtt);
  if (!our_rtt)
    our_rtt = rtt_sample;
  else
    {
      /* RFC5348 says R = q*R + (1-q)*R_sample; q == .9 */
      /*
       * However when we slow start R is set to the first sample which will be
       * based on a RTT of 2s (b/c 1 pps start rate) it takes a very long time
       * to recover from this. Use reverse filter instead.
       */
      our_rtt = ((40 * our_rtt) / 100) + ((60 * rtt_sample) / 100);
    }

  // iptfs_debug ("New RTT: %u", our_rtt);

  u64 our_rtt_clks = satd->clocks_per_usec * our_rtt;
  satd->tfs_encap.pd_our_rtt = our_rtt;
  satd->tfs_encap.pd_our_rtt_clks = our_rtt_clks;
  satd->tfs_encap.pd_loss_rate = new_loss_rate;

  {
    u32 thread_index = vlib_get_thread_index ();
    u32 sa_index = iptfs_sa_data_to_index (satd);
    iptfs_set_counter (IPTFS_CNT_RTT, thread_index, sa_index, our_rtt);
    iptfs_set_counter (IPTFS_CNT_LOSS_RATE, thread_index, sa_index, new_loss_rate);
  }

  /*
   * Setup the next time we will allow for running based on the new RTT
   * estimate. We'll allow for some skew here by using 90% of the RTT instead.
   */
  satd->tfs_encap.cc_next_check = now + ((90 * our_rtt_clks) / 100);

  /*
   * Sections 4.3, 3) Update the timeout interval.
   */
  satd->tfs_encap.cc_rto = clib_max (4 * our_rtt_clks, 2 * satd->tfs_tx.pdelay);
  satd->tfs_encap.cc_rto_ts = now;

  /*
   * Sections 4.3, 4) Update the allowed sending rate.
   */
  f64 full_rate_pps = iptfs_conf_pps (satd->tfs_config);
  f64 recv_limit = full_rate_pps;
  f64 x = satd->tfs_encap.cc_x;

  /* Estimate X_recv based on what we have been sending */
  f64 x_recv = x;

  /* If we are currently data-limited */
  if (x != full_rate_pps)
    {
      /* If p has increased (p = 1/loss_rate so comparison reversed) */
      /* a loss rate of 0 represents no loss */
      if (new_loss_rate && new_loss_rate < old_loss_rate)
	{
	  for (uint i = 0; i < vec_len (satd->tfs_encap.cc_x_recv_set); i++)
	    satd->tfs_encap.cc_x_recv_set[i] /= 2;
	  x_recv = 0.85 * x_recv;
	  iptfs_pacer_max_x_recv_set (satd, now, x_recv);
	  ASSERT (vec_len (satd->tfs_encap.cc_x_recv_set) == 1);
	  recv_limit = satd->tfs_encap.cc_x_recv_set[0];
#if IPTFS_CC_DEBUG
	  iptfs_debug ("loss increased %u from %u, setting new recv_limit: %f", new_loss_rate,
		       old_loss_rate, recv_limit);
#endif
	}
      else
	{
	  iptfs_pacer_max_x_recv_set (satd, now, x_recv);
	  ASSERT (vec_len (satd->tfs_encap.cc_x_recv_set) == 1);
	  recv_limit = 2 * satd->tfs_encap.cc_x_recv_set[0];
#if IPTFS_CC_DEBUG
	  if (new_loss_rate == old_loss_rate)
	    iptfs_debug ("loss same %u => recv_limit to %f", new_loss_rate, recv_limit);
	  else
	    iptfs_debug ("loss decreased %u from %u => recv_limit: %f", new_loss_rate,
			 old_loss_rate, recv_limit);
#endif
	}
    }
  else
    {
      /*
       * This is always going to reduce to full_rate_pps!
       *
       * The text indicates use this path if the entire interval covered by the
       * feedback was not rate-limited. This can only mean if we are in
       * slow-start I think; however, it then also indicates this is the
       * "typical behavior" which seems the opposite.
       */
      f64 max_x_recv = iptfs_pacer_update_x_recv_set (satd, now, our_rtt_clks, x_recv);
      recv_limit = 2 * max_x_recv;
      if (recv_limit > full_rate_pps)
	recv_limit = full_rate_pps;
    }

  x = iptfs_pacer_cc_recalc_pps (vm, satd, x, recv_limit, now);
  x = iptfs_cc_check_min_rate (x);
  satd->tfs_encap.cc_x = x;
  iptfs_set_counter (IPTFS_CNT_PPS, vlib_get_thread_index (), iptfs_sa_data_to_index (satd),
		     (u64) x);

#if IPTFS_CC_DEBUG
  iptfs_debug ("event new pps %f", x);
#endif

#if IPTFS_ENABLE_CC_EVENT_LOGS
  ELOG_TYPE_DECLARE (cc_update) = {
    .format = "cc-update RTT %u LR %u X (pps) %f",
    .format_args = "i4i4f8",
  };
  u32 *esd = IPTFS_ELOG_CURRENT_THREAD (cc_update);
  *esd++ = our_rtt;
  *esd++ = new_loss_rate;
  *(f64 *) esd = x;
#endif

  satd->tfs_tx.pdelay = (u64) (vm->clib_time.clocks_per_second / x);
}

static inline uword
iptfs_pacer_sa_send (vlib_main_t *vm, vlib_node_runtime_t *node, u32 sa_index, bool maybe_finish)
{
  u32 thread_index = vlib_get_thread_index ();
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);

  /* Make sure this hasn't happened */
  ASSERT (ipsec_sa_get (sa_index));
  ASSERT (satd->tfs_output_running);

  if (satd->tfs_cc && PREDICT_TRUE (satd->tfs_encap.cc_inb_sa_index != ~0))
    iptfs_pacer_sa_congestion_check (vm, satd);

  u64 pdelay = satd->tfs_tx.pdelay;
  u64 due = satd->tfs_encap.lastdue + pdelay;
  u64 now = clib_cpu_time_now ();

  if (PREDICT_FALSE (!(satd->tfs_encap.lastdue)))
    {
      satd->tfs_encap.lastdue = now;
      return 0;
    }

  i64 delta = now - due;
  i64 missed = delta / (i64) pdelay;

  if (delta < 0)
    {
      if (iptfs_is_min_rate (satd) && satd->tfs_encap.limit.size > satd->tfs_encap.limit.max_size)
	{
	  /* un-account for sending next time slot */
	  due = satd->tfs_encap.lastdue;
	  missed = -1;
	}
      else
	return 0;
    }
  else if (missed)
    {
      ASSERT (missed > 0);

      /* account for missing slots in the due time */
      due += missed * pdelay;
      if (PREDICT_FALSE (due > now))
	*(volatile u8 *) 0 = 0;

      /* If we've fallen too far behind, catch up by skipping some */
      if (missed >= IPTFS_PACER_MAX_MISSED)
	{
	  u32 dropped = missed - (IPTFS_PACER_MAX_MISSED - 1);

	  vlib_node_increment_counter (vm, iptfs_pacer_node.index,
				       IPTFS_PACER_ERROR_TX_CATCHUP_DROPS, dropped);

	  ELOG_TYPE_DECLARE (edrop) = {
	    .format = "iptfs-pacer-catchup-drops dropping %d slots",
	    .format_args = "i4",
	  };
	  u32 *edrops = IPTFS_ELOG (edrop, satd->tfs_error_track);
	  edrops[0] = dropped;

	  missed = IPTFS_PACER_MAX_MISSED - 1;
	}
      /* We do not update due here otherwise might never catch-up */
    }

  /* update last due with this run's */
  satd->tfs_encap.lastdue = due;

  /*
   * queue the packets
   */

  /*
   * If we are willing to back-up then we can also trim the send down to
   * VLIB_FRAME_SIZE and we will come back and catch up in the next cycle
   * of the thread loop. This allows IPTFS_OUTPUT_MAX_MISSED to be larger
   * than VLIB_FRAME_SIZE.
   */
  missed = clib_min (missed, VLIB_FRAME_SIZE - 1);

  u64 rv = iptfs_pacer_queue_packets (vm, node, thread_index, sa_index, missed, maybe_finish);
  u32 slots, sent;
  UNPACK_SLOTS_PACKETS (rv, slots, sent);

  /* account for burst for when we come back? */
  slots = clib_max (slots, sent);

  /* We do not allow backing up */
  if (sent <= missed)
    iptfs_inc_x_counter (IPTFS_CNT_PACER_EMPTY_SLOTS, thread_index, sa_index, missed + 1 - sent);

  /* We do not allow backing up */
  if (slots <= missed)
    {
      iptfs_warn ("slots too low %u/%u", slots, missed);
    }
  iptfs_assert (slots >= missed + 1);

  /*
   * Allow for sent > missed to burst to the output, but do not account for
   * min-rate bursting (missed == -1) in our next due.
   */
  if (missed >= 0 && slots > missed + 1)
    {
      u32 burst = slots - (missed + 1);
      /*
       * We burst forward so adjust our next send slot time.
       */
      satd->tfs_encap.lastdue += burst * pdelay;
    }
  return sent;
}

static inline uword
iptfs_pacer_poll_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *__clib_unused unused)
{
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  u32 thread_index = vlib_get_thread_index ();
  iptfs_thread_main_t *tm = vec_elt_at_index (tfsm->workers_main, thread_index);
  uword npkts = 0;

  /*
   * We queue packet to the output ring at the same pace that the output
   * thread should be removing them. This allows sending in-progress packets
   * without locks between the threads
   *
   * The output thread should (on average) be trying to send packets at the
   * same rate as the pacer so the ring should never be filling up (if it is
   * large enough for some slop to cover the average). If it does backup,
   * something is out of whack and we should just drop packets and log the
   * problem.
   */

  u32 active_index, *active_vector = tm->sa_active[IPTFS_POLLER_PACER];
  vec_foreach_index (active_index, active_vector)
    {
      u32 sa_index = active_vector[active_index];
      npkts += iptfs_pacer_sa_send (vm, node, sa_index, true);
    }

  return npkts;
}

VLIB_NODE_FN (iptfs_pacer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return iptfs_pacer_poll_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (iptfs_pacer_node) = {
  .name = "iptfs-pacer",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_iptfs_packet_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,

  .n_errors = ARRAY_LEN (iptfs_pacer_error_strings),
  .error_strings = iptfs_pacer_error_strings,
};
