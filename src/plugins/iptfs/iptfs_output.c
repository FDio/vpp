/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019, LabN Consulting, L.L.C.
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * May 24 2019, Christian Hopps <chopps@labn.net>
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vppinfra/ring.h>
#include <vppinfra/time.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <iptfs/ipsec_iptfs.h>
#include <iptfs/iptfs_sring.h>
#include <iptfs/iptfs_zpool.h>

///* XXX: disable this for now */
// #undef iptfs_pkt_debug_s
// #undef IPTFS_DEBUG_CORRUPTION
// #define iptfs_pkt_debug_s(x, ...)

typedef enum
{
  IPTFS_OUTPUT_NEXT_ESP4_ENCRYPT,
  IPTFS_OUTPUT_NEXT_ESP6_ENCRYPT,
} iptfs_output_next_t;

#define foreach_iptfs_output_error                                                                 \
  _ (TX_NO_PADS, "IPTFS-output-err all pad packets skipped due to config")                         \
  _ (TX_CATCHUP_DROPS, "IPTFS-output-err time slots dropped to catch up")

typedef enum
{
#define _(sym, str) IPTFS_OUTPUT_ERROR_##sym,
  foreach_iptfs_output_error
#undef _
    IPTFS_OUTPUT_N_ERROR,
} iptfs_output_error_t;

static char *iptfs_output_error_strings[] = {
#define _(sym, string) string,
  foreach_iptfs_output_error
#undef _
};

#ifndef CLIB_MARCH_VARIANT
clib_error_t *
iptfs_output_backend_update ()
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;

  vlib_node_add_next_with_slot (vm, iptfs_output_node.index, im->esp4_encrypt_node_index,
				IPTFS_OUTPUT_NEXT_ESP4_ENCRYPT);
  vlib_node_add_next_with_slot (vm, iptfs_output_node.index, im->esp6_encrypt_node_index,
				IPTFS_OUTPUT_NEXT_ESP6_ENCRYPT);
  return 0;
}

#ifdef IPTFS_DEBUG_CORRUPTION
void
iptfs_output_encrypt_debug (vlib_main_t *vm, ipsec_sa_t *sa, void *_esp, vlib_buffer_t *srcb,
			    vlib_buffer_t *dstb)
{
  u64 encap_seq = iptfs_private (srcb)->encap.esp_seq_debug;
  esp_header_t *esp = _esp;
  IPTFS_DBG_ARG (u8 * *dbg) = iptfs_next_debug_string ();

  if (dstb)
    {
      iptfs_private (dstb)->encap.esp_seq_debug = encap_seq;
    }
  iptfs_pkt_debug_s (dbg, "%s: SEQMAP SPI %u: encap_seq: %llu esp_seq: %u", __FUNCTION__,
		     clib_net_to_host_u32 (esp->spi), encap_seq, clib_net_to_host_u32 (esp->seq));
}
#endif
#endif

static inline void
iptfs_output_trace_buffers (vlib_main_t *vm, vlib_node_runtime_t *node, u32 next_index, u32 *bi,
			    u32 n, u32 gen, u16 ord, u16 last_ord, bool new)
{
  uword n_trace = vlib_get_trace_count (vm, node);
  if (PREDICT_FALSE (n_trace))
    {
      n_trace = clib_min (n_trace, n);
      for (uint i = 0; i < n_trace; i++)
	{
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi[i]);
	  if (new)
	    (void) vlib_trace_buffer (vm, node, next_index, b0,
				      /* follow_chain */ 1);
	  iptfs_encapped_packet_trace_store (vm, node, b0, gen, ord + i, last_ord, false);
	}
      vlib_set_trace_count (vm, node, n_trace - 1);
    }
}

typedef struct
{
  u32 sa_index, slots, avail, user, sent;
} iptfs_output_event_send_data_t;

always_inline u32
iptfs_ouptut_get_zpool_buffers (vlib_main_t *vm, u32 sa_index, iptfs_sa_data_t *satd, u32 *buffers,
				u32 n_alloc)
{
  iptfs_zpool_t *zpool = satd->tfs_tx.zpool;

  ASSERT (n_alloc > 0);

  /* This function only works if one thread is the consumer */
  u32 count = iptfs_zpool_get_buffers (zpool, buffers, n_alloc, true);
  if (PREDICT_FALSE (count < n_alloc))
    {
      /* This is only the case when we are running on main only */
      if (PREDICT_FALSE (!satd->tfs_output_zpool_running && !satd->tfs_pad_req_pending))
	goto ping;
      return count;
    }
  else if (PREDICT_FALSE (!satd->tfs_output_zpool_running && !satd->tfs_pad_req_pending))
    {
      /* This is only the case when we are running on main only */
      if (PREDICT_FALSE (iptfs_zpool_get_avail (zpool) <= zpool->trigger))
	{
	ping:
	  satd->tfs_pad_req_pending = true;
	  vlib_process_signal_event_mt (vm, iptfs_zpool_process_node.index,
					IPTFS_EVENT_TYPE_MORE_BUFFERS, sa_index);
	}
    }
  return count;
}

static inline uword
iptfs_output_packets_inline (vlib_main_t *vm, vlib_node_runtime_t *node, u32 thread_index,
			     u32 next_index, u32 sa_index, u16 missed, bool send_faster)
{
  IPTFS_DBG_ARG (u8 * *dbg) = iptfs_next_debug_string ();
  u32 bi[VLIB_FRAME_SIZE];
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
  uword npkts = 0;
  uint count;
  u32 *to = NULL;
  u32 *eto = NULL;

#if IPTFS_OUTPUT_COMPUTE_ALL_PAD_NON_ALL_PAD_DIFF
  /* Hack to see if recognizable diff in compute time for all-pad not all-pad
   */
  u64 entered = clib_cpu_time_now ();
#endif

  iptfs_prefetch_pcounter (IPTFS_PCNT_OUTPUT_RX, thread_index, sa_index);
  iptfs_prefetch_pcounter (IPTFS_PCNT_OUTPUT_TX, thread_index, sa_index);

  ASSERT (missed <= IPTFS_OUTPUT_MAX_MISSED);

  /* We don't try and handle more than VLIB_FRAME_SIZE per call */
  if (missed >= VLIB_FRAME_SIZE)
    {
      iptfs_debug ("%s: more than frame size output requested: total: %u", __func__, missed);
      missed = VLIB_FRAME_SIZE - 1;
    }

  /*
   * send at least one packet, plus one for each missed up to a max frame size
   */
  satd->tfs_tx.output_gen++;

#if IPTFS_ENABLE_OUTPUT_EVENT_LOGS
  iptfs_output_event_send_data_t *esd = NULL;
  /* Log an event with our data for this run */
  ELOG_TYPE_DECLARE (event_send) = {
    .format = "iptfs-output send-data sa_index %d time slots %d user-avail "
	      "(approx) %d user-sent %d sent %d",
    .format_args = "i4i4i4i4i4",
  };
  esd = IPTFS_ELOG (event_send, satd->tfs_tx.output_track);
  esd->sa_index = sa_index;
  esd->slots = missed + 1;
  esd->user = 0;
  /* can change priot to the following SRING_GET, do not rely on the value */
  esd->avail = SRING_NELT (&satd->tfs_tx.q);
#endif

  /* If we enter with an inprogress only to send, send it. */

  /* the number available could actually go up here */
  if (satd->tfs_mode_type != IPTFS_MODE_TYPE_MIN_RATE || send_faster)
    {
      count = SRING_GET (&satd->tfs_tx.q, bi, missed + 1);
      /*
       * XXX if send_faster then missed should be avail-1, so count should be
       * missed + 1
       */
      ASSERT (!send_faster || count == missed + 1);
    }
  else
    {
      /*
       * Here we are in the normal (due) path but with min rate, in this
       * case we want to send as many packets as possible, we have at least 1
       * due and any more that are queued can be sent as "allow-faster", if
       * things are chunking b/c the output routine is running too slow we may
       * send more than we should faster, but we aren't trying to be perfect
       * with "mode 2" (allow faster) mode.
       */
      count = SRING_GET (&satd->tfs_tx.q, bi, VLIB_FRAME_SIZE);
    }
  if (count)
    {
      vlib_put_get_next (vm, node, next_index, bi, count, &to, &eto);
      npkts += count;
#if IPTFS_ENABLE_OUTPUT_EVENT_LOGS
      if (esd)
	esd->user += count;
#endif

      iptfs_inc_pcounter (IPTFS_PCNT_OUTPUT_RX, thread_index, sa_index, count,
			  count * satd->tfs_encap.tfs_ipsec_payload_size);
      iptfs_inc_pcounter (IPTFS_PCNT_OUTPUT_TX, thread_index, sa_index, count,
			  count * satd->tfs_encap.tfs_ipsec_payload_size);

      iptfs_output_trace_buffers (vm, node, next_index, bi, count, satd->tfs_tx.output_gen, 0,
				  count - 1, false);

      iptfs_pkt_debug_t (IPTFS_PT_DBG_OUTPUT_USERDATA, "sending %u of %u full to encryption", count,
			 missed + 1);
      iptfs_pkt_debug_s (dbg, "%s: sending %u of %u full to encryption", __func__, count,
			 missed + 1);
      /* See if we are done (i.e., if we've sent missed + 1) */
      if (count > missed)
	{
	  ASSERT (satd->tfs_mode_type == IPTFS_MODE_TYPE_MIN_RATE || count == missed + 1);
	  goto done;
	}
    }
  missed -= count;

  /*
   * Get and send pad packets
   */

  if (PREDICT_FALSE (satd->tfs_no_pad_only))
    {
      /* Pretend like we send all the pads */
      vlib_node_increment_counter (vm, iptfs_output_node.index, IPTFS_OUTPUT_ERROR_TX_NO_PADS,
				   missed + 1);
#if defined(IPTFS_OUTPUT_BACKUP)
      npkts += missed + 1;
#endif
    }
  else
    {
      u16 nopad_count = count;
      ASSERT (missed + 1 + nopad_count < VLIB_FRAME_SIZE);
      count = iptfs_ouptut_get_zpool_buffers (vm, sa_index, satd, &bi[nopad_count], missed + 1);

      if (count < missed + 1u)
	{
	  iptfs_debug ("%s: got less zbufs than requested: %u < %u", __func__, count, missed + 1);
	}
      vlib_put_get_next (vm, node, next_index, &bi[nopad_count], count, &to, &eto);
#if !defined(IPTFS_OUTPUT_BACKUP)
      npkts += count;
#else
      /*
       * Because we backup the timer, we cannot treat non-alloc'd buffers as
       * come-back-laters like we do with the inprogress buffers, if we did we
       * end up never moving forward if we get into a zero buffer situation.
       */
      npkts += missed + 1;
#endif

      iptfs_pkt_debug_s (dbg, "%s: sending %u of %u all-pad to encryption", __func__, count,
			 missed + 1);

      iptfs_inc_counter (IPTFS_CNT_OUTPUT_TX_ALL_PADS, thread_index, sa_index, count);

      iptfs_inc_pcounter (IPTFS_PCNT_OUTPUT_TX, thread_index, sa_index, count,
			  count * satd->tfs_encap.tfs_ipsec_payload_size);

      /* User is not normally going to want all-pad traced */
      if (!satd->tfs_no_pad_trace)
	{
	  iptfs_output_trace_buffers (vm, node, next_index, &bi[nopad_count], count,
				      satd->tfs_tx.output_gen, npkts - count - 1, npkts - 1, true);
	}
      count += nopad_count;
    }

done:

  /*
   * We need to update the CC header data here
   *
   * We should be able to do this periodically rather than every time. But then
   * payload calculation gets complex. Leave this for improving for now.
   */
  if (satd->tfs_cc && PREDICT_TRUE (satd->tfs_encap.cc_inb_sa_index != ~0))
    {
      iptfs_sa_data_t *in_satd = iptfs_get_sa_data (satd->tfs_encap.cc_inb_sa_index);

      u32 our_rtt;
      u32 unused;
      iptfs_rx_get_loss_info (in_satd, &our_rtt, &unused);

      u32 loss_rate_net = in_satd->tfs_rx.cc_llrate_net;

      u32 cc_lasttime;
      u32 their_timeval;
      iptfs_rx_get_lastvals (in_satd, &their_timeval, &cc_lasttime);

      /* strip the top bits from current clock in usec */
      u64 now = clib_cpu_time_now ();
      /*
       * Get these values in terms of the usec from in_satd as that's how they
       * were stored
       */
#if IPTFS_OUTPUT_COMPUTE_ALL_PAD_NON_ALL_PAD_DIFF
      u64 orig_timeclks = now;
      u64 orig_timeval = iptfs_get_cpu_tval (in_satd, now);
#endif
      u32 our_timeval = iptfs_get_cpu_tval (now);
      u64 delay_tval = our_timeval;

      u32 actual_delay, xmit_delay;
      if (PREDICT_FALSE (in_satd->tfs_rx.nextseq == 0))
	{
	  /* we haven't received a packet yet */
	  xmit_delay = 0;
	  actual_delay = 0;
	  our_rtt = 0;
	}
      else
	{
	  /* compensate for clock wrap */
	  if (delay_tval < cc_lasttime)
	    {
	      STATIC_ASSERT (sizeof (cc_lasttime) == 4, "Expected 4 bytes");
	      iptfs_debug ("delay_tval %u wrapped from lasttime %u", delay_tval, cc_lasttime);
	      delay_tval += (1ull << 32);
	    }

	  /* Advertise the delay between echoing their tval */
	  if (PREDICT_FALSE (delay_tval < cc_lasttime))
	    {
	      ASSERT (delay_tval >= cc_lasttime);
	      iptfs_debug ("echo delay MAXED delay_tval %lu < cc_lasttime %u "
			   "after addition "
			   "wrap addition.",
			   delay_tval, cc_lasttime);
	      actual_delay = IPTFS_CC_DELAY_MAX;
	    }
	  else
	    {
	      u64 u_delay = iptfs_tval_to_usec (in_satd, delay_tval - cc_lasttime);
	      if (PREDICT_FALSE (u_delay > IPTFS_CC_DELAY_MAX))
		{
		  iptfs_debug ("echo_delay MAXED delay_tval %lu and "
			       "cc_lasttime %u lead to too "
			       "large u_delay %lu",
			       delay_tval, cc_lasttime, u_delay);
		  actual_delay = IPTFS_CC_DELAY_MAX;
		}
	      else
		actual_delay = u_delay;
	    }
	}

      xmit_delay = iptfs_get_cpu_usec (satd, satd->tfs_tx.pdelay);
      if (PREDICT_FALSE (xmit_delay > IPTFS_CC_DELAY_MAX))
	xmit_delay = IPTFS_CC_DELAY_MAX;

      ipsec_iptfs_cc_header_t cc_template = {
	.loss_rate = loss_rate_net,
	.tval = our_timeval,
	.techo = their_timeval,
      };
      iptfs_cc_set_rtt_and_delays (&cc_template, our_rtt, actual_delay, xmit_delay);
#if IPTFS_OUTPUT_COMPUTE_ALL_PAD_NON_ALL_PAD_DIFF
      iptfs_debug ("output cc: tval %u cch->tval %u orig clk %lu orig tval "
		   "%lu cpusec %0.4f or %0.4f",
		   our_timeval, cc_template.tval, orig_timeclks, orig_timeval,
		   satd->clocks_per_usec, vm->clib_time.clocks_per_second / 1e6);
#endif

      for (uint i = 0; i < count; i++)
	{
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi[i]);
	  if (i + 1 < count)
	    {
	      vlib_buffer_t *b1 = vlib_get_buffer (vm, bi[i + 1]);
	      vlib_prefetch_buffer_header (b1, LOAD);
	      vlib_prefetch_buffer_data (b1, STORE);
	    }

	  ipsec_iptfs_cc_header_t *h = vlib_buffer_get_current (b0);
	  if (h->subtype != IPTFS_SUBTYPE_CC)
	    continue;
	  clib_memcpy_fast (&h->loss_rate, &cc_template.loss_rate,
			    sizeof (cc_template) - offsetof (ipsec_iptfs_cc_header_t, loss_rate));
	}
    }

#if IPTFS_OUTPUT_COMPUTE_ALL_PAD_NON_ALL_PAD_DIFF
  /* Hack to see if recognizable diff in compute time for all-pad not all-pad
   */
  /* XXX SPIN UP TO 20us on 2.1GHz machine to make the above code run in the
   * same amount of time  */
  entered += 42000;
  while (clib_cpu_time_now () < entered)
    ;
#endif

  vlib_put_next_frame_with_cnt (vm, node, next_index, to, eto, ~0);

#if IPTFS_ENABLE_OUTPUT_EVENT_LOGS
  if (esd)
    esd->sent = npkts;
#endif

  return npkts;
}

extern vlib_node_registration_t iptfs_output_node;

static inline uword
iptfs_output_poll_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *__clib_unused unused)
{
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  u32 thread_index = vlib_get_thread_index ();
  iptfs_thread_main_t *tm = vec_elt_at_index (tfsm->workers_main, thread_index);
  uword npkts = 0;
  u32 next_index;

  /*
   * First send any packets that are due.
   *
   * When we split the sending and building, we need to track the minimum
   * next due. We then will only construct packets until this min due is hit,
   * in which case we will return to all the dispatch to run, it will call us
   * back and we will send the next packet.
   */

  u32 *sap;
  vec_foreach (sap, tm->sa_active[IPTFS_POLLER_OUTPUT])
    {
      u32 sa_index = *sap;
      iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);

      /* Make sure this hasn't happened */
      ASSERT (ipsec_sa_get (sa_index));
      ASSERT (satd->tfs_output_running);

      /* grab pdelay once as it may be changed in other threads */
      u64 pdelay = satd->tfs_tx.pdelay;
      u64 due = satd->tfs_tx.lastdue + pdelay;
      u64 now = clib_cpu_time_now ();

      if (PREDICT_FALSE (!(satd->tfs_tx.lastdue)))
	due = now;

      if (PREDICT_FALSE (satd->tfs_ipv6))
	next_index = IPTFS_OUTPUT_NEXT_ESP6_ENCRYPT;
      else
	next_index = IPTFS_OUTPUT_NEXT_ESP4_ENCRYPT;

      if (due > now)
	{
	  /*
	   * If we are allowing sending faster and we have more than 1 packet
	   * then we are going to send all but that one immediately. The output
	   * routine should always be running faster than the pacer which is
	   * cooperative with the encap thread, and the encap routine is the
	   * computationally large component of the process.
	   */
	  u32 n_avail;
	  if (iptfs_is_min_rate (satd) && (n_avail = SRING_NELT (&satd->tfs_tx.q)) > 1)
	    {
	      iptfs_inc_counter (IPTFS_CNT_OUTPUT_TX_FASTER, thread_index, sa_index, n_avail);

	      n_avail = clib_min (n_avail, VLIB_FRAME_SIZE);
	      npkts += iptfs_output_packets_inline (vm, node, thread_index, next_index, sa_index,
						    n_avail - 1, true);
	    }
	  continue;
	}

      u64 missed;
      u64 delta = now - due;
      if ((missed = delta / pdelay))
	{
	  /* account for missing slots in the due time */
	  due += missed * pdelay;
	  if (due > now)
	    *(volatile u8 *) 0 = 0;

	  /* If we've fallen too far behind, catch up by skipping some */
	  /* XXX can we really afford to not drop if > VLIB_FRAME_SIZE? */
	  if (missed >= IPTFS_OUTPUT_MAX_MISSED)
	    {
	      u32 dropped = missed - (IPTFS_OUTPUT_MAX_MISSED - 1);

	      vlib_node_increment_counter (vm, iptfs_output_node.index,
					   IPTFS_OUTPUT_ERROR_TX_CATCHUP_DROPS, dropped);

	      ELOG_TYPE_DECLARE (edrop) = {
		.format = "iptfs-output-catchup-drops dropping %d slots",
		.format_args = "i4",
	      };
	      u32 *edrops = IPTFS_ELOG (edrop, satd->tfs_error_track);
	      edrops[0] = dropped;

	      missed = IPTFS_OUTPUT_MAX_MISSED - 1;
	    }
	  /* We do not update due here otherwise might never catch-up */
	}

      /* update last due with this run's */
      satd->tfs_tx.lastdue = due;

      /*
       * send the packets
       */

#if defined(IPTFS_OUTPUT_BACKUP)
      /*
       * If we are willing to back-up then we can also trim the send down to
       * VLIB_FRAME_SIZE and we will come back and catch up in the next cycle
       * of the thread loop. This allows IPTFS_OUTPUT_MAX_MISSED to be larger
       * than VLIB_FRAME_SIZE.
       */
      missed = clib_min (missed, VLIB_FRAME_SIZE - 1);
#endif
      u32 sent =
	iptfs_output_packets_inline (vm, node, thread_index, next_index, sa_index, missed, false);

      if (!iptfs_is_min_rate (satd) && PREDICT_FALSE (sent > missed + 1))
	*(volatile u8 *) 0 = 0;

      npkts += sent;
#if defined(IPTFS_OUTPUT_BACKUP)
      /* This code does not work at all with min-rate */
      XXX if ((missed = (missed + 1) - sent))
      {
	/*
	 * CRITICAL: Its important that the crypto engine and other
	 * downstream nodes get to run before we process an in-progress (as
	 * long as we did a real packet. Otherwise we end up sending
	 * partially filled packets even though there would have been data to
	 * send if we'd waited. This is how VPP is designed to work, and we
	 * need to work with it.
	 */
	/*
	 * We missed sending all our packets either b/c we skipped an
	 * in-progress or b/c we couldn't get a buffer, etc. Account for this
	 * in the lastdue so that we send it in the next iteration, after
	 * giving other nodes a chance to run.
	 */
	satd->tfs_tx.lastdue -= missed * pdelay;
      }
#endif
    }

  return npkts;
}

VLIB_NODE_FN (iptfs_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return iptfs_output_poll_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (iptfs_output_node) = {
  .name = "iptfs-output",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  // Need to add length to va_args for this function to use.
  // .format_buffer = format_iptfs_header,
  .format_trace = format_iptfs_packet_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,

  .n_errors = ARRAY_LEN (iptfs_output_error_strings),
  .error_strings = iptfs_output_error_strings,
};
