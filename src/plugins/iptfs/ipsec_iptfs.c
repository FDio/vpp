/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019, LabN Consulting, L.L.C.
 * May 18 2019, Christian E. Hopps <chopps@labn.net>
 */
/**
 * @file
 * @brief IPsec IP-TFS plugin, plugin API / trace / CLI handling.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/types.h>
#include <vppinfra/ring.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/esp.h>
#include <iptfs/deferred.h>
#include <iptfs/ipsec_iptfs.h>
#include <iptfs/iptfs_zpool.h>

VLIB_PLUGIN_REGISTER () = {
  .version = IPSEC_IPTFS_PLUGIN_BUILD_VER,
  .description = "IPsec IP-TFS Plugin",
};

ipsec_iptfs_main_t ipsec_iptfs_main;

#ifdef IPTFS_DEBUG
bool iptfs_debug = true;
bool iptfs_pkt_debug = false;
#else
bool iptfs_debug = false;
bool iptfs_pkt_debug = false;
#endif

ipsec_iptfs_config_t iptfs_default_config = {
  .tfs_mtu = IPSEC_IPTFS_DEFAULT_MTU,
  .tfs_max_delay = IPSEC_IPTFS_DEFAULT_MAX_DELAY,
  .tfs_rewin = IPSEC_IPTFS_DEFAULT_REORDER_WINDOW,
  .tfs_inbound_sa_id = ~0,
};

static u32
vlib_buffer_main_buffers (void)
{
  vlib_buffer_pool_t *bp;
  u32 nbuf = 0;
  vec_foreach (bp, vlib_get_main_by_index (0)->buffer_main->buffer_pools)
    {
      nbuf += bp->n_buffers;
    }
  return nbuf;
}

static clib_error_t *
iptfs_check_support (ipsec_sa_t *sa, void *tfs_config)
{
  ipsec_iptfs_config_t *conf = (ipsec_iptfs_config_t *) tfs_config;
  iptfs_debug ("%s: Entered", __FUNCTION__);

  if (!ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      return clib_error_return (0, "No IPTFS IPsec transport mode");
    }

  if (!ipsec_sa_is_set_IS_INBOUND (sa))
    {
      if (sa->tfs_type == IPSEC_SA_TFS_TYPE_IPTFS_CC)
	{
	  if (sa->id == conf->tfs_inbound_sa_id)
	    return clib_error_return (0, "Cannot run iptfs-cc mode w/o valid paired inbound SA "
					 "(iptfs-inbound-sa-id refers to outbound SA)");

	  index_t sa_index = ipsec_sa_find_and_lock (conf->tfs_inbound_sa_id);
	  if (sa_index == INDEX_INVALID)
	    return clib_error_return (0, "Cannot run iptfs-cc mode w/o valid paired inbound SA "
					 "(iptfs-inbound-sa-id doesn't exist)");
	  ipsec_sa_unlock (sa_index);
	}

      if ((!conf || (!conf->tfs_ebyterate && !conf->tfs_byterate)))
	{
	  /* XXX this is pretty odd changing a value that we don't own */
	  clib_warning ("%s: disabling outbound TFS b/c no config", __FUNCTION__);
	  sa->tfs_type = IPSEC_SA_TFS_TYPE_NO_TFS;
	}
    }
  /* XXX check the worker config here */
  // return clib_error_return (0, "Worker %u doesn't exist");
  return 0;
}

/*
 * Get overhead of IP+ESP
 */
static u16
iptfs_get_ipsec_overhead (ipsec_sa_t *sa)
{
  u16 o;
  ipsec_sa_outb_rt_t *ort = ipsec_sa_get_outb_rt (sa);

  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
    o = sizeof (ip6_and_esp_header_t) + sizeof (esp_footer_t);
  else
    o = sizeof (ip4_and_esp_header_t) + sizeof (esp_footer_t);

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    o += sizeof (udp_header_t);

  return o + (ort->cached.integ_icv_size + ort->cached.cipher_iv_size);
}

/*
 * Get overhead of IP+ESP+IPTFS
 */
static u16
iptfs_get_overhead (ipsec_sa_t *sa)
{
  u16 o = iptfs_get_ipsec_overhead (sa);

  /* Data area for TFS */
  if (sa->tfs_type == IPSEC_SA_TFS_TYPE_IPTFS_NOCC)
    o += sizeof (ipsec_iptfs_basic_header_t);
  else
    {
      ASSERT (sa->tfs_type == IPSEC_SA_TFS_TYPE_IPTFS_CC);
      o += sizeof (ipsec_iptfs_cc_header_t);
    }

  return o;
}

u16
ipsec_iptfs_get_payload_size (u32 sa_index)
{
  ipsec_sa_t *sa = ipsec_sa_get (sa_index);
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
  return (satd->tfs_mtu - iptfs_get_overhead (sa));
}

f64
ipsec_iptfs_get_conf_payload_rate (u32 sa_index)
{
  ipsec_sa_t *sa = ipsec_sa_get (sa_index);
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
  f64 pps = iptfs_conf_pps (satd->tfs_config);
  return pps * (satd->tfs_mtu - iptfs_get_overhead (sa));
}

#define UROUND(x, to) ((((x) + (to) - 1) / (to)) * (to))

/*
 * iptfs_tfs_data_fixup -
 * use tfs_byterate and tfs_mtu to fix tfs_prate
 * use tfs_max_delay and tfs_bitrate to fixup tfs_encap.q_max_size.
 */
static void
iptfs_tfs_data_init (u32 sa_index, ipsec_iptfs_config_t *conf)
{
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  vlib_main_t *vm = vlib_get_main ();
  /* This updates the clocks per second */
  /* XXX we need to redo this periodically */
  (void) clib_time_now (&vm->clib_time);
  f64 clockspersec = vm->clib_time.clocks_per_second;

  vec_validate_aligned (tfsm->sa_data, sa_index, CLIB_CACHE_LINE_BYTES);
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
  ipsec_sa_t *sa = ipsec_sa_get (sa_index);

  iptfs_debug ("TFS init %f, conf %p sa_index %u", clockspersec, conf, sa_index);

  if (!vlib_thread_is_main_w_barrier ())
    {
      iptfs_debug ("%s: called outside of barrier", __func__);
      os_panic ();
    }

  // pps = f64(satd->tfs_bitrate) / (satd->tfs_config.tfs_mtu * 8);
  // packet ever N ns = 1000000000 / pps
  // packet every second = f64(1000000000) / f64(satd->tfs_rate) /
  //   satd->tfs_config.tfs_mtu;
  // 64Kbps = 8KBps @ 1400 = 5.71pps

  clib_memset (satd, 0, sizeof (*satd));
  if (conf || iptfs_is_sa_index_possible_IPTFS (sa_index))
    {
      /* Log an event with our data for this run */
      ELOG_TYPE_DF (iptfs_data_init_e);
      ELOG (vlib_global_main.elog_main, iptfs_data_init_e, sa_index);

      if (!conf)
	conf = &iptfs_default_config;

      ipsec_iptfs_config_t *copyconf = clib_mem_alloc (sizeof (*conf));
      clib_memcpy (copyconf, conf, sizeof (*conf));
      satd->tfs_config = copyconf;

      /* copy important data to top of data section */
      satd->tfs_mtu = conf->tfs_mtu;
      satd->tfs_rewin = conf->tfs_rewin;
      satd->tfs_df = conf->tfs_df;
      satd->tfs_mode_type = conf->tfs_mode_type;
      satd->tfs_no_pad_only = conf->tfs_no_pad_only;
      satd->tfs_no_pad_trace = conf->tfs_no_pad_trace;
      satd->tfs_decap_chaining = conf->tfs_decap_chaining;
      satd->tfs_encap_chaining = conf->tfs_encap_chaining;
      satd->tfs_ipv6 = ipsec_sa_is_set_IS_TUNNEL_V6 (sa);

      satd->clocks_per_usec = vm->clib_time.clocks_per_second / 1e6;
      satd->usecs_per_clock = 1.0 / satd->clocks_per_usec;

      /*
       * XXX How does this work for global RX enable? Should we maybe default
       * to CC?
       */
      ipsec_sa_t *sa = ipsec_sa_get (sa_index);
      satd->tfs_cc = (sa->tfs_type == IPSEC_SA_TFS_TYPE_IPTFS_CC);

      /* Update counters to accommodate this sa_index */
      /* XXX would be nice to check current length prio to locking */
      for (uint i = 0; i < IPTFS_CNT_N_COUNTERS; i++)
	vlib_validate_simple_counter (&tfsm->cm[i], sa_index);
      for (uint i = 0; i < IPTFS_PCNT_N_COUNTERS; i++)
	vlib_validate_combined_counter (&tfsm->pcm[i], sa_index);

      /* Clear the counters for this sa_index */
      for (uint i = 0; i < IPTFS_CNT_N_COUNTERS; i++)
	vlib_zero_simple_counter (&tfsm->cm[i], sa_index);
      for (uint i = 0; i < IPTFS_PCNT_N_COUNTERS; i++)
	vlib_zero_combined_counter (&tfsm->pcm[i], sa_index);

      /*
       * encap/decap init
       */
      satd->tfs_error_track.name = (char *) format (0, "SA-ERROR %d", sa_index);
      vec_add1 (satd->tfs_error_track.name, 0);
      elog_track_register (vlib_global_main.elog_main, &satd->tfs_error_track);

      if (ipsec_sa_is_set_IS_INBOUND (sa))
	{
	  iptfs_log ("%s: inbound TFS SA", __FUNCTION__);

	  /* Catch bugs */
	  clib_memset (&satd->tfs_encap, 0xDA, sizeof (satd->tfs_encap));
	  clib_memset (&satd->tfs_tx, 0xDA, sizeof (satd->tfs_tx));
	  clib_memset (&satd->tfs_rx, 0, sizeof (satd->tfs_rx));

	  satd->tfs_is_inbound = 1;
	  satd->tfs_rx.frag_bi = ~0u;

	  /* Pre-allocate our reorder-window */
	  vec_validate (satd->tfs_rx.win, conf->tfs_rewin - 1);
	  vec_reset_length (satd->tfs_rx.win);

	  satd->tfs_rx.decap_thread_index = iptfs_next_thread_index (
	    &tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP], conf->tfs_decap_thread_index);

	  /* We don't use decrypt threads for NULL encryption */
	  if (sa->crypto_alg != IPSEC_CRYPTO_ALG_NONE)
	    {
	      satd->tfs_rx.decrypt_thread_index = iptfs_next_thread_index (
		&tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT], conf->tfs_decrypt_thread_index);
	      /* Set it in the SA too for native decrypt handoff support */
	      ipsec_sa_bind (sa->id, vlib_get_worker_index (satd->tfs_rx.decrypt_thread_index),
			     true);
	    }

#if IPTFS_ENABLE_DECAP_EVENT_LOGS
	  /* Register a decap ELOG track for this SA */
	  satd->tfs_rx.decap_track.name = (char *) format (0, "SA-IN %d", sa_index);
	  vec_add1 (satd->tfs_rx.decap_track.name, 0);
	  elog_track_register (vlib_global_main.elog_main, &satd->tfs_rx.decap_track);
#endif

#if IPTFS_ENABLE_CC_EVENT_LOGS
	  /* Register a CC ELOG track for this SA */
	  satd->tfs_rx.cc_track.name = (char *) format (0, "SA-IN-CCEV %d", sa_index);
	  vec_add1 (satd->tfs_rx.cc_track.name, 0);
	  elog_track_register (vlib_global_main.elog_main, &satd->tfs_rx.cc_track);
#endif
	}
      else
	{
	  iptfs_assert (conf);

	  /* Catch bugs */
	  clib_memset (&satd->tfs_rx, 0xDA, sizeof (satd->tfs_rx));
	  clib_memset (&satd->tfs_encap, 0, sizeof (satd->tfs_encap));
	  clib_memset (&satd->tfs_tx, 0, sizeof (satd->tfs_tx));

	  satd->tfs_encap.tfs_ipsec_payload_size = conf->tfs_mtu - iptfs_get_ipsec_overhead (sa);
	  satd->tfs_encap.tfs_payload_size =
	    conf->tfs_mtu - ipsec_iptfs_get_payload_size (sa_index);

	  /* There is an associated inbound SA for CC mode */
	  if (satd->tfs_cc)
	    {
	      satd->tfs_encap.cc_inb_sa_index = ipsec_sa_find_and_lock (conf->tfs_inbound_sa_id);
	      if (satd->tfs_encap.cc_inb_sa_index == INDEX_INVALID)
		iptfs_warn ("Cannot run in CC mode w/o inbound SA");
	      else
		{
		  iptfs_sa_data_t *in_satd = iptfs_get_sa_data (satd->tfs_encap.cc_inb_sa_index);
		  in_satd->tfs_rx.cc_out_sa_index = sa_index;
		}
	    }

	  u32 max_size;
	  f64 payload_rate = ipsec_iptfs_get_conf_payload_rate (sa_index);
	  if (conf->tfs_max_delay)
	    {
	      max_size = payload_rate * ((f64) conf->tfs_max_delay / 1000000);
	      /* some slop for in progress packet */
	      max_size += 2;
	    }
	  else
	    max_size = IPTFS_DEF_ENCAP_QUEUE_SIZE * ipsec_iptfs_get_payload_size (sa_index);

	  if (max_size < ipsec_iptfs_get_payload_size (sa_index))
	    {
	      iptfs_log ("%s: WARNING: tfs_max_delay %u too short to allow "
			 "constructing single iptfs packet, increasing",
			 __FUNCTION__, conf->tfs_max_delay);
	      max_size = ipsec_iptfs_get_payload_size (sa_index);
	    }

	  u32 max_queue_size = 1 + max_size / (ipsec_iptfs_get_payload_size (sa_index));

	  /*
	   * For min-rate mode we allow overflow which we will then send this
	   * immediately from the pacer->output.
	   */
	  if (conf->tfs_mode_type == IPTFS_MODE_TYPE_MIN_RATE)
	    max_queue_size += IPTFS_MIN_RATE_OVER_ALLOW;

	  /*
	   * For the zpool target size we need enough buffers to hold an entire
	   * queue of packets. The maximum zbuffers per iptfs packet are 3: a
	   * zbuffer header, zbuffer indirect, zbuffer esp footer. Many iptfs
	   * packets will use less but this is the maximum.
	   *
	   * If dont-fragment is set we never straddle so it's all chained and
	   * the count is 1-1, same for not chaining.
	   *
	   * Additionally we need enough buffers to cover what has been sent on
	   * (as we consider those out of the queue) but have not been
	   * recovered yet by the buffer pool. In a perfect world we would
	   * manage our own buffer pool and only subtract from the output queue
	   * size when buffer is recovered after being sent. This isn't a
	   * perfect world. Instead add another 2 * VLIB_FRAME_SIZE worth of
	   * buffers.
	   */

	  /* Must be at least VLIB_FRAME_SIZE * 2 */
	  u32 zpool_target_size;
	  if (conf->tfs_df || !conf->tfs_encap_chaining)
	    zpool_target_size =
	      clib_max (2 * VLIB_FRAME_SIZE, (2 * VLIB_FRAME_SIZE + max_queue_size));
	  else
	    zpool_target_size =
	      clib_max (2 * VLIB_FRAME_SIZE, 3 * (2 * VLIB_FRAME_SIZE + max_queue_size));
	  zpool_target_size = clib_min (zpool_target_size, IPTFS_ZPOOL_MAX_ALLOC);
	  zpool_target_size = UROUND (zpool_target_size, VLIB_FRAME_SIZE);

	  /* XXX move this to check supported? */
	  u32 free_buffers = vlib_buffer_main_buffers ();
	  if (zpool_target_size > (free_buffers / 2))
	    {
	      clib_error ("%s: too few free buffers (%u) for iptfs "
			  "max-delay %llu (min-reqd %u)",
			  __FUNCTION__, free_buffers, conf->tfs_max_delay, zpool_target_size * 2);
	    }

	  /* For dont-fragment the calculation is light as we waste space */
	  if (conf->tfs_df)
	    max_queue_size *= 4;

	  satd->tfs_encap.infirst = ~0u;
	  iptfs_bufq_init (&satd->tfs_encap.outq, max_queue_size);
	  satd->tfs_encap.limit.max_size = max_size;
	  satd->tfs_encap.limit.hard_max_size = max_size;

	  if (conf->tfs_mode_type == IPTFS_MODE_TYPE_MIN_RATE)
	    satd->tfs_encap.limit.hard_max_size +=
	      IPTFS_MIN_RATE_OVER_ALLOW * ipsec_iptfs_get_payload_size (sa_index);

	  /* We can't need more than a queue of for 20 byte packets in 10000b
	   * frame
	   */
	  vec_validate (satd->tfs_encap.buffers, IPTFS_MAX_PACKET_SIZE / sizeof (ip4_header_t));
	  vec_reset_length (satd->tfs_encap.buffers);

	  satd->tfs_encap.zpool_thread_index = iptfs_next_thread_index (
	    &tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL], conf->tfs_encap_zpool_thread_index);
	  satd->tfs_tx.zpool_thread_index = iptfs_next_thread_index (
	    &tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL], conf->tfs_output_zpool_thread_index);

	  /*
	   * if we have even number of zpools and they don't overlap with other
	   * ranges, skip forward one to round-robin * between output and encap
	   * This is dubious since it means one SA user load might affect
	   * another SA TFS output timing.
	   */
	  iptfs_worker_range_t *zr = &tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL];
	  if (((zr->last - zr->first + 1) % 2) == 0)
	    {
	      bool overlap = false;
	      for (uint i = 0; i < IPTFS_WK_RANGE_COUNT; i++)
		{
		  if (i == IPTFS_WK_RANGE_ZPOOL)
		    continue;
		  iptfs_worker_range_t *wr = &tfsm->wk_ranges[i];
		  if ((zr->first >= wr->first && zr->first <= wr->last) ||
		      (zr->last >= wr->first && zr->last <= wr->last))
		    {
		      overlap = true;
		      break;
		    }
		}
	      if (!overlap)
		iptfs_skip_thread_index (&tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL]);
	    }

	  satd->tfs_encap.encap_thread_index = iptfs_next_thread_index (
	    &tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP], conf->tfs_encap_thread_index);
	  satd->tfs_encap.output_thread_index = iptfs_next_thread_index (
	    &tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT], conf->tfs_output_thread_index);

#if IPTFS_ENABLE_PACER_EVENT_LOGS
	  /* Register a pacer ELOG track for this SA */
	  satd->tfs_encap.pacer_track.name = (char *) format (0, "SA-PACER %d", sa_index);
	  vec_add1 (satd->tfs_encap.pacer_track.name, 0);
	  elog_track_register (vlib_global_main.elog_main, &satd->tfs_encap.pacer_track);
#endif
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
	  /* Register a ELOG track for this SA */
	  satd->tfs_encap.zpool_track.name = (char *) format (0, "SA-ZPOOL-ENCAP %d", sa_index);
	  vec_add1 (satd->tfs_encap.zpool_track.name, 0);
	  elog_track_register (vlib_global_main.elog_main, &satd->tfs_encap.zpool_track);
#endif

	  satd->tfs_encap.zpool = iptfs_zpool_alloc (
	    vm, zpool_target_size, sa_index, satd->tfs_encap.tfs_ipsec_payload_size,
	    false, /* zeros, no put length */
	    false  /* cc, we never init the header for
		      these */
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
	    ,
	    &satd->tfs_encap.zpool_track, &satd->tfs_error_track
#endif
	  );

	  f64 pps = iptfs_conf_pps (conf);
	  if (satd->tfs_cc && satd->tfs_encap.cc_inb_sa_index != INDEX_INVALID)
	    {
	      /*
	       * RFC5348: Section 4.2, Sender Initialization
	       *
	       * We are running in CC mode so slow-start
	       */
	      pps = IPTFS_CC_MIN_PPS;
	    }
	  satd->tfs_encap.cc_x = pps;
	  iptfs_set_counter (IPTFS_CNT_PPS, vlib_get_thread_index (), iptfs_sa_data_to_index (satd),
			     (u64) pps);

	  /*
	   * TX Initialize
	   */

	  satd->tfs_tx.pdelay = (u64) (clockspersec / pps);

#ifdef IPTFS_DEBUG_CORRUPTION
	  /* For static tunnels they should align */
	  satd->tfs_tx.encap_seq = 1;
#endif

#if IPTFS_ENABLE_OUTPUT_EVENT_LOGS
	  /* Register a ELOG track for this SA */
	  satd->tfs_tx.output_track.name = (char *) format (0, "SA-OUTBOUND %d", sa_index);
	  vec_add1 (satd->tfs_tx.output_track.name, 0);
	  elog_track_register (vlib_global_main.elog_main, &satd->tfs_tx.output_track);
#endif
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
	  /* Register a ELOG track for this SA */
	  satd->tfs_tx.zpool_track.name = (char *) format (0, "SA-ZPOOL-OUTPUT %d", sa_index);
	  vec_add1 (satd->tfs_tx.zpool_track.name, 0);
	  elog_track_register (vm->elog_main, &satd->tfs_tx.zpool_track);
#endif

	  /* XXX maybe be smarter about this number wise */
	  satd->tfs_tx.zpool =
	    iptfs_zpool_alloc (vm, IPTFS_OUTPUT_ZPOOL_SIZE, sa_index,
			       satd->tfs_encap.tfs_ipsec_payload_size, true, /* zero, put length */
			       satd->tfs_cc /* init CC header if needed */
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
			       ,
			       &satd->tfs_tx.zpool_track, &satd->tfs_error_track
#endif
	    );
	}
      iptfs_log ("%s: TFS config: %U data: %U", __FUNCTION__, format_iptfs_config_early, conf,
		 format_iptfs_data, sa_index);
    }
}

static void
iptfs_satd_cleanup_inbound (void *_satd)
{
  vlib_main_t *vm = vlib_get_main ();
  iptfs_sa_data_t *satd = (iptfs_sa_data_t *) _satd;
  u32 count;

  iptfs_log ("%s: inbound TFS SA, freeing resources", __FUNCTION__);

  if ((count = vec_len (satd->tfs_rx.win)))
    iptfs_buffer_free (vm, satd->tfs_rx.win, count);
  vec_free (satd->tfs_rx.win);

  /* Debug */
  clib_memset (satd, 0xDA, sizeof (*satd));

  vec_free (satd);
}

static void
iptfs_satd_cleanup_outbound (void *_satd)
{
  vlib_main_t *vm = vlib_get_main ();
  iptfs_sa_data_t *satd = (iptfs_sa_data_t *) _satd;
  u32 cc_inb_sa_index = ~0;
  u32 count;

  /*
   * If we had a paired inbound SA, disassociate and release the lock
   */
  if (satd->tfs_cc)
    {
      cc_inb_sa_index = satd->tfs_encap.cc_inb_sa_index;
      iptfs_sa_data_t *in_satd = iptfs_get_sa_data (cc_inb_sa_index);
      ASSERT (in_satd->tfs_rx.cc_out_sa_index == iptfs_sa_data_to_index (satd));
      in_satd->tfs_rx.cc_out_sa_index = ~0;
    }

  /* No reason to lock anything as nothing should be using it, now */

  count = iptfs_bufq_n_enq (&satd->tfs_encap.outq) + (satd->tfs_encap.infirst != ~0u);
  iptfs_log ("%s: outbound TFS SA, freeing resources: bufq count %u", __FUNCTION__, count);
  if (count)
    {
      /* Need to empty the queue */
      u32 *bi = NULL, *sz = NULL;
      vec_validate (bi, count);
      vec_validate (sz, count);
      (void) iptfs_bufq_ndequeue (&satd->tfs_encap.outq, bi, sz, count);
      if (satd->tfs_encap.infirst != ~0u)
	bi[count++] = satd->tfs_encap.infirst;
      iptfs_debug ("OUTBOUND TFS SA, freeing %u buffers from encap queue", count);
      iptfs_buffer_free (vm, bi, count);
      vec_free (bi);
      vec_free (sz);
    }

  iptfs_bufq_free (&satd->tfs_encap.outq);

  iptfs_zpool_free (vm, satd->tfs_encap.zpool);
  iptfs_zpool_free (vm, satd->tfs_tx.zpool);

  /* Free our scratch vector for encap building */
  ASSERT (vec_len (satd->tfs_encap.buffers) == 0);
  vec_free (satd->tfs_encap.buffers);

  /* Debug */
  clib_memset (satd, 0xDA, sizeof (*satd));

  vec_free (satd);

  /* Release any lock we may have had on an inbound SA */
  if (cc_inb_sa_index != ~0)
    ipsec_sa_unlock (cc_inb_sa_index);
}

/*
 * iptfs_tfs_data_fixup -
 * use tfs_byterate and tfs_mtu to fix tfs_prate
 * use tfs_max_delay and tfs_bitrate to fixup tfs_encap.q_max_size.
 */
static void
iptfs_tfs_data_cleanup (u32 sa_index)
{
  /* Log an event with our data for this run */
  ELOG_TYPE_DF (iptfs_data_cleanup_e);
  ELOG (vlib_global_main.elog_main, iptfs_data_cleanup_e, sa_index);

  /*
   * ipsec_sa_delete() calls us indiscriminately
   */
  if (!iptfs_is_sa_index_valid (sa_index))
    return;

  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);

  /* Need to re-enable the deferred code if this changes */
  if (!vlib_thread_is_main_w_barrier ())
    {
      iptfs_debug ("%s: called outside of barrier", __func__);
      os_panic ();
    }

  iptfs_debug ("%s: TFS cleanup sa_index %u satd %p", __FUNCTION__, sa_index, satd);

  ASSERT (ipsec_sa_index_is_IPTFS (&ipsec_main, sa_index));
  ASSERT (!satd->tfs_input_running);
  ASSERT (!satd->tfs_output_running);
  ASSERT (!satd->tfs_encap_zpool_running);
  ASSERT (!satd->tfs_output_zpool_running);

  clib_memset ((void *) satd->tfs_config, 0xDA, sizeof (*satd->tfs_config));
  clib_mem_free ((void *) satd->tfs_config);
  satd->tfs_config = NULL;

  iptfs_sa_data_t *copy = vec_new (iptfs_sa_data_t, 1);
  clib_memcpy_fast (copy, satd, sizeof (*satd));
  /* overwrite the iptfs data to destect missued */
  clib_memset (satd, 0xDA, sizeof (*satd));

  ipsec_sa_t *sa = ipsec_sa_get (sa_index);
  /*
   * We do *not* want to defer cleanup. Currently when SA is being deleted
   * there are no workers running. So we need to empty our queues now,
   * otherwise they will start emptying when workers start up again.
   *
   * This does *not* work for DPDK cryptodev or any other offload queues. That
   * needs to also be handled by those devices.
   *
   * The right way to do this is to turn off the SA processing, and then defer
   * it's cleanup until all packets have been processed that might have been
   * queued from that SA. This needs to be done in ipsec generic code.
   */
  if (ipsec_sa_is_set_IS_INBOUND (sa))
    iptfs_satd_cleanup_inbound (copy);
  else
    iptfs_satd_cleanup_outbound (copy);
}

/*
 * Enable an SA to be processed on a polling node.
 */
static void
iptfs_node_set_sa_running (u32 sa_index, u32 poller_index, u32 thread_index, bool running)
{
  vlib_main_t *vm = vlib_get_main_by_index (thread_index);
  iptfs_thread_main_t *tm = vec_elt_at_index (ipsec_iptfs_main.workers_main, thread_index);

  const char *name;
  u32 node_index;
  switch (poller_index)
    {
    case IPTFS_POLLER_OUTPUT:
      name = "output";
      node_index = iptfs_output_node.index;
      break;
    case IPTFS_POLLER_PACER:
      name = "pacer";
      node_index = iptfs_pacer_node.index;
      break;
    case IPTFS_POLLER_ZPOOL:
      name = "zpool";
      node_index = iptfs_zpool_poll_node.index;
      break;
    case IPTFS_POLLER_ENCAP_ONLY:
      name = "encap-only";
      node_index = ~0;
      break;
    default:
      ASSERT (0);
    }

  iptfs_debug ("%s: sa_index %u set running %u for node %s on thread %u", __func__, sa_index,
	       running, name, thread_index);

  if (running)
    {
      ASSERT (vec_search (tm->sa_active[poller_index], sa_index) == ~0);
      vec_add1 (tm->sa_active[poller_index], sa_index);
      if (vec_len (tm->sa_active[poller_index]) == 1 && node_index != ~0)
	{
	  vlib_node_set_state (vm, node_index, VLIB_NODE_STATE_POLLING);

	  iptfs_debug ("%s: start polling node %s on thread %u", __func__, name, thread_index);
	}
    }
  else
    {
      uint i = vec_search (tm->sa_active[poller_index], sa_index);
      ASSERT (i != ~0u);
      vec_del1 (tm->sa_active[poller_index], i);
      if (!vec_len (tm->sa_active[poller_index]) && node_index != ~0)
	{
	  vlib_node_set_state (vm, node_index, VLIB_NODE_STATE_DISABLED);

	  iptfs_debug ("%s: stop polling node %s on thread %u", __func__, name, thread_index);
	}
    }
}

static void
iptfs_start_stop_running (u32 sa_index, bool start)
{
  ipsec_sa_t *sa = ipsec_sa_get (sa_index);
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);

  ASSERT (vlib_thread_is_main_w_barrier ());

  if (ipsec_sa_is_set_IS_INBOUND (sa))
    {
      satd->tfs_input_running = start;
    }
  else if (satd->tfs_mode_type != IPTFS_MODE_TYPE_ENCAP_ONLY && satd->tfs_cc &&
	   satd->tfs_encap.cc_inb_sa_index == INDEX_INVALID)
    iptfs_warn ("Can't %s TFS processing for CC outbound SA %U b/c no paired inbound",
		start ? "Start" : "Stop", format_ipsec_sa, sa_index, IPSEC_FORMAT_BRIEF);
  else
    {
      iptfs_debug ("%s: %s TFS processing for outbound SA %U", __FUNCTION__,
		   start ? "Start" : "Stop", format_ipsec_sa, sa_index, IPSEC_FORMAT_BRIEF);
      if (satd->tfs_encap.zpool_thread_index != 0)
	{
	  iptfs_node_set_sa_running (sa_index, IPTFS_POLLER_ZPOOL,
				     satd->tfs_encap.zpool_thread_index, start);

	  satd->tfs_encap_zpool_running = start;
	}

      if (satd->tfs_tx.zpool_thread_index != 0)
	{
	  if (satd->tfs_tx.zpool_thread_index != satd->tfs_encap.zpool_thread_index)
	    iptfs_node_set_sa_running (sa_index, IPTFS_POLLER_ZPOOL,
				       satd->tfs_tx.zpool_thread_index, start);

	  satd->tfs_output_zpool_running = start;
	}

      if (satd->tfs_mode_type == IPTFS_MODE_TYPE_ENCAP_ONLY)
	for (uint i = 0; i < vlib_thread_main.n_vlib_mains; i++)
	  {
	    iptfs_node_set_sa_running (sa_index, IPTFS_POLLER_ENCAP_ONLY, i, start);
	  }
      else
	{
	  /* Set an initial RTO of 2 seconds */
	  if (satd->tfs_cc)
	    {
	      /* XXX should use the thread we are doing encap on? */
	      f64 clockspersec = vlib_get_main ()->clib_time.clocks_per_second;
	      satd->tfs_encap.cc_rto = (2 * clockspersec);
	      satd->tfs_encap.cc_rto_ts = clib_cpu_time_now ();
	    }
	  satd->tfs_output_running = start;
	  iptfs_node_set_sa_running (sa_index, IPTFS_POLLER_OUTPUT,
				     satd->tfs_encap.output_thread_index, start);

	  /* Start pacer on all RED side RX threads */
	  iptfs_node_set_sa_running (sa_index, IPTFS_POLLER_PACER,
				     satd->tfs_encap.encap_thread_index, start);
	}
    }
}

/*
 * Called when SA is attached/detached to/from a protect policy
 *
 * Policy is added and removed within the worker barrier.
 */
static clib_error_t *
iptfs_add_del_policy (u32 sa_index, u8 is_add)
{
  if (INDEX_INVALID == sa_index)
    return 0;

  if (!ipsec_sa_index_is_IPTFS (&ipsec_main, sa_index))
    {
      iptfs_debug ("%s: No IP-TFS", __FUNCTION__);
      return 0;
    }

  bool got_barrier = false;
  ASSERT (vlib_get_thread_index () == 0);
  if (vlib_num_workers () && !vlib_thread_is_main_w_barrier ())
    {
      vlib_worker_thread_barrier_sync (vlib_get_main ());
      got_barrier = true;
    }

  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);

  iptfs_debug ("%s: Entered sa_index %u is_add %d use_count %u", __FUNCTION__, sa_index, is_add,
	       satd->tfs_use_count);

  if (!is_add)
    {
      /* Log an event with our data for this run */
      ELOG_TYPE_DF (iptfs_delete_policy_e);
      ELOG (vlib_global_main.elog_main, iptfs_delete_policy_e, sa_index);

      ASSERT (satd->tfs_use_count > 0);
      if (!--satd->tfs_use_count)
	{
	  /* Log an event with our data for this run */
	  ELOG_TYPE_DF (iptfs_delete_last_policy_e);
	  ELOG (vlib_global_main.elog_main, iptfs_delete_last_policy_e, sa_index);

	  iptfs_start_stop_running (sa_index, false);
	}
    }
  else
    {
      /* Log an event with our data for this run */
      ELOG_TYPE_DF (iptfs_add_policy_e);
      ELOG (vlib_global_main.elog_main, iptfs_add_policy_e, sa_index);

      if (!satd->tfs_use_count++)
	{
	  /* Log an event with our data for this run */
	  ELOG_TYPE_DF (iptfs_add_first_policy_e);
	  ELOG (vlib_global_main.elog_main, iptfs_add_first_policy_e, sa_index);

	  iptfs_start_stop_running (sa_index, true);
	}
    }

  if (got_barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());

  iptfs_debug ("%s: Exiting", __FUNCTION__);
  return 0;
}

/*
 * Old ipsec_sa_get_sw_if_index() is obsolete. Just force failure
 * return value here.
 */
#define ipsec_sa_get_sw_if_index(vnm, sa_index) ((u32) ~0)

/* Called for intf detatch, admin-up/admin-down */
static clib_error_t *
iptfs_add_del_sess (u32 sa_index, u8 is_add)
{
  /*
   * XXX this functionality will go away in VPP 20.01
   *
   * We may want some sort of replacement, but it's only for DF ipsec0 tunnel
   * case to adjust the MTU to avoid too large packets.
   */

  if (!ipsec_sa_index_is_IPTFS (&ipsec_main, sa_index))
    {
      iptfs_debug ("%s: No IP-TFS", __FUNCTION__);
      return 0;
    }

  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);

  iptfs_debug ("%s: Entered sa_index %u is_add %d use_count %u", __FUNCTION__, sa_index, is_add,
	       satd->tfs_use_count);

  bool got_barrier = false;
  ASSERT (vlib_get_thread_index () == 0);
  if (vlib_num_workers () && !vlib_thread_is_main_w_barrier ())
    {
      vlib_worker_thread_barrier_sync (vlib_get_main ());
      got_barrier = true;
    }

  if (!is_add)
    {
      ASSERT (satd->tfs_use_count > 0);
      if (!--satd->tfs_use_count)
	iptfs_start_stop_running (sa_index, false);
    }

  if (is_add)
    {
      /*
       * If we have don't frag set, set tunnel MTU
       * need to fetch intf index using inbound SA
       * (remote SPI and remote ADDR for key)
       */
      ipsec_sa_t *sa = ipsec_sa_get (sa_index);
      if (satd->tfs_df && satd->tfs_mtu && ipsec_sa_is_set_IS_INBOUND (sa))
	{
	  vnet_main_t *vnm = vnet_get_main ();
	  u32 sw_if_index = ipsec_sa_get_sw_if_index (vnm, sa_index);
	  if (sw_if_index == (u32) ~0)
	    clib_warning ("%s: no interface for sa_index %d to set MTU", __FUNCTION__, sa_index);
	  else
	    {
	      iptfs_debug ("%s: setting MTU to %u for interface %u for sa_index %u", __FUNCTION__,
			   satd->tfs_mtu, sw_if_index, sa_index);

	      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);

	      satd->tfs_old_mtu = si->mtu[VNET_MTU_L3];

	      /* XXX we want to register a callback to notice changes here! */
	      // call_sw_interface_mtu_change_callbacks (vnm, sw_if_index);

	      /*
	       * Set our L3 MTU to our payload size. If an IP packet would
	       * exceed this then it will be pre-fragmented then.
	       */
	      u16 mtu = satd->tfs_mtu - iptfs_sa_data_hdrlen (satd);
	      vnet_sw_interface_set_mtu (vnm, sw_if_index, mtu);
	    }
	}
    }
  else
    {
      /* Restore MTU if we changed it */
      if (satd->tfs_old_mtu)
	{
	  vnet_main_t *vnm = vnet_get_main ();
	  u32 sw_if_index = ipsec_sa_get_sw_if_index (vnm, sa_index);
	  if (sw_if_index == (u32) ~0)
	    clib_warning ("%s: no interface for sa_index %d to restore MTU", __FUNCTION__,
			  sa_index);
	  else
	    {
	      iptfs_debug ("%s: restoring MTU to %u for interface %u for sa_index %u", __FUNCTION__,
			   satd->tfs_old_mtu, sw_if_index, sa_index);
	      vnet_sw_interface_set_mtu (vnm, sw_if_index, satd->tfs_old_mtu);
	      satd->tfs_old_mtu = 0;
	    }
	}
    }

  if (is_add && !satd->tfs_use_count++)
    iptfs_start_stop_running (sa_index, true);

  if (got_barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());

  iptfs_debug ("%s: Exiting", __FUNCTION__);
  return 0;
}

static clib_error_t *
iptfs_add_del_sa (u32 sa_index, void *tfs_config, u8 is_add)
{
  if (!iptfs_is_sa_index_possible_IPTFS (sa_index))
    {
      iptfs_debug ("%s: No IP-TFS (sa_index %u)", __FUNCTION__, sa_index);
      return 0;
    }

  ipsec_iptfs_config_t *conf = (ipsec_iptfs_config_t *) tfs_config;

  clib_warning ("%s: Entered sa_index %u is_add %d tfs_config %p", __FUNCTION__, sa_index, is_add,
		conf);

  bool got_barrier = false;
  ASSERT (vlib_get_thread_index () == 0);
  if (vlib_num_workers () && !vlib_thread_is_main_w_barrier ())
    {
      vlib_worker_thread_barrier_sync (vlib_get_main ());
      got_barrier = true;
    }

  if (is_add)
    iptfs_tfs_data_init (sa_index, conf);
  else
    {
      ASSERT (conf == NULL);
      iptfs_tfs_data_cleanup (sa_index);
    }

  if (got_barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());

  iptfs_debug ("%s: Exiting", __FUNCTION__);
  return 0;
}

static void
iptfs_tunnel_check_running (u32 sa_index, bool enabled)
{
#ifdef IPTFS_DEBUG
  ipsec_sa_t *sa = ipsec_sa_get (sa_index);
  iptfs_assert (ipsec_sa_is_IPTFS (sa));
  iptfs_assert (!ipsec_sa_is_set_IS_INBOUND (sa));
#endif
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
  if (enabled && !satd->tfs_output_running)
    iptfs_add_del_sess (sa_index, true);
  else if (!enabled && satd->tfs_output_running)
    iptfs_add_del_sess (sa_index, false);
}

static clib_error_t *
iptfs_sw_interface_up_down (vnet_main_t *vnm, u32 sw_if_index, u32 flags)
{
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  bool enabled = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  u32 sa_index;

  iptfs_debug ("sw_if_index %d enabled %d", sw_if_index, enabled);

  if (sw_if_index >= vec_len (tfsm->if_to_sa))
    return 0;
  if ((sa_index = tfsm->if_to_sa[sw_if_index]) == ~0)
    return 0;

  iptfs_tunnel_check_running (sa_index, enabled);
  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (iptfs_sw_interface_up_down);

static void
iptfs_tunnel_feature_set (void *_itp, u8 enabled)
{
  vnet_main_t *vnm = vnet_get_main ();
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  ipsec_tun_protect_t *itp = _itp;
  u32 sw_if_index = itp->itp_sw_if_index;
  u32 sa_index = itp->itp_out_sa;

  iptfs_debug ("sw_if_index %u enabled %u", sw_if_index, enabled);

  /* maintain an sw_if_index to output SA map */
  vec_validate_init_empty (tfsm->if_to_sa, sw_if_index, ~0);
  if (enabled)
    tfsm->if_to_sa[sw_if_index] = sa_index;
  else
    tfsm->if_to_sa[sw_if_index] = ~0;

  /*
   * use feature names instead of indices: lower risk of error
   */

  vnet_feature_enable_disable ("ip4-output", "iptfs-encap4-tun", sw_if_index, enabled, &sa_index,
			       sizeof (sa_index));

  vnet_feature_enable_disable ("ip6-output", "iptfs-encap6-tun", sw_if_index, enabled, &sa_index,
			       sizeof (sa_index));

  /* We want to watch for up/down on the ipsec interface */
  if (enabled)
    iptfs_sw_interface_up_down (vnm, sw_if_index, vnet_sw_interface_get_flags (vnm, sw_if_index));
  else
    iptfs_tunnel_check_running (sa_index, false);

#ifdef IPTFS_ENCRYPT_PREOUTPUT
  vnet_feature_enable_disable ("ip4-output", "iptfs-output-enq4-tun", sw_if_index, enabled,
			       &sa_index, sizeof (sa_index));

  vnet_feature_enable_disable ("ip6-output", "iptfs-output-enq6-tun", sw_if_index, enabled,
			       &sa_index, sizeof (sa_index));
#endif
}

/* non-inline this hugish function (for our pathalogical case) */
void
iptfs_buffer_free (vlib_main_t *vm, u32 *buffers, u32 n_buffers)
{
  vlib_buffer_free (vm, buffers, n_buffers);
}

#ifdef IPTFS_DEBUG_CORRUPTION
static void
iptfs_dump_thread_debug_strings (iptfs_thread_main_t *tm)
{
  u32 end = tm->debug_idx;
  u32 thread_index = tm - ipsec_iptfs_main.workers_main;
  u32 count = 0;
  for (u32 i = end; i < IPTFS_DEBUG_STRING_COUNT; i++)
    if (tm->debug_strings[i])
      clib_warning ("\nTHREAD: %u DEBUG_DUMP %u:%s\n", thread_index, count++, tm->debug_strings[i]);
  for (u32 i = 0; i < end; i++)
    if (tm->debug_strings[i])
      clib_warning ("\nTHREAD: %u DEBUG_DUMP %u:%s\n", thread_index, count++, tm->debug_strings[i]);
}
#endif

void
iptfs_dump_debug_strings (i32 thread_index)
{
#ifdef IPTFS_DEBUG_CORRUPTION
  if (thread_index == -1)
    thread_index = vlib_get_thread_index ();

  iptfs_dump_thread_debug_strings (&ipsec_iptfs_main.workers_main[thread_index]);
#endif
}

void
iptfs_dump_debug_all_strings ()
{
#ifdef IPTFS_DEBUG_CORRUPTION
  iptfs_thread_main_t *tm;

  vec_foreach (tm, ipsec_iptfs_main.workers_main)
    {
      iptfs_dump_thread_debug_strings (tm);
    }
#endif
}

/**
 * @brief worker ranges
 *
 */
static clib_error_t *
iptfs_set_worker_range (iptfs_worker_range_t *range, uint first, const uint *lastp)
{
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  uint last = lastp ? *lastp : first;

  first++, last++;
  if (first > last)
    return clib_error_return (0, "err, worker range first > last");
  if (first < tfsm->worker_range.first || last > tfsm->worker_range.last)
    return clib_error_return (0, "err, worker range outside boundary");
  range->first = range->next = first;
  range->last = last;

#ifdef IPTFS_DEBUG
  const char *rname;
  switch (range - tfsm->wk_ranges)
    {
#define _(n, s)                                                                                    \
  case n:                                                                                          \
    rname = s;                                                                                     \
    break;
      foreach_iptfs_wk_range_type
#undef _
	default : rname = "unknown";
      break;
    }
  iptfs_debug ("new worker range: %s %u %u", rname, range->first, range->last);
#endif
  return 0;
}

static clib_error_t *
iptfs_worker_ranges_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      error = clib_error_return (0, "'help iptfs worker range");
      return error;
    }

  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      u32 first, last;
      if (0)
	; /* clang-format off */
#define _(n, s)                                                       \
      else if (unformat (line_input, s " %u %u", &first, &last))           \
        iptfs_set_worker_range (&tfsm->wk_ranges[n], first, &last);   \
      else if (unformat (line_input, s " %u", &first))                     \
        iptfs_set_worker_range (&tfsm->wk_ranges[n], first, NULL);
      foreach_iptfs_wk_range_type
#undef _
      else
        {
          error = clib_error_return (0, "err, unknown worker range config");
          goto done;
        }
      /* clang-format on */
    }
done:
  unformat_free (line_input);
  return error;
}

/**
 * @brief CLI command to enable/disable the etfs3 decap plugin.
 */
VLIB_CLI_COMMAND (iptfs_worker_ranges_command, static) = {
  .path = "iptfs worker ranges",
  .function = iptfs_worker_ranges_cli,
  .short_help = "iptfs worker ranges range-type first last [range-type "
		"first last ...]",
  .long_help = "iptfs worker ranges range-type first last [range-type first "
	       "last ...]\n"
	       "   range-type is one of:"
	       " encap decap decrypt output zpool",
  /*
   * The documentation parsing scripts can't handle the
   * following construct, so we have to encode the string
   * literally above:
   * #define _(n, s) " " s
   *   foreach_iptfs_wk_range_type
   * #undef _
   */
};

void
iptfs_clear_counters (void)
{
  for (uint i = 0; i < IPTFS_CNT_N_COUNTERS; i++)
    vlib_clear_simple_counters (&ipsec_iptfs_main.cm[i]);
  for (uint i = 0; i < IPTFS_PCNT_N_COUNTERS; i++)
    vlib_clear_combined_counters (&ipsec_iptfs_main.pcm[i]);
}

/**
 * @brief clear stats
 *
 */
static clib_error_t *
iptfs_clear_counters_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    error = clib_error_return (0, "err, help clear iptfs counters, for help");
  else
    iptfs_clear_counters ();

  unformat_free (line_input);
  return error;
}

/**
 * @brief CLI command to enable/disable the etfs3 decap plugin.
 */
VLIB_CLI_COMMAND (iptfs_clear_counters_command, static) = {
  .path = "clear iptfs counters",
  .function = iptfs_clear_counters_cli,
  .short_help = "clear iptfs counters",
  .long_help = "clear iptfs counters",
};

u32 iptfs_pkt_type_debug_mask;

/*
 * name -> mask lookup table
 */
struct iptfs_pt_dbg_name_to_mask
{
  char *name;
  u32 mask;
} iptfs_pt_dbg_n2m[] = {
#define _(s, t) { s, IPTFS_PT_DBG_##t },
  foreach_pt_debug_type
#undef _
};

char *
iptfs_pkt_type_debug_str (uint index)
{
  ASSERT (index < IPTFS_PT_DEBUG_FLAG_BIT_MAX);
  return iptfs_pt_dbg_n2m[index].name;
}

/**
 * @brief debug
 *
 */
static clib_error_t *
iptfs_debug_cli (vlib_main_t *vm, unformat_input_t *_input, vlib_cli_command_t *cmd)
{
  unformat_input_t line;
  clib_error_t *error = NULL;

  if (!unformat_user (_input, unformat_line_input, &line))
    return 0;

  while (unformat_check_input (&line) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&line, "enable packet"))
	iptfs_pkt_debug = true;
      else if (unformat (&line, "disable packet"))
	iptfs_pkt_debug = false;
      else if (unformat (&line, "show packet"))
	vlib_cli_output (vm, "debug packet: %s\n", (iptfs_pkt_debug ? "enabled" : "disabled"));

#define _(s, t)                                                                                    \
  else if (unformat (&line, "enable pt " s)) iptfs_pkt_type_debug_mask |= IPTFS_PT_DBG_##t;        \
  else if (unformat (&line, "disable pt " s)) iptfs_pkt_type_debug_mask &= ~IPTFS_PT_DBG_##t;
      foreach_pt_debug_type
#undef _

	else if (unformat (&line, "show pt"))
      {
	bool ena;

#define _(s, t)                                                                                    \
  ena = (iptfs_pkt_type_debug_mask & IPTFS_PT_DBG_##t);                                            \
  vlib_cli_output (vm, "%s%s\n", (ena ? "ON  " : "off "),                                          \
		   iptfs_pkt_type_debug_str (IPTFS_PT_DEBUG_FLAG_BIT_##t));
	foreach_pt_debug_type
#undef _
      }
      else if (unformat (&line, "enable")) iptfs_debug = true;
      else if (unformat (&line, "disable")) iptfs_debug = false;
      else if (unformat (&line, "show"))
	vlib_cli_output (vm, "debug: %s\n", (iptfs_debug ? "enabled" : "disabled"));
      else
      {
	error = clib_error_return (0, "err, unknown command");
	goto done;
      }
    }
done:
  unformat_free (&line);
  return error;
}

/**
 * @brief CLI command to enable/disable the etfs3 decap plugin.
 */
VLIB_CLI_COMMAND (iptfs_debug_command, static) = {
  .path = "iptfs debug",
  .function = iptfs_debug_cli,
  .short_help = "iptfs debug enable|disable|show [packet]|[pt <type>]",
  .long_help = "iptfs debug enable|disable|show [packet]|[pt <type>]",
};

void
iptfs_skip_thread_index (iptfs_worker_range_t *range)
{
  if (range->first == 0)
    return;
  if (++range->next > range->last)
    range->next = range->first;
}

u32
iptfs_next_thread_index (iptfs_worker_range_t *range, u32 thread_index)
{
  iptfs_worker_range_t *wrange = &ipsec_iptfs_main.worker_range;
  if (thread_index != 0)
    {
      if (thread_index >= wrange->first && thread_index <= wrange->last)
	return thread_index;

      clib_warning ("%s: requested worker thread index %u out of range [%u,%u]", __FUNCTION__,
		    thread_index, wrange->first, wrange->last);
    }

  if (range->first == 0)
    return 0;

  thread_index = range->next++;
  if (range->next > range->last)
    range->next = range->first;

  return thread_index;
}

clib_error_t *
iptfs_backend_update ()
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;

  /* Causes address sanitizer to fail? */
  iptfs_debug ("encrypt node %v", vlib_get_node (vm, im->esp4_encrypt_node_index)->name);

  iptfs_output_backend_update ();
  iptfs_encap_backend_update ();
  return 0;
}

static void
iptfs_add_feature (const char *arc_name, const char *node_name, u32 *out_feature_index)
{
  u8 arc;

  arc = vnet_get_feature_arc_index (arc_name);
  ASSERT (arc != (u8) ~0);
  *out_feature_index = vnet_get_feature_index (arc, node_name);
  iptfs_debug ("node \"%s\" on arc \"%s\" has feature index %d", node_name, arc_name,
	       *out_feature_index);
}

/**
 * @brief Initialize the ipsec_iptfs plugin.
 */
static clib_error_t *
ipsec_iptfs_init (vlib_main_t *vm)
{
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  ipsec_main_t *im = &ipsec_main;
  vlib_thread_registration_t *tr;

  /* iptfs_api_hookup (vm); */ /* duplicate? */

  iptfs_debug ("%s: Entered", __FUNCTION__);
  (void) vlib_time_now (vm); /* Update cps values in clib_main */
  iptfs_debug ("%s: clocks-per-sec %f clocks-per-nanosec %.6f", __FUNCTION__,
	       vm->clib_time.clocks_per_second, (f64) vm->clib_time.clocks_per_second / 1e9);

  /*
   * Initialize counters
   */

  /* clang-format off */
  {
#define _(E, n)         \
  tfsm->cm[E].name = n; \
  tfsm->cm[E].stat_segment_name = "/net/ipsec/sa/iptfs/" n;
  foreach_iptfs_counter
#undef _

#define _(E, n)          \
  tfsm->pcm[E].name = n; \
  tfsm->pcm[E].stat_segment_name = "/net/ipsec/sa/iptfs/" n;
      foreach_iptfs_pcounter
#undef _
  } /* clang-format on */

  /*
   * Register with ipsec
   */

  im->tfs_check_support_cb = iptfs_check_support;
  im->tfs_unformat_config_cb = unformat_iptfs_config;
  im->tfs_format_config_cb = format_iptfs_config;
  im->tfs_format_data_cb = format_iptfs_data;
  im->tfs_add_del_sa_cb = iptfs_add_del_sa;
  im->tfs_add_del_policy_cb = iptfs_add_del_policy;
  im->tfs_tunnel_feature_set_cb = iptfs_tunnel_feature_set;
#ifdef IPTFS_DEBUG_CORRUPTION
  im->tfs_encrypt_debug_cb = iptfs_output_encrypt_debug;
#endif

  ipsec_add_node (vm, "iptfs-encap-enq", "ipsec4-output-feature", &im->tfs_encap_node_index,
		  &im->tfs_encap_next_index);
  ipsec_add_node (vm, "iptfs-encap-enq", "ipsec6-output-feature", &im->tfs_encap_node_index,
		  &im->tfs_encap_next_index);

  ipsec_register_next_header (vm, IP_PROTOCOL_AGGFRAG, "iptfs-decap-reorder");

  iptfs_add_feature ("ip4-output", "iptfs-encap4-tun", &tfsm->encap4_tun_feature_index);
  iptfs_add_feature ("ip6-output", "iptfs-encap6-tun", &tfsm->encap6_tun_feature_index);

#ifdef IPTFS_ENCRYPT_PREOUTPUT
  iptfs_add_feature ("ip4-output", "iptfs-output-enq4-tun", &tfsm->output_enq4_tun_feature_index);
  iptfs_add_feature ("ip6-output", "iptfs-output-enq6-tun", &tfsm->output_enq6_tun_feature_index);
#endif

  /* XXX need to maybe add iptfs-output-enq to a feature arc or dpoi */

  /*
   * Get worker range for auto placement.
   *
   * Assumes:
   *   RED (user) interface is placed on worker 0
   *   BLACK (TFS) interface is placed on worker 1
   * XXX Should make this more generic, counts on 2 interfaces
   * first being RED second being BLACK placed that way.
   */

  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;
  if (!tr || tr->count == 0)
    {
      clib_warning ("WARNING: TFS output cannot be isolated from input, use "
		    "workers > 1");
    }
  else
    {
      uint chunk, leftovers;

      tfsm->worker_range.first = tr->first_index;
      tfsm->worker_range.next = tr->first_index;
      tfsm->worker_range.last = tr->first_index + tr->count - 1;

      /* By default worker 0 is used for encap */
      tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP].first = tr->first_index;
      tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP].next = tr->first_index;
      tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP].last = tr->first_index;

      switch (tr->count)
	{
	case 1:
	  /*
	   * no isolation
	   */
	  clib_warning ("WARNING: TFS output cannot be isolated from input, "
			"use workers > 1");
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL] = tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP];
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT] = tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP];
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP] = tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT];
	  tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT] = tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT];
	  break;
	case 2:
	  /*
	   * partial isolation, rx/tx BLACK, rx/tx RED + zpool
	   */
	  /* decap and zpool overlap on RED interface */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL] = tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP];
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP] = tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP];
	  /* tx/rx BLACK interface */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].first = tr->first_index + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].next = tr->first_index + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].last = tr->first_index + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT] = tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT];
	  break;
	case 3:
#if defined(__aarch64__)
	  /*
	   * Performance configuration for Macchiatobin (or non-caching HW
	   * crypto): keep each rx on worker interface threads.
	   *
	   * partial isolation, 0: rx RED + zpool, 1: rx/tx BLACK, 2: tx RED
	   */

	  /*
	   * Zpool is split so that output zpool is on output thread and encap
	   * zpool is on encap thread.
	   */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL].first = tr->first_index;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL].next = tr->first_index;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL].last = tr->first_index + 1;

	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].first = tr->first_index + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].next = tr->first_index + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].last = tr->first_index + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT] = tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT];

	  /* decap in isolation (performance) */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP].first = tr->first_index + 2;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP].next = tr->first_index + 2;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP].last = tr->first_index + 2;
#else
	  /* This probably performs best if we are SW crypto, but maybe not
	     better than above, need to check out */

	  /*
	   * partial isolation, 0: rx RED + zpool, 1: rx BLACK tx RED, 2: tx
	   * BLACK
	   */
	  /* zpool on rx RED */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL] = tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP];

	  /* decap (tx RED) on rx BLACK */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].first = tr->first_index + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].next = tr->first_index + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].last = tr->first_index + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP] = tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT];
	  /* tx BLACK (isolated) interface */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT].first = tr->first_index + 2;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT].next = tr->first_index + 2;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT].last = tr->first_index + 2;
#endif
	  break;
	default:
	  /*
	   * full isolation (although w/ 4 zpool overlaps rx RED)
	   */
	  /*
	   * IPTFS_ENABLE_ENCAP_MULTITHREAD
	   *
	   * We need to deal with this not being set, in which case we only
	   * have a single encap queue thread.
	   */
#if !IPTFS_ENABLE_ENCAP_MULTITHREAD
#error better code for this case
#endif
	  /*
	   * XXX we need some better way to decide if we want to isolate all
	   * rx/tx or combine the rx black decrypt with decap.
	   * Combining reduces singular throughput but increases overall
	   * bandwidth available in the presence of many tunnels.
	   */

	  if (IPTFS_ENABLE_DECAP_ISOLATION && tr->count >= 5)
	    {
	      /* 11 = chunk 2, leftovers == 1 */
	      chunk = tr->count / 5;
	      leftovers = tr->count % 5;
	    }
	  else
	    {
	      /* 11 = chunk 2, leftovers == 3 */
	      chunk = tr->count / 4;
	      leftovers = tr->count % 4;
	    }

	  /* encap on rx RED threads */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP].first = tr->first_index;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP].next = tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP].first;
	  /* encap gets the penultimate less likely leftover */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP].last =
	    tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP].first + chunk + (leftovers > 2) - 1;

	  /* decrypt rx BLACK threads */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].first =
	    tfsm->wk_ranges[IPTFS_WK_RANGE_ENCAP].last + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].next =
	    tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].first;
	  /* decrypt gets the least likely leftover */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].last =
	    tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].first + (leftovers > 3) + chunk - 1;

	  if (IPTFS_ENABLE_DECAP_ISOLATION && tr->count >= 5)
	    {
	      /* decap in isolation */
	      tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP].first =
		tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].last + 1;
	      tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP].next =
		tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP].first;
	      /* decap gets the penultimate likely leftover */
	      tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP].last =
		tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP].first + chunk + (leftovers > 1) - 1;
	    }
	  else
	    {
	      /*
	       * decrypt is decap, add in the leftovers we normally keep for
	       * decap.
	       */
	      tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT].last += (leftovers > 1);

	      tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP] = tfsm->wk_ranges[IPTFS_WK_RANGE_DECRYPT];
	    }

	  /* output in isolation */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT].first =
	    tfsm->wk_ranges[IPTFS_WK_RANGE_DECAP].last + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT].next =
	    tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT].first;
	  /* output gets the most likely leftover */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT].last =
	    tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT].first + chunk + (leftovers > 0) - 1;

	  /* zpools */
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL].first =
	    tfsm->wk_ranges[IPTFS_WK_RANGE_OUTPUT].last + 1;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL].next = tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL].first;
	  tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL].last =
	    tfsm->wk_ranges[IPTFS_WK_RANGE_ZPOOL].first + chunk - 1;
	  break;
	}
    }
  {
#define _(n, s)                                                                                    \
  iptfs_debug ("worker range: " s " %u %u", tfsm->wk_ranges[n].first, tfsm->wk_ranges[n].last);
    foreach_iptfs_wk_range_type
#undef _
  }

  /*
   * Initialize per thread data.
   */
  vec_validate_init_empty_aligned (tfsm->workers_main, tm->n_vlib_mains,
				   (iptfs_thread_main_t) { 0 }, CLIB_CACHE_LINE_BYTES);
  /*
   * Create a queue for handoff to decap
   */
  tfsm->decap_frame_queue = vlib_handoff_alloc_queues (&(vlib_handoff_alloc_queues_args_t) {
    .node_index = iptfs_decap_node.index,
    .queue_size = IPTFS_DECAP_HANDOFF_QUEUE_SIZE,
  });

#if IPTFS_ENABLE_ENCAP_MULTITHREAD
  tfsm->encap_frame_queue = vlib_handoff_alloc_queues (&(vlib_handoff_alloc_queues_args_t) {
    .node_index = iptfs_encap_handoff_node.index,
    .queue_size = IPTFS_ENCAP_HANDOFF_QUEUE_SIZE,
  });

#endif

  /*
   * Track handoff queues for backend encryption
   */
  tfsm->handoff_queue_by_index = hash_create (0, sizeof (uword));

  /*
   * Wire up our output routine to the backend encrypter
   */
  iptfs_backend_update ();

  return NULL;
}

/* clang-format off */
VLIB_INIT_FUNCTION (ipsec_iptfs_init) = {
  .runs_after = VLIB_INITS ("ipsec_init"),
};
/* clang-format on */
