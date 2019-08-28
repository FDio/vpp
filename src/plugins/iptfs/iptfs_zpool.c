/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019, LabN Consulting, L.L.C.
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * October 3 2019, Christian Hopps <chopps@labn.net>
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vppinfra/ring.h>
#include <vppinfra/time.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <iptfs/ipsec_iptfs.h>
#include <iptfs/iptfs_zpool.h>

#ifndef CLIB_MARCH_VARIANT
char *iptfs_event_type_strings[IPTFS_EVENT_N_TYPES] = {
#define _(sym, string) string,
  foreach_iptfs_event_type
#undef _
};
#endif

#define foreach_iptfs_zpool_error                                                                  \
  _ (ENTER_ENCAP_NOBUF, "IPTFS-encap-zpool-err zpool empty on refill")                             \
  _ (ENCAP_NOBUF, "IPTFS-encap-zpool-err no buffers to fill zpool")                                \
  _ (ENCAP_SHORTBUF, "IPTFS-encap-zpool-err only some buffers to fill zpool")                      \
  _ (ENTER_OUTPUT_NOBUF, "IPTFS-output-zpool-err zpool empty on refill")                           \
  _ (OUTPUT_NOBUF, "IPTFS-output-zpool-err no buffers to fill zpool")                              \
  _ (OUTPUT_SHORTBUF, "IPTFS-output-zpool-err only some buffers to fill zpool")                    \
  _ (UNKNOWN_EVENT, "IPTFS unknown event to pad pool process")

typedef enum
{
#define _(sym, str) IPTFS_ZPOOL_ERROR_##sym,
  foreach_iptfs_zpool_error
#undef _
    IPTFS_ZPOOL_N_ERROR,
} iptfs_zpool_error_t;

static char *iptfs_zpool_error_strings[] = {
#define _(sym, string) string,
  foreach_iptfs_zpool_error
#undef _
};

/*
 * gets buffer pointers to newly allocated buffers
 */
static inline void
iptfs_zpool_get_new_buffers (vlib_main_t *vm, iptfs_zpool_t *zpool, vlib_buffer_t **buffers,
			     u32 n_alloc)
{
  const u32 ring_size = zpool->ring_size;
  u32 tail = zpool->tail;
  u32 new_tail = (tail + n_alloc) & (ring_size - 1);
  u32 n;

  if (tail > new_tail)
    {
      n = clib_min (ring_size - tail, n_alloc);
      vlib_get_buffers (vm, &zpool->buffers[tail], buffers, n);
      tail = 0;
      n_alloc -= n;
      buffers += n;
    }
  if (n_alloc)
    vlib_get_buffers (vm, &zpool->buffers[tail], buffers, n_alloc);
}

static inline u32
iptfs_refill_zpool (vlib_main_t *vm, iptfs_zpool_t *zpool, u32 sa_index, u32 payload_size,
		    bool init)
{
  const u32 ring_size = zpool->ring_size;
  u32 __clib_unused _unused;
  u32 tail, n, nreq;
  bool put = zpool->is_output;
  u32 nelm = iptfs_zpool_get_avail_ht (zpool, &_unused, &tail);

  if (nelm > zpool->trigger)
    return 0;

  nreq = zpool->queue_size - nelm;
  /* We need to let others run too so we limit the number of buffers each time
   */
  if (PREDICT_TRUE (!init))
    {
      if (nreq > (VLIB_FRAME_SIZE << 1))
	nreq = (VLIB_FRAME_SIZE << 1);
    }
  n = vlib_buffer_alloc_to_ring (vm, zpool->buffers, tail, ring_size, nreq);
  if (n)
    {
      if (n < nreq)
	{
	  iptfs_debug ("%s: ZPOOL: less buffers allocated than requested %u<%u", __func__, n, nreq);
	}

      vlib_buffer_t **b, **eb;
      vec_validate (zpool->tmp, n - 1);
      iptfs_zpool_get_new_buffers (vm, zpool, zpool->tmp, n);

      bool is_cc = zpool->is_cc;
      for (b = zpool->tmp, eb = b + n; b < eb; b++)
	{
	  vlib_buffer_t *b0 = *b;
	  /* Initialize the buffers */
	  iptfs_init_buffer (vm, b0, sa_index);
	  /* Zero the packet data but leave length 0 */
	  u8 *payload =
	    put ? vlib_buffer_put_uninit (b0, payload_size) : vlib_buffer_get_current (b0);
	  clib_memset (payload, 0, payload_size);
	  if (is_cc)
	    ((ipsec_iptfs_cc_header_t *) payload)->subtype = IPTFS_SUBTYPE_CC;
	}
      vec_set_len (zpool->tmp, 0);
    }
  else
    {
      iptfs_debug ("%s: got no buffers allocated to the ring", __func__);
    }

  CLIB_MEMORY_STORE_BARRIER ();
  zpool->tail = (tail + n) & (ring_size - 1);

#if IPTFS_ENABLE_PACER_EVENT_LOGS
  /* Log an event with our data for this run */
  ELOG_TYPE_DECLARE (e) = {
    .format = "iptfs-refill-zpool sa_index %d before %d requested %d head "
	      "%d tail %d",
    .format_args = "i4i4i4i4i4",
  };
  u32 *data = IPTFS_ELOGP (&e, zpool->track);
  *data++ = sa_index;
  *data++ = nelm;
  *data++ = nreq;
  *data++ = zpool->head;
  *data++ = zpool->tail;
#endif

  return n;
}

static inline u32
iptfs_node_refill_zpool (vlib_main_t *vm, u32 node_index, iptfs_zpool_t *zpool, u32 sa_index,
			 u32 payload_size)
{
  u32 avail = iptfs_zpool_get_avail (zpool);

  if (PREDICT_FALSE (!avail))
    {
      if (zpool->is_output)
	vlib_node_increment_counter (vm, node_index, IPTFS_ZPOOL_ERROR_ENTER_OUTPUT_NOBUF, 1);
      else
	vlib_node_increment_counter (vm, node_index, IPTFS_ZPOOL_ERROR_ENTER_ENCAP_NOBUF, 1);
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
      /* Log an event with our data for this run */
      ELOG_TYPE_DECLARE (e) = {
	.format = "iptfs-zpool-was-empty sa_index %d",
	.format_args = "i4",
      };
      u32 *data = IPTFS_ELOGP (&e, zpool->err_track);
      *data++ = sa_index;
#endif
    }

  if (avail > zpool->trigger)
    return 0;

  u32 needed = zpool->queue_size - avail;
  u32 n = iptfs_refill_zpool (vm, zpool, sa_index, payload_size, 0);
  if (PREDICT_FALSE (n < needed))
    {
      u32 error;
      if (zpool->is_output)
	error = !n ? IPTFS_ZPOOL_ERROR_OUTPUT_NOBUF : IPTFS_ZPOOL_ERROR_OUTPUT_SHORTBUF;
      else
	error = !n ? IPTFS_ZPOOL_ERROR_ENCAP_NOBUF : IPTFS_ZPOOL_ERROR_ENCAP_SHORTBUF;
      vlib_node_increment_counter (vm, node_index, error, 1);

#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
      /* Log an event with our data for this run */
      ELOG_TYPE_DECLARE (e) = {
	.format = "iptfs-zpool-short-alloc sa_index %d asked %d got %d",
	.format_args = "i4i4i4",
      };
      u32 *data = IPTFS_ELOGP (&e, zpool->err_track);
      *data++ = sa_index;
      *data++ = needed;
      *data++ = n;
#endif
    }

  iptfs_pkt_debug ("%s: refilled: sa_index: %u before %u after %u", __FUNCTION__, sa_index, avail,
		   avail + n);

  return n;
}

static inline u32
iptfs_refill_zbuffers (vlib_main_t *vm, u32 node_index, iptfs_sa_data_t *satd, u32 sa_index,
		       u32 thread_index)
{
  u32 psize = satd->tfs_encap.tfs_ipsec_payload_size;
  u32 npkts = 0;

  if (satd->tfs_tx.zpool_thread_index == thread_index)
    npkts += iptfs_node_refill_zpool (vm, node_index, satd->tfs_tx.zpool, sa_index, psize);
  if (satd->tfs_encap.zpool_thread_index == thread_index)
    npkts += iptfs_node_refill_zpool (vm, node_index, satd->tfs_encap.zpool, sa_index, psize);
  return npkts;
}

/*
 * Allocate a zpool to maintain queue_size zero'd buffers.
 */
#ifndef CLIB_MARCH_VARIANT
iptfs_zpool_t *
iptfs_zpool_alloc (vlib_main_t *vm, u32 queue_size, u32 sa_index, u32 payload_size,
		   bool output_pool, bool is_cc
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
		   ,
		   elog_track_t *track, elog_track_t *err_track
#endif
)
{
  iptfs_zpool_t template = {
    .queue_size = queue_size,
    /* Ring size must always be power of 2 */
    .ring_size = max_pow2 (queue_size + 1),
    /* .trigger =
	queue_size - ((queue_size <= VLIB_FRAME_SIZE * 2) ? queue_size / 8
							  : VLIB_FRAME_SIZE),
    */
    .trigger = queue_size - clib_min (VLIB_FRAME_SIZE, queue_size / 8),
    .is_output = output_pool,
    .is_cc = is_cc,
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
    .track = track,
    .err_track = err_track,
#endif
  };
  iptfs_zpool_t *zpool = clib_mem_alloc_aligned (sizeof (*zpool), CLIB_CACHE_LINE_BYTES);
  clib_memcpy (zpool, &template, sizeof (*zpool));

  vec_validate (zpool->buffers, zpool->ring_size - 1);
  if (queue_size != iptfs_refill_zpool (vm, zpool, sa_index, payload_size, 1))
    {
      iptfs_zpool_free (vm, zpool);
      zpool = NULL;
    }
  return zpool;
}

void
iptfs_zpool_free (vlib_main_t *vm, iptfs_zpool_t *zpool)
{
  /* free buffers in ring */
  u32 head = zpool->head;
  u32 tail = zpool->tail;

  if (head > tail)
    {
      iptfs_buffer_free (vm, &zpool->buffers[head], zpool->ring_size - head);
      head = 0;
    }
  if (head != tail)
    iptfs_buffer_free (vm, &zpool->buffers[head], tail - head);
  vec_free (zpool->buffers);
  clib_mem_free (zpool);
}
#endif

/* ------------------ */
/* ZPOOL Process Node */
/* ------------------ */

static inline void
iptfs_zpool_process_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				 vlib_frame_t *__clib_unused frame)
{
  const uword event_type = IPTFS_EVENT_TYPE_MORE_BUFFERS;
  u32 thread_index = vlib_get_thread_index ();
  uword *event_data = 0;

  while (1)
    {
      (void) vlib_process_wait_for_event_with_type (vm, &event_data, event_type);
      u32 sa_index = event_data[0];
      vec_reset_length (event_data);

      iptfs_debug ("XXX: ZPOOLPROCESS");

      iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
      iptfs_refill_zbuffers (vm, node->node_index, satd, sa_index, thread_index);
      satd->tfs_pad_req_pending = false;
    }
}

VLIB_NODE_FN (iptfs_zpool_process_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  iptfs_zpool_process_node_inline (vm, node, frame);
  /*NOTREACHED*/
  return 0;
}

VLIB_REGISTER_NODE (iptfs_zpool_process_node) = {
  .name = "iptfs-zpool-process",
  .vector_size = sizeof (u32),
  .format_trace = format_iptfs_header_trace,
  .type = VLIB_NODE_TYPE_PROCESS,
  // XXX we don't actually support tracing here, the user will.
  // .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .n_errors = IPTFS_ZPOOL_N_ERROR,
  .error_strings = iptfs_zpool_error_strings,
};

/* ------------------ */
/* ZPOOL Polling Node */
/* ------------------ */

#if IPTFS_ZPOOL_CHECK_NOT_FREE_DEBUG
static inline void
check_sa_pool_not_free_debug (u32 sa_index)
{
  pool_header_t *p = pool_header (ipsec_main.sad);
  int vl = vec_len (ipsec_main.sad);
  ASSERT (sa_index < vl);

  uword i0 = sa_index / BITS (p->free_bitmap[0]);
  uword i1 = sa_index % BITS (p->free_bitmap[0]);
  if (i0 < vec_len (p->free_bitmap))
    ASSERT (!((p->free_bitmap[i0] >> i1) & 1));

  ASSERT (!clib_bitmap_get (p->free_bitmap, sa_index));
}
#endif

static inline u32
iptfs_zpool_poll_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_frame_t *__clib_unused frame)
{
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  u32 thread_index = vlib_get_thread_index ();
  iptfs_thread_main_t *tm = vec_elt_at_index (tfsm->workers_main, thread_index);

  u32 npkts = 0;
  u32 *sap;
  vec_foreach (sap, tm->sa_active[IPTFS_POLLER_ZPOOL])
    {
      u32 sa_index = *sap;
      iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
      ASSERT (satd->tfs_encap_zpool_running || satd->tfs_output_zpool_running);
      npkts += iptfs_refill_zbuffers (vm, node->node_index, satd, sa_index, thread_index);
    }
  return npkts;
}

VLIB_NODE_FN (iptfs_zpool_poll_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return iptfs_zpool_poll_node_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (iptfs_zpool_poll_node) = {
  .name = "iptfs-zpool-poller",
  .vector_size = sizeof (u32),
  .format_trace = format_iptfs_header_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  // XXX we don't actually support tracing here, the user will.
  // .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,

  .n_errors = IPTFS_ZPOOL_N_ERROR,
  .error_strings = iptfs_zpool_error_strings,
};
