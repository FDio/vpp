/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020, LabN Consulting, L.L.C
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * April 5 2020, Christian E. Hopps <chopps@labn.net>
 */
#ifndef __included_iptfs_zpool_h__
#define __included_iptfs_zpool_h__

#include <vlib/vlib.h>

extern vlib_node_registration_t iptfs_zpool_poll_node;
extern vlib_node_registration_t iptfs_zpool_process_node;

/*
 * The ring is always power of 2, and can hold ringsize - 1 elements.
 *
 * So best to ask for 2^N - 1 qsize to be efficient.
 *
 * The code assumes only 1 writer and only 1 reader thread for efficient
 * lock-less operation.
 */
typedef struct iptfs_zpool_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  const u32 queue_size; /* number of zeroed buffers to maintain */
  const u32 ring_size;	/* power of 2 ring size */
  const u32 trigger;	/* reload when queue_size is at or below trigger */
  const bool is_cc;	/* true if should init CC header subtype */
  const bool is_output; /* true if used for output */
  volatile u32 tail;	/* read by one thread, written by zpool */
  volatile u32 head;	/* read by zpool written by one thread */
  u32 *buffers;		/* read by one thread, written by zpool */
  vlib_buffer_t **tmp;	/* internally used when refilling */
#ifdef IPTFS_ENABLE_ZPOOL_EVENT_LOGS
  elog_track_t *track;
  elog_track_t *err_track;
#endif
} iptfs_zpool_t;

always_inline u32
iptfs_zpool_get_avail (iptfs_zpool_t *zpool)
{
  u32 head = zpool->head;
  u32 tail = zpool->tail;

  if (head > tail)
    return zpool->ring_size - (head - tail);
  else
    return tail - head;
}

always_inline u32
iptfs_zpool_get_avail_ht (iptfs_zpool_t *zpool, u32 *hp, u32 *tp)
{
  u32 head = zpool->head;
  u32 tail = zpool->tail;

  *hp = head;
  *tp = tail;

  if (head > tail)
    return zpool->ring_size - (head - tail);
  else
    return tail - head;
}

/*
 * Ping the zpool process, should only be done when running with no workers.
 */
always_inline void
iptfs_zpool_ping_nobuf (vlib_main_t *vm, u32 sa_index, iptfs_sa_data_t *satd)
{
  ASSERT (vlib_num_workers () == 0);
  if (PREDICT_TRUE (satd->tfs_pad_req_pending))
    return;
  satd->tfs_pad_req_pending = true;
  vlib_process_signal_event_mt (vm, iptfs_zpool_process_node.index, IPTFS_EVENT_TYPE_MORE_BUFFERS,
				sa_index);
}

always_inline u32
iptfs_zpool_get_buffer (iptfs_zpool_t *zpool)
{
  u32 bi0 = ~0u;
  u32 head;

  if ((head = zpool->head) != zpool->tail)
    {
      bi0 = zpool->buffers[head++];
      head = head & (zpool->ring_size - 1);

      /* I think we need to do a store barrier prior to updating the head */
      /* XXX although we aren't changing anything else. */
      CLIB_MEMORY_STORE_BARRIER ();
      zpool->head = head;
    }

  return bi0;
}

always_inline u32
iptfs_zpool_get_buffers (iptfs_zpool_t *zpool, u32 *buffers, u32 n_alloc, bool partial_ok)
{
  const u32 ring_size = zpool->ring_size;
  u32 head, tail, n;
  u32 n_avail = iptfs_zpool_get_avail_ht (zpool, &head, &tail);

  if (n_avail < n_alloc)
    {
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
      /* Log an event with our data for this run */
      ELOG_TYPE_DECLARE (event_err_zbuf) = {
	.format = "low/no zbuf req %d avail %d head %d tail %d ringsize %d",
	.format_args = "i4i4i4i4i4",
      };
      u32 *esd = IPTFS_ELOGP (&event_err_zbuf, zpool->track);
      *esd++ = n_alloc;
      *esd++ = n_avail;
      *esd++ = zpool->head;
      *esd++ = zpool->tail;
      *esd++ = zpool->ring_size;
#endif

      if (!n_avail)
	return 0;
      if (!partial_ok)
	return 0;
      n_alloc = n_avail;
    }

  u32 n_need = n_alloc;
  if (head > tail)
    {
      n = clib_min (ring_size - head, n_need);
      clib_memcpy_fast (buffers, &zpool->buffers[head], n * sizeof (u32));
      head = (head + n) & (ring_size - 1);
      n_need -= n;
      buffers += n;
    }
  if (n_need)
    {
      clib_memcpy_fast (buffers, &zpool->buffers[head], n_need * sizeof (u32));
      head = (head + n_need) & (ring_size - 1);
    }

  /* Do we need a store ordering fence here? */
  CLIB_MEMORY_STORE_BARRIER ();
  zpool->head = head;

#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
  /* Log an event with our data for this run */
  ELOG_TYPE_DECLARE (event_get_zbuf) = {
    .format = "get zbuf req %d avail %d head %d tail %d ringsize %d",
    .format_args = "i4i4i4i4i4",
  };
  u32 *esd = IPTFS_ELOGP (&event_get_zbuf, zpool->track);
  *esd++ = n_alloc;
  *esd++ = n_avail;
  *esd++ = zpool->head;
  *esd++ = zpool->tail;
  *esd++ = zpool->ring_size;
#endif

  return n_alloc;
}

extern vlib_node_registration_t iptfs_zpool_poll_node;

iptfs_zpool_t *iptfs_zpool_alloc (vlib_main_t *vm, u32 queue_size, u32 sa_index, u32 payload_size,
				  bool put, bool is_cc
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
				  ,
				  elog_track_t *track, elog_track_t *err_track
#endif
);
void iptfs_zpool_free (vlib_main_t *vm, iptfs_zpool_t *zpool);
#endif /* __included_iptfs_zpool_h__ */
