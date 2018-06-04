/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <avf/avf.h>

#include "/home/damarion/cisco/vpp-sandbox/include/tscmarks.h"
#include <iacaMarks.h>

#define foreach_avf_input_error \
  _(BUFFER_ALLOC, "buffer alloc error") \
  _(RX_PACKET_ERROR, "Rx packet errors") \
  _(DUMMY_DESC, "dummy descriptor")

typedef enum
{
#define _(f,s) AVF_INPUT_ERROR_##f,
  foreach_avf_input_error
#undef _
    AVF_INPUT_N_ERROR,
} avf_input_error_t;

static __clib_unused char *avf_input_error_strings[] = {
#define _(n,s) s,
  foreach_avf_input_error
#undef _
};

#define AVF_RX_DESC_STATUS(x)		(1 << x)
#define AVF_RX_DESC_STATUS_DD		AVF_RX_DESC_STATUS(0)
#define AVF_RX_DESC_STATUS_EOP		AVF_RX_DESC_STATUS(1)

static __clib_unused u8 *
format_avf_rx_desc (u8 * s, va_list * args)
{
  avf_rx_desc_t *d = va_arg (*args, avf_rx_desc_t *);

  s = format (s, "status 0x%llx length %u error 0x%x ptype 0x%x",
	      avf_get_u64_bits ((void *) d, 8, 18, 0),
	      avf_get_u64_bits ((void *) d, 8, 63, 38),
	      avf_get_u64_bits ((void *) d, 8, 26, 19),
	      avf_get_u64_bits ((void *) d, 8, 37, 30));
  return s;
}

static_always_inline uword
avf_get_rx_buffer_dma_addr (vlib_main_t * vm, u32 bi, int use_iova)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_buffer_main_t *bm = &buffer_main;
  vlib_buffer_pool_t *pool;
  if (use_iova)
    return pointer_to_uword (b->data);

  pool = vec_elt_at_index (bm->buffer_pools, b->buffer_pool_index);
  return vlib_physmem_virtual_to_physical (vm, pool->physmem_region, b->data);
}

static inline u64x2
u64x2_zero_and_set_lowest (u64 x)
{
  return (u64x2) _mm_cvtsi64_si128 (x);
}


static_always_inline void
avf_enq_rx_buffer (vlib_main_t * vm, avf_rx_desc_t * d, u32 * bi, int count,
		   int use_iova)
{
  if (count == 4)
    {
      u64 addr0 = avf_get_rx_buffer_dma_addr (vm, bi[0], use_iova);
      u64 addr1 = avf_get_rx_buffer_dma_addr (vm, bi[1], use_iova);
      u64 addr2 = avf_get_rx_buffer_dma_addr (vm, bi[2], use_iova);
      u64 addr3 = avf_get_rx_buffer_dma_addr (vm, bi[3], use_iova);
      //IACA_START;
#ifdef CLIB_HAVE_VEC128
      d[0].as_u64x2[0] = u64x2_zero_and_set_lowest (addr0);
      d[1].as_u64x2[0] = u64x2_zero_and_set_lowest (addr1);
      d[2].as_u64x2[0] = u64x2_zero_and_set_lowest (addr2);
      d[3].as_u64x2[0] = u64x2_zero_and_set_lowest (addr3);
#else
      d[0].qword[0] = addr0;
      d[0].qword[1] = 0;
      d[1].qword[0] = addr1;
      d[1].qword[1] = 0;
      d[2].qword[0] = addr2;
      d[2].qword[1] = 0;
      d[3].qword[0] = addr3;
      d[3].qword[1] = 0;
#endif
      //IACA_END;
    }
  else
    {
      u64 addr0 = avf_get_rx_buffer_dma_addr (vm, bi[0], use_iova);
#ifdef CLIB_HAVE_VEC128
      d[0].as_u64x2[0] = u64x2_zero_and_set_lowest (addr0);
#else
      d[0].qword[0] = addr0;
      d[0].qword[1] = 0;
#endif
    }
}

#define AVF_INPUT_REFILL_TRESHOLD 32
static_always_inline void
avf_rxq_refill (vlib_main_t * vm, vlib_node_runtime_t * node, avf_rxq_t * rxq,
		int use_iova)
{
  u16 n_refill, mask, n_alloc, slot;
  avf_rx_desc_t *d;

  n_refill = rxq->size - 1 - rxq->n_enqueued;
  if (PREDICT_TRUE (n_refill <= AVF_INPUT_REFILL_TRESHOLD))
    return;

  mask = rxq->size - 1;
  slot = (rxq->next - n_refill - 1) & mask;

  n_refill &= ~7;		/* round to 8 */
  n_alloc = vlib_buffer_alloc_to_ring (vm, rxq->bufs, slot, rxq->size,
				       n_refill);

  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      vlib_error_count (vm, node->node_index,
			AVF_INPUT_ERROR_BUFFER_ALLOC, 1);
      if (n_alloc)
	vlib_buffer_free_from_ring_no_next (vm, rxq->bufs, slot, rxq->size,
					    n_alloc);
      return;
    }

  rxq->n_enqueued += n_alloc;

  while (n_alloc)
    {
      d = ((avf_rx_desc_t *) rxq->descs) + slot;

      if (n_alloc < 4 || slot > rxq->size - 4)
	goto one_by_one;

      avf_enq_rx_buffer (vm, d, rxq->bufs + slot, 4, use_iova);

      /* next */
      slot = (slot + 4) & mask;
      n_alloc -= 4;
      continue;

    one_by_one:
      avf_enq_rx_buffer (vm, d, rxq->bufs + slot, 1, use_iova);

      /* next */
      slot = (slot + 1) & mask;
      n_alloc -= 1;
    }

  CLIB_MEMORY_BARRIER ();
  *(rxq->qrx_tail) = (u32) slot;
}

static_always_inline void
avf_check_for_error (vlib_node_runtime_t * node, avf_rx_vector_entry_t * rxve,
		     vlib_buffer_t * b, u16 * next)
{
  avf_main_t *am = &avf_main;
  avf_ptype_t *ptype;
  if (PREDICT_FALSE (rxve->error))
    {
      b->error = node->errors[AVF_INPUT_ERROR_RX_PACKET_ERROR];
      ptype = am->ptypes + rxve->ptype;
      /* retract */
      vlib_buffer_advance (b, -ptype->buffer_advance);
      *next = VNET_DEVICE_INPUT_NEXT_DROP;
    }
}

static_always_inline u32
avf_find_next (avf_rx_vector_entry_t * rxve, vlib_buffer_t * b,
	       int maybe_tagged)
{
  avf_main_t *am = &avf_main;
  ethernet_header_t *e = (ethernet_header_t *) b->data;
  avf_ptype_t *ptype;
  if (maybe_tagged && ethernet_frame_is_tagged (e->type))
    return VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  ptype = am->ptypes + rxve->ptype;
  vlib_buffer_advance (b, ptype->buffer_advance);
  b->flags |= ptype->flags;
  return ptype->next_node;
}


static_always_inline uword
avf_process_rx_burst (vlib_main_t * vm, vlib_node_runtime_t * node,
		      avf_per_thread_data_t * ptd, u32 n_rx_desc,
		      u8 maybe_err, int known_next)
{
  uword n_rx_bytes = 0;
  vlib_buffer_t **b = ptd->buffer_pointers + ptd->skip;
  u32 *bi = ptd->buffer_indices + ptd->skip;
  avf_rx_vector_entry_t *rxve = ptd->rx_vector + ptd->skip;
  u16 *next = ptd->nexts;
  u32 *to_next = ptd->to_next;
#ifdef CLIB_HAVE_VEC512
  u8x64 bt = u8x64_load_unaligned (&ptd->buffer_template);
#elif defined (CLIB_HAVE_VEC256)
  u8x32 bt0 = u8x32_load_unaligned (&ptd->buffer_template);
  u8x32 bt1 = u8x32_load_unaligned (((void *) &ptd->buffer_template) + 32);
#else
  vlib_buffer_t *bt = &ptd->buffer_template;
#endif

  while (n_rx_desc >= 4)
    {
      if (n_rx_desc < 16)
	goto no_prefetch;

      vlib_prefetch_buffer_header (b[12], LOAD);
      vlib_prefetch_buffer_header (b[13], LOAD);
      vlib_prefetch_buffer_header (b[14], LOAD);
      vlib_prefetch_buffer_header (b[15], LOAD);
      if (!known_next)
	{
	  CLIB_PREFETCH (b[12]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b[13]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b[14]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b[15]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	}
    no_prefetch:

#ifdef CLIB_HAVE_VEC512
      u8x64_store_unaligned (bt, b[0]);
      u8x64_store_unaligned (bt, b[1]);
      u8x64_store_unaligned (bt, b[2]);
      u8x64_store_unaligned (bt, b[3]);
#elif defined (CLIB_HAVE_VEC256)
      u8x32_store_unaligned (bt0, b[0]);
      u8x32_store_unaligned (bt1, ((void *) b[0]) + 32);
      u8x32_store_unaligned (bt0, b[1]);
      u8x32_store_unaligned (bt1, ((void *) b[1]) + 32);
      u8x32_store_unaligned (bt0, b[2]);
      u8x32_store_unaligned (bt1, ((void *) b[2]) + 32);
      u8x32_store_unaligned (bt0, b[3]);
      u8x32_store_unaligned (bt1, ((void *) b[3]) + 32);
#else
      clib_memcpy64_x4 (b[0], b[1], b[2], b[3], bt);
#endif
      clib_memcpy (to_next, bi, 4 * sizeof (u32));

      n_rx_bytes += b[0]->current_length = rxve[0].length;
      n_rx_bytes += b[1]->current_length = rxve[1].length;
      n_rx_bytes += b[2]->current_length = rxve[2].length;
      n_rx_bytes += b[3]->current_length = rxve[3].length;

      if (!known_next)
	{
	  ethernet_header_t *e0, *e1, *e2, *e3;

	  e0 = (ethernet_header_t *) b[0]->data;
	  e1 = (ethernet_header_t *) b[1]->data;
	  e2 = (ethernet_header_t *) b[2]->data;
	  e3 = (ethernet_header_t *) b[3]->data;

	  if (ethernet_frame_is_any_tagged_x4 (e0->type, e1->type,
					       e2->type, e3->type))
	    {
	      next[0] = avf_find_next (rxve + 0, b[0], 1);
	      next[1] = avf_find_next (rxve + 1, b[1], 1);
	      next[2] = avf_find_next (rxve + 2, b[2], 1);
	      next[3] = avf_find_next (rxve + 3, b[3], 1);
	    }
	  else
	    {
	      next[0] = avf_find_next (rxve + 0, b[0], 0);
	      next[1] = avf_find_next (rxve + 1, b[1], 0);
	      next[2] = avf_find_next (rxve + 2, b[2], 0);
	      next[3] = avf_find_next (rxve + 3, b[3], 0);
	    }

	  if (maybe_err)
	    {
	      avf_check_for_error (node, rxve + 0, b[0], next + 0);
	      avf_check_for_error (node, rxve + 1, b[1], next + 1);
	      avf_check_for_error (node, rxve + 2, b[2], next + 2);
	      avf_check_for_error (node, rxve + 3, b[3], next + 3);
	    }
	}

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      /* next */
      rxve += 4;
      b += 4;
      next += 4;
      n_rx_desc -= 4;
      to_next += 4;
      bi += 4;
    }
  while (n_rx_desc)
    {
      to_next[0] = bi[0];
#ifdef CLIB_HAVE_VEC512
      u8x64_store_unaligned (bt, b[0]);
#elif defined(CLIB_HAVE_VEC256)
      u8x32_store_unaligned (bt0, b[0]);
      u8x32_store_unaligned (bt1, ((void *) b[0]) + 32);
#else
      clib_memcpy (b[0], bt, 64);
#endif
      n_rx_bytes += b[0]->current_length = rxve->length;

      if (!known_next)
	{
	  next[0] = avf_find_next (rxve, b[0], 1);
	  avf_check_for_error (node, rxve + 0, b[0], next);
	}

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      /* next */
      rxve += 1;
      b += 1;
      next += 1;
      n_rx_desc -= 1;
      to_next += 1;
      bi += 1;
    }
  return n_rx_bytes;
}

/* vector ops expect specific ffsets */
STATIC_ASSERT_SIZEOF (avf_rx_vector_entry_t, 8);
STATIC_ASSERT_OFFSET_OF (avf_rx_vector_entry_t, status, 0);
STATIC_ASSERT_OFFSET_OF (avf_rx_vector_entry_t, length, 4);
STATIC_ASSERT_OFFSET_OF (avf_rx_vector_entry_t, ptype, 6);
STATIC_ASSERT_OFFSET_OF (avf_rx_vector_entry_t, error, 7);

#define AVF_RX_DESC_QW1_STATUS_SHIFT		0
#define AVF_RX_DESC_QW1_STATUS_MASK		((1ULL << 19) - 1)
#define AVF_RX_DESC_QW1_ERROR_SHIFT		19
#define AVF_RX_DESC_QW1_ERROR_MASK		(((1ULL << 8) - 1) << 19)
#define AVF_RX_DESC_QW1_PTYPE_SHIFT		30
#define AVF_RX_DESC_QW1_PTYPE_MASK		(((1ULL << 8) - 1) << 30)
#define AVF_RX_DESC_QW1_LENGTH_SHIFT		38
#define AVF_RX_DESC_QW1_LENGTH_MASK		(((1ULL << 26) - 1) << 38)
#define CLIB_COMPILER_BARRIER() asm volatile("" ::: "memory")

static_always_inline uword
avf_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame, avf_device_t * ad, u16 qid)
{
  avf_main_t *am = &avf_main;
  vnet_main_t *vnm = vnet_get_main ();
  avf_per_thread_data_t *ptd =
    vec_elt_at_index (am->per_thread_data, vm->thread_index);
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);
  uword n_trace;
  avf_rx_desc_t *d;
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  u16 mask = rxq->size - 1;
  u16 n_rx_desc;
  u8 skip, or_error = 0;
  u32 *bi, next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_t *bt = &ptd->buffer_template;
  avf_rx_vector_entry_t *rxv;
  int known_next = 0, i;
#ifdef CLIB_HAVE_VEC256
  u64x4 err0, err1, v, r;
  u64x2 d0, d1, d2, d3;
  u8x32 eop_bits;
  u64x4 status_mask = u64x4_splat (AVF_RX_DESC_QW1_STATUS_MASK);
  u64x4 error_mask = u64x4_splat (AVF_RX_DESC_QW1_ERROR_MASK);
  u64x4 ptype_mask = u64x4_splat (AVF_RX_DESC_QW1_PTYPE_MASK);
  u64x4 length_mask = u64x4_splat (AVF_RX_DESC_QW1_LENGTH_MASK);
  u64x4 eop_mask = u64x4_splat (AVF_RX_DESC_STATUS_EOP);
#endif

  d = rxq->descs + rxq->next;
  if ((d[0].status & AVF_RX_DESC_STATUS_DD) == 0)
    return 0;

  tsc_mark ("parse");
  skip = ptd->skip = rxq->next & 0x7;
  n_rx_desc = 0;
  while (1)
    {
      u16 offset = (rxq->next + n_rx_desc - skip) & mask;
      d = rxq->descs + offset;
      rxv = ptd->rx_vector + n_rx_desc;

      clib_memcpy (ptd->buffer_indices + n_rx_desc, rxq->bufs + offset,
		   8 * sizeof (u32));

      vlib_get_buffers (vm, ptd->buffer_indices + n_rx_desc,
			ptd->buffer_pointers + n_rx_desc, 8);

      //IACA_START;
#ifdef CLIB_HAVE_VEC256
      d3 = u64x2_load_unaligned ((void *) (d + 7));
      CLIB_COMPILER_BARRIER ();
      d2 = u64x2_load_unaligned ((void *) (d + 6));
      v = u64x4_insert_hi (v, u64x2_interleave_hi (d2, d3));
      CLIB_COMPILER_BARRIER ();
      d1 = u64x2_load_unaligned ((void *) (d + 5));
      CLIB_COMPILER_BARRIER ();
      d0 = u64x2_load_unaligned ((void *) (d + 4));
      v = u64x4_insert_lo (v, u64x2_interleave_hi (d0, d1));
      r = v & status_mask;
      r |= err1 = ((v & error_mask) >> AVF_RX_DESC_QW1_ERROR_SHIFT) << 56;
      r |= ((v & ptype_mask) >> AVF_RX_DESC_QW1_PTYPE_SHIFT) << 48;
      r |= ((v & length_mask) >> AVF_RX_DESC_QW1_LENGTH_SHIFT) << 32;
      u64x4_store_unaligned (r, rxv + 4);
      eop_bits = (u8x32) ((v & eop_mask) << 8);

      CLIB_COMPILER_BARRIER ();

      d3 = u64x2_load_unaligned ((void *) (d + 3));
      CLIB_COMPILER_BARRIER ();
      d2 = u64x2_load_unaligned ((void *) (d + 2));
      v = u64x4_insert_hi (v, u64x2_interleave_hi (d2, d3));
      CLIB_COMPILER_BARRIER ();
      d1 = u64x2_load_unaligned ((void *) (d + 1));
      CLIB_COMPILER_BARRIER ();
      d0 = u64x2_load_unaligned ((void *) (d + 0));
      v = u64x4_insert_lo (v, u64x2_interleave_hi (d0, d1));

      r = v & status_mask;
      r |= err0 = ((v & error_mask) >> AVF_RX_DESC_QW1_ERROR_SHIFT) << 56;
      r |= ((v & ptype_mask) >> AVF_RX_DESC_QW1_PTYPE_SHIFT) << 48;
      r |= ((v & length_mask) >> AVF_RX_DESC_QW1_LENGTH_SHIFT) << 32;
      u64x4_store_unaligned (r, rxv);

      if (!u64x4_is_all_zero (err0 | err1))
	or_error = 0xff;

      eop_bits |= (u8x32) (v & eop_mask);
      eop_bits = eop_bits != (u8x32)
      {
      0};			/* not equal to zero to get msb set */
      n_rx_packets += count_set_bits (u8x32_msb_mask (eop_bits));
#else
      for (i = 7; i >= 0; i--)
	{
	  u64 qw1 = d[i].qword[1];
	  rxv[i].status = qw1 & AVF_RX_DESC_QW1_STATUS_MASK;
	  rxv[i].error = ((qw1 & AVF_RX_DESC_QW1_ERROR_MASK) >>
			  AVF_RX_DESC_QW1_ERROR_SHIFT);
	  rxv[i].ptype = ((qw1 & AVF_RX_DESC_QW1_PTYPE_MASK) >>
			  AVF_RX_DESC_QW1_PTYPE_SHIFT);
	  rxv[i].length = ((qw1 & AVF_RX_DESC_QW1_LENGTH_MASK) >>
			   AVF_RX_DESC_QW1_LENGTH_SHIFT);
	  or_error |= rxv[i].error;
	  if (rxv[i].status & AVF_RX_DESC_STATUS_EOP)
	    n_rx_packets++;
	}
#endif
      //IACA_END;
#if 0
      fformat (stderr, "\nn_rx_packets %u\n", n_rx_packets);
      for (i = 0; i < 8; i++)
	{
	  fformat (stderr, "qw1 %lx, statux %x, len %u ptype %u error %x\n",
		   d[i].qword[1], rxv[i].status, rxv[i].length, rxv[i].ptype,
		   rxv[i].error);
	  //if (rxv[i].status & AVF_RX_DESC_STATUS_EOP)
	  //    n_rx_packets++;
	}
#endif
      n_rx_desc += 8;
      if ((rxv[7].status & AVF_RX_DESC_STATUS_DD) == 0)
	break;
      if (n_rx_packets > AVF_RX_VECTOR_SZ + 7 /* max skip */ )
	break;
    }

  tsc_mark ("fix");
  /* decrement n_rx_desc, n_rx_packets for skipped descriptors */
  n_rx_desc -= skip;
  rxv = ptd->rx_vector;
  for (i = 0; i < skip; i++)
    if (rxv[i].status & AVF_RX_DESC_STATUS_EOP)
      n_rx_packets--;

  /* remove incomplete descriptors from the end and ones exceeding
     RX_VECTOR_SIZE */
  rxv = ptd->rx_vector + skip;
  while (1)
    {
      u32 flags = AVF_RX_DESC_STATUS_DD | AVF_RX_DESC_STATUS_EOP;
      if ((n_rx_packets <= AVF_RX_VECTOR_SZ) &&
	  (rxv[n_rx_desc - 1].status & flags) == flags)
	break;
      n_rx_desc--;
      if (rxv[n_rx_desc].status & AVF_RX_DESC_STATUS_EOP)
	n_rx_packets--;
      if (n_rx_desc == 0)
	goto done;
    }

  rxq->next = (rxq->next + n_rx_desc) & mask;
  rxq->n_enqueued -= n_rx_desc;

  tsc_mark ("refill");
  /* refill rx ring */
  if (ad->flags & AVF_DEVICE_F_IOVA)
    avf_rxq_refill (vm, node, rxq, 1 /* use_iova */ );
  else
    avf_rxq_refill (vm, node, rxq, 0 /* use_iova */ );

  tsc_mark ("process");
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = ad->sw_if_index;
  vnet_buffer (bt)->sw_if_index[VLIB_TX] = ~0;

  if (PREDICT_FALSE (ad->per_interface_next_index != ~0))
    {
      known_next = 1;
      next_index = ad->per_interface_next_index;
    }

  /* as all packets belong to the same interface feature arc lookup
     can be don once and result stored */
  if (PREDICT_FALSE (vnet_device_input_have_features (ad->sw_if_index)))
    {
      vnet_feature_start_device_input_x1 (ad->sw_if_index, &next_index, bt);
      known_next = 1;
    }

  if (known_next)
    {
      clib_memset_u16 (ptd->nexts, next_index, n_rx_packets);
      n_rx_bytes = or_error ?
	avf_process_rx_burst (vm, node, ptd, n_rx_desc, /* maybe_err */ 1,
			      /* known_next */ 1) :
	avf_process_rx_burst (vm, node, ptd, n_rx_desc, /* maybe_err */ 0,
			      /* known_next */ 1);
      vnet_buffer (bt)->feature_arc_index = 0;
      bt->current_config_index = 0;
    }
  else
    n_rx_bytes = or_error ?
      avf_process_rx_burst (vm, node, ptd, n_rx_desc, /* maybe_err */ 1,
			    /* known_next */ 0) :
      avf_process_rx_burst (vm, node, ptd, n_rx_desc, /* maybe_err */ 0,
			    /* known_next */ 0);

  /* packet trace if enabled */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 n_left = n_rx_packets;
      bi = ptd->to_next;
      u16 *next = ptd->nexts;
      rxv = ptd->rx_vector + skip;
      while (n_trace && n_left)
	{
	  vlib_buffer_t *b;
	  avf_input_trace_t *tr;
	  b = vlib_get_buffer (vm, bi[0]);
	  vlib_trace_buffer (vm, node, next[0], b, /* follow_chain */ 0);
	  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = next[0];
	  tr->hw_if_index = ad->hw_if_index;
	  clib_memcpy (tr->descs, rxv, sizeof (*rxv));
	  tr->descs[0].as_u64 = rxv->as_u64;
	  tr->n_desc = 1;
	  rxv++;
	  while ((rxv[-1].status & AVF_RX_DESC_STATUS_EOP) == 0)
	    tr->descs[tr->n_desc++].as_u64 = rxv++->as_u64;

	  /* next */
	  n_trace--;
	  n_left--;
	  bi++;
	  next++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  tsc_mark ("enq");
  vlib_buffer_enqueue_to_next (vm, node, ptd->to_next, ptd->nexts,
			       n_rx_packets);
  vlib_increment_combined_counter (vnm->
				   interface_main.combined_sw_if_counters +
				   VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, ad->hw_if_index,
				   n_rx_packets, n_rx_bytes);

  tsc_mark (0);
  tsc_print (3, n_rx_packets);
done:
  return n_rx_packets;
}

VLIB_NODE_FN (avf_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_rx = 0;
  avf_main_t *am = &avf_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    avf_device_t *ad;
    ad = vec_elt_at_index (am->devices, dq->dev_instance);
    if ((ad->flags & AVF_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += avf_device_input_inline (vm, node, frame, ad, dq->queue_id);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_input_node) = {
  .name = "avf-input",
  .sibling_of = "device-input",
  .format_trace = format_avf_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = AVF_INPUT_N_ERROR,
  .error_strings = avf_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
