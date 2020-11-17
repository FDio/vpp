/*
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
 */
#ifndef __VIRTIO_VHOST_USER_INLINE_H__
#define __VIRTIO_VHOST_USER_INLINE_H__
/* vhost-user inline functions */
#include <vppinfra/elog.h>

static_always_inline void *
map_guest_mem (vhost_user_intf_t * vui, uword addr, u32 * hint)
{
  int i = *hint;
  if (PREDICT_TRUE ((vui->regions[i].guest_phys_addr <= addr) &&
		    ((vui->regions[i].guest_phys_addr +
		      vui->regions[i].memory_size) > addr)))
    {
      return (void *) (vui->region_mmap_addr[i] + addr -
		       vui->regions[i].guest_phys_addr);
    }
#if __SSE4_2__
  __m128i rl, rh, al, ah, r;
  al = _mm_set1_epi64x (addr + 1);
  ah = _mm_set1_epi64x (addr);

  rl = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_lo[0]);
  rl = _mm_cmpgt_epi64 (al, rl);
  rh = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_hi[0]);
  rh = _mm_cmpgt_epi64 (rh, ah);
  r = _mm_and_si128 (rl, rh);

  rl = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_lo[2]);
  rl = _mm_cmpgt_epi64 (al, rl);
  rh = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_hi[2]);
  rh = _mm_cmpgt_epi64 (rh, ah);
  r = _mm_blend_epi16 (r, _mm_and_si128 (rl, rh), 0x22);

  rl = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_lo[4]);
  rl = _mm_cmpgt_epi64 (al, rl);
  rh = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_hi[4]);
  rh = _mm_cmpgt_epi64 (rh, ah);
  r = _mm_blend_epi16 (r, _mm_and_si128 (rl, rh), 0x44);

  rl = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_lo[6]);
  rl = _mm_cmpgt_epi64 (al, rl);
  rh = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_hi[6]);
  rh = _mm_cmpgt_epi64 (rh, ah);
  r = _mm_blend_epi16 (r, _mm_and_si128 (rl, rh), 0x88);

  r = _mm_shuffle_epi8 (r, _mm_set_epi64x (0, 0x0e060c040a020800));
  i = count_trailing_zeros (_mm_movemask_epi8 (r) |
			    (1 << VHOST_MEMORY_MAX_NREGIONS));

  if (i < vui->nregions)
    {
      *hint = i;
      return (void *) (vui->region_mmap_addr[i] + addr -
		       vui->regions[i].guest_phys_addr);
    }
#elif __aarch64__ && __ARM_NEON
  uint64x2_t al, ah, rl, rh, r;
  uint32_t u32 = 0;

  al = vdupq_n_u64 (addr + 1);
  ah = vdupq_n_u64 (addr);

  /*First Iteration */
  rl = vld1q_u64 (&vui->region_guest_addr_lo[0]);
  rl = vcgtq_u64 (al, rl);
  rh = vld1q_u64 (&vui->region_guest_addr_hi[0]);
  rh = vcgtq_u64 (rh, ah);
  r = vandq_u64 (rl, rh);
  u32 |= (vgetq_lane_u8 (vreinterpretq_u8_u64 (r), 0) & 0x1);
  u32 |= ((vgetq_lane_u8 (vreinterpretq_u8_u64 (r), 8) & 0x1) << 1);

  if (u32)
    {
      i = count_trailing_zeros (u32);
      goto vhost_map_guest_mem_done;
    }

  /*Second Iteration */
  rl = vld1q_u64 (&vui->region_guest_addr_lo[2]);
  rl = vcgtq_u64 (al, rl);
  rh = vld1q_u64 (&vui->region_guest_addr_hi[2]);
  rh = vcgtq_u64 (rh, ah);
  r = vandq_u64 (rl, rh);
  u32 |= ((vgetq_lane_u8 (vreinterpretq_u8_u64 (r), 0) & 0x1) << 2);
  u32 |= ((vgetq_lane_u8 (vreinterpretq_u8_u64 (r), 8) & 0x1) << 3);

  if (u32)
    {
      i = count_trailing_zeros (u32);
      goto vhost_map_guest_mem_done;
    }

  /*Third Iteration */
  rl = vld1q_u64 (&vui->region_guest_addr_lo[4]);
  rl = vcgtq_u64 (al, rl);
  rh = vld1q_u64 (&vui->region_guest_addr_hi[4]);
  rh = vcgtq_u64 (rh, ah);
  r = vandq_u64 (rl, rh);
  u32 |= ((vgetq_lane_u8 (vreinterpretq_u8_u64 (r), 0) & 0x1) << 6);
  u32 |= ((vgetq_lane_u8 (vreinterpretq_u8_u64 (r), 8) & 0x1) << 7);

  i = count_trailing_zeros (u32 | (1 << VHOST_MEMORY_MAX_NREGIONS));

vhost_map_guest_mem_done:
  if (i < vui->nregions)
    {
      *hint = i;
      return (void *) (vui->region_mmap_addr[i] + addr -
		       vui->regions[i].guest_phys_addr);
    }
#else
  for (i = 0; i < vui->nregions; i++)
    {
      if ((vui->regions[i].guest_phys_addr <= addr) &&
	  ((vui->regions[i].guest_phys_addr + vui->regions[i].memory_size) >
	   addr))
	{
	  *hint = i;
	  return (void *) (vui->region_mmap_addr[i] + addr -
			   vui->regions[i].guest_phys_addr);
	}
    }
#endif
  /* *INDENT-OFF* */
  ELOG_TYPE_DECLARE (el) =
  {
    .format = "failed to map guest mem addr %lx",
    .format_args = "i8",
  };
  /* *INDENT-ON* */
  struct
  {
    uword addr;
  } *ed;
  ed = ELOG_DATA (&vlib_global_main.elog_main, el);
  ed->addr = addr;
  *hint = 0;
  return 0;
}

static_always_inline void *
map_user_mem (vhost_user_intf_t * vui, uword addr)
{
  int i;
  for (i = 0; i < vui->nregions; i++)
    {
      if ((vui->regions[i].userspace_addr <= addr) &&
	  ((vui->regions[i].userspace_addr + vui->regions[i].memory_size) >
	   addr))
	{
	  return (void *) (vui->region_mmap_addr[i] + addr -
			   vui->regions[i].userspace_addr);
	}
    }
  return 0;
}

#define VHOST_LOG_PAGE 0x1000

static_always_inline void
vhost_user_log_dirty_pages_2 (vhost_user_intf_t * vui,
			      u64 addr, u64 len, u8 is_host_address)
{
  if (PREDICT_TRUE (vui->log_base_addr == 0
		    || !(vui->features & VIRTIO_FEATURE (VHOST_F_LOG_ALL))))
    {
      return;
    }
  if (is_host_address)
    {
      addr = pointer_to_uword (map_user_mem (vui, (uword) addr));
    }
  if (PREDICT_FALSE ((addr + len - 1) / VHOST_LOG_PAGE / 8 >= vui->log_size))
    {
      vu_log_debug (vui, "vhost_user_log_dirty_pages(): out of range\n");
      return;
    }

  CLIB_MEMORY_BARRIER ();
  u64 page = addr / VHOST_LOG_PAGE;
  while (page * VHOST_LOG_PAGE < addr + len)
    {
      ((u8 *) vui->log_base_addr)[page / 8] |= 1 << page % 8;
      page++;
    }
}


#define vhost_user_log_dirty_ring(vui, vq, member) \
  if (PREDICT_FALSE(vq->log_used)) { \
    vhost_user_log_dirty_pages_2(vui, vq->log_guest_addr + STRUCT_OFFSET_OF(vring_used_t, member), \
                             sizeof(vq->used->member), 0); \
  }

static_always_inline u8 *
format_vhost_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = vnet_get_main ();
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_trace_t *t = va_arg (*va, vhost_trace_t *);
  vhost_user_intf_t *vui = vum->vhost_user_interfaces + t->device_index;
  vnet_sw_interface_t *sw;
  u32 indent;

  if (pool_is_free (vum->vhost_user_interfaces, vui))
    {
      s = format (s, "vhost-user interface is deleted");
      return s;
    }
  sw = vnet_get_sw_interface (vnm, vui->sw_if_index);
  indent = format_get_indent (s);
  s = format (s, "%U %U queue %d\n", format_white_space, indent,
	      format_vnet_sw_interface_name, vnm, sw, t->qid);

  s = format (s, "%U virtio flags:\n", format_white_space, indent);
#define _(n,i,st) \
          if (t->virtio_ring_flags & (1 << VIRTIO_TRACE_F_##n)) \
            s = format (s, "%U  %s %s\n", format_white_space, indent, #n, st);
  foreach_virtio_trace_flags
#undef _
    s = format (s, "%U virtio_net_hdr first_desc_len %u\n",
		format_white_space, indent, t->first_desc_len);

  s = format (s, "%U   flags 0x%02x gso_type %u\n",
	      format_white_space, indent,
	      t->hdr.hdr.flags, t->hdr.hdr.gso_type);

  if (vui->virtio_net_hdr_sz == 12)
    s = format (s, "%U   num_buff %u",
		format_white_space, indent, t->hdr.num_buffers);

  return s;
}

static_always_inline u64
vhost_user_is_packed_ring_supported (vhost_user_intf_t * vui)
{
  return (vui->features & VIRTIO_FEATURE (VIRTIO_F_RING_PACKED));
}

static_always_inline u64
vhost_user_is_event_idx_supported (vhost_user_intf_t * vui)
{
  return (vui->features & VIRTIO_FEATURE (VIRTIO_RING_F_EVENT_IDX));
}

static_always_inline void
vhost_user_kick (vlib_main_t * vm, vhost_user_vring_t * vq)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u64 x = 1;
  int fd = UNIX_GET_FD (vq->callfd_idx);
  int rv;

  rv = write (fd, &x, sizeof (x));
  if (PREDICT_FALSE (rv <= 0))
    {
      clib_unix_warning
	("Error: Could not write to unix socket for callfd %d", fd);
      return;
    }

  vq->n_since_last_int = 0;
  vq->int_deadline = vlib_time_now (vm) + vum->coalesce_time;
}

static_always_inline u16
vhost_user_avail_event_idx (vhost_user_vring_t * vq)
{
  volatile u16 *event_idx = (u16 *) & (vq->used->ring[vq->qsz_mask + 1]);

  return *event_idx;
}

static_always_inline u16
vhost_user_used_event_idx (vhost_user_vring_t * vq)
{
  volatile u16 *event_idx = (u16 *) & (vq->avail->ring[vq->qsz_mask + 1]);

  return *event_idx;
}

static_always_inline u16
vhost_user_need_event (u16 event_idx, u16 new_idx, u16 old_idx)
{
  return ((u16) (new_idx - event_idx - 1) < (u16) (new_idx - old_idx));
}

static_always_inline void
vhost_user_send_call_event_idx (vlib_main_t * vm, vhost_user_vring_t * vq)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u8 first_kick = vq->first_kick;
  u16 event_idx = vhost_user_used_event_idx (vq);

  vq->first_kick = 1;
  if (vhost_user_need_event (event_idx, vq->last_used_idx, vq->last_kick) ||
      PREDICT_FALSE (!first_kick))
    {
      vhost_user_kick (vm, vq);
      vq->last_kick = event_idx;
    }
  else
    {
      vq->n_since_last_int = 0;
      vq->int_deadline = vlib_time_now (vm) + vum->coalesce_time;
    }
}

static_always_inline void
vhost_user_send_call_event_idx_packed (vlib_main_t * vm,
				       vhost_user_vring_t * vq)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u8 first_kick = vq->first_kick;
  u16 off_wrap;
  u16 event_idx;
  u16 new_idx = vq->last_used_idx;
  u16 old_idx = vq->last_kick;

  if (PREDICT_TRUE (vq->avail_event->flags == VRING_EVENT_F_DESC))
    {
      CLIB_COMPILER_BARRIER ();
      off_wrap = vq->avail_event->off_wrap;
      event_idx = off_wrap & 0x7fff;
      if (vq->used_wrap_counter != (off_wrap >> 15))
	event_idx -= (vq->qsz_mask + 1);

      if (new_idx <= old_idx)
	old_idx -= (vq->qsz_mask + 1);

      vq->first_kick = 1;
      vq->last_kick = event_idx;
      if (vhost_user_need_event (event_idx, new_idx, old_idx) ||
	  PREDICT_FALSE (!first_kick))
	vhost_user_kick (vm, vq);
      else
	{
	  vq->n_since_last_int = 0;
	  vq->int_deadline = vlib_time_now (vm) + vum->coalesce_time;
	}
    }
  else
    vhost_user_kick (vm, vq);
}

static_always_inline void
vhost_user_send_call (vlib_main_t * vm, vhost_user_intf_t * vui,
		      vhost_user_vring_t * vq)
{
  if (vhost_user_is_event_idx_supported (vui))
    {
      if (vhost_user_is_packed_ring_supported (vui))
	vhost_user_send_call_event_idx_packed (vm, vq);
      else
	vhost_user_send_call_event_idx (vm, vq);
    }
  else
    vhost_user_kick (vm, vq);
}

static_always_inline u8
vui_is_link_up (vhost_user_intf_t * vui)
{
  return vui->admin_up && vui->is_ready;
}

static_always_inline void
vhost_user_update_gso_interface_count (vhost_user_intf_t * vui, u8 add)
{
  vhost_user_main_t *vum = &vhost_user_main;

  if (vui->enable_gso)
    {
      if (add)
	{
	  vum->gso_count++;
	}
      else
	{
	  ASSERT (vum->gso_count > 0);
	  vum->gso_count--;
	}
    }
}

static_always_inline u8
vhost_user_packed_desc_available (vhost_user_vring_t * vring, u16 idx)
{
  return (((vring->packed_desc[idx].flags & VRING_DESC_F_AVAIL) ==
	   vring->avail_wrap_counter));
}

static_always_inline void
vhost_user_advance_last_avail_idx (vhost_user_vring_t * vring)
{
  vring->last_avail_idx++;
  if (PREDICT_FALSE ((vring->last_avail_idx & vring->qsz_mask) == 0))
    {
      vring->avail_wrap_counter ^= VRING_DESC_F_AVAIL;
      vring->last_avail_idx = 0;
    }
}

static_always_inline void
vhost_user_advance_last_avail_table_idx (vhost_user_intf_t * vui,
					 vhost_user_vring_t * vring,
					 u8 chained)
{
  if (chained)
    {
      vring_packed_desc_t *desc_table = vring->packed_desc;

      /* pick up the slot of the next avail idx */
      while (desc_table[vring->last_avail_idx & vring->qsz_mask].flags &
	     VRING_DESC_F_NEXT)
	vhost_user_advance_last_avail_idx (vring);
    }

  vhost_user_advance_last_avail_idx (vring);
}

static_always_inline void
vhost_user_undo_advanced_last_avail_idx (vhost_user_vring_t * vring)
{
  if (PREDICT_FALSE ((vring->last_avail_idx & vring->qsz_mask) == 0))
    vring->avail_wrap_counter ^= VRING_DESC_F_AVAIL;

  if (PREDICT_FALSE (vring->last_avail_idx == 0))
    vring->last_avail_idx = vring->qsz_mask;
  else
    vring->last_avail_idx--;
}

static_always_inline void
vhost_user_dequeue_descs (vhost_user_vring_t * rxvq,
			  virtio_net_hdr_mrg_rxbuf_t * hdr,
			  u16 * n_descs_processed)
{
  u16 i;

  *n_descs_processed -= (hdr->num_buffers - 1);
  for (i = 0; i < hdr->num_buffers - 1; i++)
    vhost_user_undo_advanced_last_avail_idx (rxvq);
}

static_always_inline void
vhost_user_dequeue_chained_descs (vhost_user_vring_t * rxvq,
				  u16 * n_descs_processed)
{
  while (*n_descs_processed)
    {
      vhost_user_undo_advanced_last_avail_idx (rxvq);
      (*n_descs_processed)--;
    }
}

static_always_inline void
vhost_user_advance_last_used_idx (vhost_user_vring_t * vring)
{
  vring->last_used_idx++;
  if (PREDICT_FALSE ((vring->last_used_idx & vring->qsz_mask) == 0))
    {
      vring->used_wrap_counter ^= 1;
      vring->last_used_idx = 0;
    }
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
