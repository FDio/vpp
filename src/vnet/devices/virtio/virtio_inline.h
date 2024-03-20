/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __VIRTIO_INLINE_H__
#define __VIRTIO_INLINE_H__

#define foreach_virtio_input_error                                            \
  _ (BUFFER_ALLOC, "buffer alloc error")                                      \
  _ (FULL_RX_QUEUE, "full rx queue (driver tx drop)")                         \
  _ (UNKNOWN, "unknown")

typedef enum
{
#define _(f, s) VIRTIO_INPUT_ERROR_##f,
  foreach_virtio_input_error
#undef _
    VIRTIO_INPUT_N_ERROR,
} virtio_input_error_t;

static_always_inline void
virtio_refill_vring_split (vlib_main_t *vm, virtio_if_t *vif,
			   virtio_if_type_t type, vnet_virtio_vring_t *vring,
			   const int hdr_sz, u32 node_index)
{
  u16 used, next, avail, n_slots, n_refill;
  u16 sz = vring->queue_size;
  u16 mask = sz - 1;

more:
  used = vring->desc_in_use;

  if (sz - used < sz / 8)
    return;

  /* deliver free buffers in chunks of 64 */
  n_refill = clib_min (sz - used, 64);

  next = vring->desc_next;
  avail = vring->avail->idx;
  n_slots = vlib_buffer_alloc_to_ring_from_pool (vm, vring->buffers, next,
						 vring->queue_size, n_refill,
						 vring->buffer_pool_index);

  if (PREDICT_FALSE (n_slots != n_refill))
    {
      vlib_error_count (vm, node_index, VIRTIO_INPUT_ERROR_BUFFER_ALLOC,
			n_refill - n_slots);
      if (n_slots == 0)
	return;
    }

  while (n_slots)
    {
      vnet_virtio_vring_desc_t *d = &vring->desc[next];
      ;
      vlib_buffer_t *b = vlib_get_buffer (vm, vring->buffers[next]);
      /*
       * current_data may not be initialized with 0 and may contain
       * previous offset. Here we want to make sure, it should be 0
       * initialized.
       */
      b->current_data = -hdr_sz;
      clib_memset (vlib_buffer_get_current (b), 0, hdr_sz);
      d->addr = ((type == VIRTIO_IF_TYPE_PCI) ?
		   vlib_buffer_get_current_pa (vm, b) :
		   pointer_to_uword (vlib_buffer_get_current (b)));
      d->len = vlib_buffer_get_default_data_size (vm) + hdr_sz;
      d->flags = VRING_DESC_F_WRITE;
      vring->avail->ring[avail & mask] = next;
      avail++;
      next = (next + 1) & mask;
      n_slots--;
      used++;
    }
  clib_atomic_store_seq_cst (&vring->avail->idx, avail);
  vring->desc_next = next;
  vring->desc_in_use = used;
  if ((clib_atomic_load_seq_cst (&vring->used->flags) &
       VRING_USED_F_NO_NOTIFY) == 0)
    {
      virtio_kick (vm, vring, vif);
    }
  goto more;
}

static_always_inline void
virtio_refill_vring_packed (vlib_main_t *vm, virtio_if_t *vif,
			    virtio_if_type_t type, vnet_virtio_vring_t *vring,
			    const int hdr_sz, u32 node_index)
{
  u16 used, next, n_slots, n_refill, flags = 0, first_desc_flags;
  u16 sz = vring->queue_size;

more:
  used = vring->desc_in_use;

  if (sz == used)
    return;

  /* deliver free buffers in chunks of 64 */
  n_refill = clib_min (sz - used, 64);

  next = vring->desc_next;
  first_desc_flags = vring->packed_desc[next].flags;
  n_slots = vlib_buffer_alloc_to_ring_from_pool (
    vm, vring->buffers, next, sz, n_refill, vring->buffer_pool_index);

  if (PREDICT_FALSE (n_slots != n_refill))
    {
      vlib_error_count (vm, node_index, VIRTIO_INPUT_ERROR_BUFFER_ALLOC,
			n_refill - n_slots);
      if (n_slots == 0)
	return;
    }

  while (n_slots)
    {
      vnet_virtio_vring_packed_desc_t *d = &vring->packed_desc[next];
      vlib_buffer_t *b = vlib_get_buffer (vm, vring->buffers[next]);
      /*
       * current_data may not be initialized with 0 and may contain
       * previous offset. Here we want to make sure, it should be 0
       * initialized.
       */
      b->current_data = -hdr_sz;
      clib_memset (vlib_buffer_get_current (b), 0, hdr_sz);
      d->addr = ((type == VIRTIO_IF_TYPE_PCI) ?
		   vlib_buffer_get_current_pa (vm, b) :
		   pointer_to_uword (vlib_buffer_get_current (b)));
      d->len = vlib_buffer_get_default_data_size (vm) + hdr_sz;

      if (vring->avail_wrap_counter)
	flags = (VRING_DESC_F_AVAIL | VRING_DESC_F_WRITE);
      else
	flags = (VRING_DESC_F_USED | VRING_DESC_F_WRITE);

      d->id = next;
      if (vring->desc_next == next)
	first_desc_flags = flags;
      else
	d->flags = flags;

      next++;
      if (next >= sz)
	{
	  next = 0;
	  vring->avail_wrap_counter ^= 1;
	}
      n_slots--;
      used++;
    }
  CLIB_MEMORY_STORE_BARRIER ();
  vring->packed_desc[vring->desc_next].flags = first_desc_flags;
  vring->desc_next = next;
  vring->desc_in_use = used;
  CLIB_MEMORY_BARRIER ();
  if (vring->device_event->flags != VRING_EVENT_F_DISABLE)
    {
      virtio_kick (vm, vring, vif);
    }

  goto more;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
