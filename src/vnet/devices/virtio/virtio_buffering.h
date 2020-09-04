/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef _VNET_DEVICES_VIRTIO_VIRTIO_BUFFERING_H_
#define _VNET_DEVICES_VIRTIO_VIRTIO_BUFFERING_H_

#define VIRTIO_BUFFERING_DEFAULT_SIZE 1024
#define VIRTIO_BUFFERING_TIMEOUT 1e-5

typedef struct
{
  f64 timeout_ts;
  u32 *buffers;
  u32 node_index;
  u16 size;
  u16 free_size;
  u16 front;
  u16 back;
  u8 is_enable;
} virtio_vring_buffering_t;

static_always_inline u32
virtio_vring_buffering_init (virtio_vring_buffering_t ** buffering,
			     u32 node_index, u16 size)
{
  if (*buffering)
    return 0;

  if (!is_pow2 (size))
    return 0;

  if (size > 32768)
    return 0;

  if (size == 0)
    size = VIRTIO_BUFFERING_DEFAULT_SIZE;

  virtio_vring_buffering_t *b_temp = 0;
  b_temp =
    (virtio_vring_buffering_t *)
    clib_mem_alloc (sizeof (virtio_vring_buffering_t));
  clib_memset (b_temp, 0, sizeof (virtio_vring_buffering_t));

  b_temp->node_index = node_index;
  b_temp->free_size = size;
  b_temp->size = size;

  vec_validate_aligned (b_temp->buffers, size, CLIB_CACHE_LINE_BYTES);
  b_temp->is_enable = 1;

  *buffering = b_temp;
  return 1;
}


static_always_inline u8
virtio_vring_buffering_is_enable (virtio_vring_buffering_t * buffering)
{
  if (buffering)
    return buffering->is_enable;

  return 0;
}

static_always_inline void
virtio_vring_buffering_set_is_enable (virtio_vring_buffering_t * buffering,
				      u8 is_enable)
{
  if (buffering)
    buffering->is_enable = is_enable;
}

static_always_inline void
virtio_vring_buffering_set_timeout (vlib_main_t * vm,
				    virtio_vring_buffering_t * buffering,
				    f64 timeout_expire)
{
  if (buffering)
    buffering->timeout_ts = vlib_time_now (vm) + timeout_expire;
}

static_always_inline u8
virtio_vring_buffering_is_timeout (vlib_main_t * vm,
				   virtio_vring_buffering_t * buffering)
{
  if (buffering && (buffering->timeout_ts < vlib_time_now (vm)))
    return 1;
  return 0;
}

static_always_inline u8
virtio_vring_buffering_is_empty (virtio_vring_buffering_t * buffering)
{
  if (buffering->size == buffering->free_size)
    return 1;
  return 0;
}

static_always_inline u8
virtio_vring_buffering_is_full (virtio_vring_buffering_t * buffering)
{
  if (buffering->free_size == 0)
    return 1;
  return 0;
}

static_always_inline u16
virtio_vring_n_buffers (virtio_vring_buffering_t * buffering)
{
  return (buffering->size - buffering->free_size);
}

static_always_inline u16
virtio_vring_buffering_store_packets (virtio_vring_buffering_t * buffering,
				      u32 * bi, u16 n_store)
{
  u16 mask, n_s = 0, i = 0;

  if (!virtio_vring_buffering_is_enable (buffering)
      || virtio_vring_buffering_is_full (buffering))
    return 0;

  mask = buffering->size - 1;
  n_s = clib_min (n_store, buffering->free_size);

  while (i < n_s)
    {
      buffering->buffers[buffering->back] = bi[i];
      buffering->back = (buffering->back + 1) & mask;
      buffering->free_size--;
      i++;
    }
  return n_s;
}

static_always_inline u32
virtio_vring_buffering_read_from_front (virtio_vring_buffering_t * buffering)
{
  u32 bi = ~0;
  u16 mask = buffering->size - 1;
  if (virtio_vring_buffering_is_empty (buffering))
    return bi;

  bi = buffering->buffers[buffering->front];
  buffering->buffers[buffering->front] = ~0;
  buffering->front = (buffering->front + 1) & mask;
  buffering->free_size++;
  return bi;
}

static_always_inline u32
virtio_vring_buffering_read_from_back (virtio_vring_buffering_t * buffering)
{
  u32 bi = ~0;
  u16 mask = buffering->size - 1;
  if (virtio_vring_buffering_is_empty (buffering))
    return bi;

  buffering->back = (buffering->back - 1) & mask;
  bi = buffering->buffers[buffering->back];
  buffering->buffers[buffering->back] = ~0;
  buffering->free_size++;
  return bi;
}

static_always_inline void
virtio_vring_buffering_schedule_node_on_dispatcher (vlib_main_t * vm,
						    virtio_vring_buffering_t *
						    buffering)
{
  if (buffering && virtio_vring_buffering_is_timeout (vm, buffering)
      && virtio_vring_n_buffers (buffering))
    {
      vlib_frame_t *f = vlib_get_frame_to_node (vm, buffering->node_index);
      u32 *f_to = vlib_frame_vector_args (f);
      f_to[f->n_vectors] = virtio_vring_buffering_read_from_back (buffering);
      f->n_vectors++;
      vlib_put_frame_to_node (vm, buffering->node_index, f);
      virtio_vring_buffering_set_timeout (vm, buffering,
					  VIRTIO_BUFFERING_TIMEOUT);
    }
}

static_always_inline u8 *
virtio_vring_buffering_format (u8 * s, va_list * args)
{
  virtio_vring_buffering_t *buffering =
    va_arg (*args, virtio_vring_buffering_t *);

  s =
    format (s,
	    "buffering: size %u n_buffers %u front %u back %u",
	    buffering->size, virtio_vring_n_buffers (buffering),
	    buffering->front, buffering->back);

  return s;
}

#endif /* _VNET_DEVICES_VIRTIO_VIRTIO_BUFFERING_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
