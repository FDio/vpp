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

#define VIRTIO_BUFFERING_SIZE 1024
#define VIRTIO_BUFFERING_TIMEOUT 1e-5

typedef struct
{
  u32 buffers[VIRTIO_BUFFERING_SIZE];
  f64 timeout_ts;
  u32 node_index;
  u16 free_size;
  u16 start;
  u16 end;
  u8 is_enable;
} vritio_vring_buffering_t;

static_always_inline u32
virtio_vring_buffering_init (vritio_vring_buffering_t * buffering,
			     u32 node_index)
{
  if (!buffering)
    return 0;

  buffering->timeout_ts = 0;
  buffering->node_index = node_index;
  buffering->free_size = VIRTIO_BUFFERING_SIZE;
  buffering->start = 0;
  buffering->end = 0;
  buffering->is_enable = 1;

  return 1;
}

static_always_inline u8
virtio_vring_buffering_is_enable (vritio_vring_buffering_t * buffering)
{
  if (buffering)
    return buffering->is_enable;

  return 0;
}

static_always_inline void
virtio_vring_buffering_set_is_enable (vritio_vring_buffering_t * buffering,
				      u8 is_enable)
{
  if (buffering)
    {
      if (is_enable)
	{
	  buffering->is_enable = 1;
	}
      else
	{
	  buffering->is_enable = 0;
	}
    }
}

static_always_inline void
virtio_vring_buffering_set_timeout (vlib_main_t * vm,
				    vritio_vring_buffering_t * buffering,
				    f64 timeout_expire)
{
  if (buffering)
    buffering->timeout_ts = vlib_time_now (vm) + timeout_expire;
}

static_always_inline u8
virtio_vring_buffering_is_timeout (vlib_main_t * vm,
				   vritio_vring_buffering_t * buffering)
{
  if (buffering && (buffering->timeout_ts < vlib_time_now (vm)))
    return 1;
  return 0;
}

static_always_inline u8
virtio_vring_buffering_is_empty (vritio_vring_buffering_t * buffering)
{
  if (buffering->free_size == VIRTIO_BUFFERING_SIZE)
    return 1;
  return 0;
}

static_always_inline u8
virtio_vring_buffering_is_full (vritio_vring_buffering_t * buffering)
{
  if (buffering->free_size == 0)
    return 1;
  return 0;
}

static_always_inline u16
virtio_vring_n_buffers (vritio_vring_buffering_t * buffering)
{
  return (VIRTIO_BUFFERING_SIZE - buffering->free_size);
}

static_always_inline void
virtio_vring_buffering_a_packet (vritio_vring_buffering_t * buffering,
				 u32 bi0)
{
  u16 mask = VIRTIO_BUFFERING_SIZE - 1;
  buffering->buffers[buffering->end] = bi0;
  buffering->end = (buffering->end + 1) & mask;
  buffering->free_size--;
}

static_always_inline u16
virtio_vring_buffering_store_packet (vritio_vring_buffering_t * buffering,
				     u32 * bi, u16 n_store)
{
  u16 free_size = buffering->free_size;

  if (!virtio_vring_buffering_is_enable (buffering)
      || virtio_vring_buffering_is_full (buffering))
    return 0;

  u16 n_s = clib_min (n_store, free_size);

  for (u32 i = 0; i < n_s; i++)
    virtio_vring_buffering_a_packet (buffering, bi[i]);
  return n_s;
}

static_always_inline u32
virtio_vring_buffering_read_packet (vritio_vring_buffering_t * buffering)
{
  u32 bi = ~0;
  u16 mask = VIRTIO_BUFFERING_SIZE - 1;
  if (virtio_vring_buffering_is_empty (buffering))
    return bi;

  bi = buffering->buffers[buffering->start];
  buffering->buffers[buffering->start] = ~0;
  buffering->start = (buffering->start + 1) & mask;
  buffering->free_size++;
  return bi;
}

static_always_inline u32
virtio_vring_buffering_read_last_packet (vritio_vring_buffering_t * buffering)
{
  u32 bi = ~0;
  u16 mask = VIRTIO_BUFFERING_SIZE - 1;
  if (virtio_vring_buffering_is_empty (buffering))
    return bi;

  buffering->end = (buffering->end - 1) & mask;
  bi = buffering->buffers[buffering->end];
  buffering->buffers[buffering->end] = ~0;
  buffering->free_size++;
  return bi;
}

static_always_inline void
virtio_vring_buffering_schedule_node_on_dispatcher (vlib_main_t * vm,
						    vritio_vring_buffering_t *
						    buffering)
{
  if (buffering && virtio_vring_buffering_is_timeout (vm, buffering)
      && virtio_vring_n_buffers (buffering))
    {
      vlib_frame_t *f = vlib_get_frame_to_node (vm, buffering->node_index);
      u32 *f_to = vlib_frame_vector_args (f);
      f_to[f->n_vectors] =
	virtio_vring_buffering_read_last_packet (buffering);
      f->n_vectors++;
      vlib_put_frame_to_node (vm, buffering->node_index, f);
      virtio_vring_buffering_set_timeout (vm, buffering,
					  VIRTIO_BUFFERING_TIMEOUT);
    }
}

static_always_inline u8 *
virtio_vring_buffering_format (u8 * s, va_list * args)
{
  vritio_vring_buffering_t *buffering =
    va_arg (*args, vritio_vring_buffering_t *);

  s =
    format (s,
	    "buffering: n_buffers %u free-size %u start %u end %u",
	    virtio_vring_n_buffers (buffering), buffering->free_size,
	    buffering->start, buffering->end);

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
