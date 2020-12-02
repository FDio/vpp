/*
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
 */

#ifndef included_vnet_mpcap_h
#define included_vnet_mpcap_h

#include <vnet/vnet.h>
#include <vppinfra/mpcap.h>

/**
 * @brief Add packet
 *
 * @param *pm - mpcap_main_t
 * @param time_now - f64
 * @param n_bytes_in_trace - u32
 * @param n_bytes_in_packet - u32
 *
 * @return Packet Data
 *
 */
static inline void *
mpcap_add_packet (mpcap_main_t * pm,
		  f64 time_now, u32 n_bytes_in_trace, u32 n_bytes_in_packet)
{
  mpcap_packet_header_t *h;
  u8 *d;

  /* File already closed? */
  if (PREDICT_FALSE (pm->flags & MPCAP_FLAG_INIT_DONE) == 0)
    return 0;

  d = pm->current_va;
  pm->current_va += sizeof (h[0]) + n_bytes_in_trace;

  /* Out of space? */
  if (PREDICT_FALSE (pm->current_va >= pm->file_baseva + pm->max_file_size))
    return 0;
  h = (void *) (d);
  h->time_in_sec = time_now;
  h->time_in_usec = 1e6 * (time_now - h->time_in_sec);
  h->n_packet_bytes_stored_in_file = n_bytes_in_trace;
  h->n_bytes_in_packet = n_bytes_in_packet;
  pm->n_packets_captured++;
  return h->data;
}

/**
 * @brief Add buffer (vlib_buffer_t) to the trace
 *
 * @param *pm - mpcap_main_t
 * @param *vm - vlib_main_t
 * @param time_now - f64
 * @param buffer_index - u32
 * @param n_bytes_in_trace - u32
 *
 */
static inline void
mpcap_add_buffer (mpcap_main_t * pm,
		  vlib_main_t * vm,
		  f64 time_now, u32 buffer_index, u32 n_bytes_in_trace)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
  u32 n = vlib_buffer_length_in_chain (vm, b);
  i32 n_left = clib_min (n_bytes_in_trace, n);
  void *d;

  clib_spinlock_lock_if_init (&pm->lock);

  d = mpcap_add_packet (pm, time_now, n_left, n);
  if (PREDICT_FALSE (d == 0))
    {
      mpcap_close (pm);
      clib_spinlock_unlock_if_init (&pm->lock);
      return;
    }

  while (1)
    {
      u32 copy_length = clib_min ((u32) n_left, b->current_length);
      clib_memcpy (d, b->data + b->current_data, copy_length);
      n_left -= b->current_length;
      if (n_left <= 0)
	break;
      d += b->current_length;
      ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
      b = vlib_get_buffer (vm, b->next_buffer);
    }
  if (pm->n_packets_captured >= pm->n_packets_to_capture)
    mpcap_close (pm);

  clib_spinlock_unlock_if_init (&pm->lock);
}

/**
* @brief Add buffer (vlib_buffer_t) to the trace, with extra custom header
*
* @param *pm - mpcap_main_t
* @param *vm - vlib_main_t
* @param time_now - f64
* @param buffer_index - u32
* @param n_bytes_in_trace, excluding custom header - u32
* @param *custom_header - u8
* @param n_bytes_custom_header - u32
*
*/
static inline void
  mpcap_add_buffer_plus_custom_header
  (mpcap_main_t * pm,
   vlib_main_t * vm,
   f64 time_now,
   u32 buffer_index,
   u32 n_bytes_in_trace, u8 * custom_header, u32 n_bytes_custom_header)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
  u32 n = vlib_buffer_length_in_chain (vm, b);
  i32 n_left = clib_min (n_bytes_in_trace, n);
  void *d;

  clib_spinlock_lock_if_init (&pm->lock);

  d =
    mpcap_add_packet (pm, time_now, n_left + n_bytes_custom_header,
		      n + n_bytes_custom_header);
  if (PREDICT_FALSE (d == 0))
    {
      mpcap_close (pm);
      clib_spinlock_unlock_if_init (&pm->lock);
      return;
    }

  if (PREDICT_TRUE (n_bytes_custom_header != 0))
    {
      ASSERT (custom_header);
      clib_memcpy (d, custom_header, n_bytes_custom_header);
      d += n_bytes_custom_header;
    }

  while (1)
    {
      u32 copy_length = clib_min ((u32) n_left, b->current_length);
      clib_memcpy (d, b->data + b->current_data, copy_length);
      n_left -= b->current_length;
      if (n_left <= 0)
	break;
      d += b->current_length;
      ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
      b = vlib_get_buffer (vm, b->next_buffer);
    }
  if (pm->n_packets_captured >= pm->n_packets_to_capture)
    mpcap_close (pm);

  clib_spinlock_unlock_if_init (&pm->lock);
}

#endif /* included_vnet_mpcap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
