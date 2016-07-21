/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/lisp-cp/lisp_types.h>

#define IP_DF 0x4000 /* don't fragment */

void *
pkt_push_ip (vlib_main_t * vm, vlib_buffer_t *b, ip_address_t *src,
	     ip_address_t *dst, u32 proto);

void *
pkt_push_udp_and_ip (vlib_main_t * vm, vlib_buffer_t *b, u16 sp, u16 dp,
		     ip_address_t *sip, ip_address_t *dip);

void *
pkt_push_ecm_hdr (vlib_buffer_t *b);

always_inline u8 *
vlib_buffer_get_tail (vlib_buffer_t *b)
{
  return b->data + b->current_data + b->current_length;
}

always_inline void *
vlib_buffer_put_uninit (vlib_buffer_t *b, u8 size)
{
  /* XXX should make sure there's enough space! */
  void * p = vlib_buffer_get_tail (b);
  b->current_length += size;
  return p;
}

always_inline void *
vlib_buffer_push_uninit (vlib_buffer_t *b, u8 size)
{
  /* XXX should make sure there's enough space! */
  ASSERT (b->current_data >= size);
  b->current_data -= size;
  b->current_length += size;

  return vlib_buffer_get_current(b);
}

always_inline void *
vlib_buffer_make_headroom (vlib_buffer_t *b, u8 size)
{
  /* XXX should make sure there's enough space! */
  b->current_data += size;
  return vlib_buffer_get_current (b);
}

always_inline void *
vlib_buffer_pull (vlib_buffer_t * b, u8 size)
{
  if (b->current_length < size)
    return 0;

  void * data = vlib_buffer_get_current (b);
  vlib_buffer_advance (b, size);
  return data;
}
