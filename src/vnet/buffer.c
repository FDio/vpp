/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/buffer.h>

u8 *
format_vnet_buffer_offload (u8 *s, va_list *args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);

#define _(bit, name, ss, v)                                                   \
  if (v && (vnet_buffer (b)->oflags & VNET_BUFFER_OFFLOAD_F_##name))          \
    s = format (s, "%s ", ss);
  foreach_vnet_buffer_offload_flag
#undef _

    if (vnet_buffer (b)->oflags & VNET_BUFFER_OFFLOAD_F_TNL_MASK)
  {
    s = format (s, "outer-l3-hdr-offset %d ",
		vnet_buffer2 (b)->outer_l3_hdr_offset);
    s = format (s, "outer-l4-hdr-offset %d ",
		vnet_buffer2 (b)->outer_l4_hdr_offset);
  }
    return s;
}

static u8 *
format_vnet_buffer_internal (u8 *s, vlib_buffer_t *b, int no_chain)
{
  u32 indent = format_get_indent (s);
  u8 *a = 0;

#define _(bit,name,ss,v)                      \
  if (v && (b->flags & VNET_BUFFER_F_##name)) \
    a = format (a, "%s ", ss);
  foreach_vnet_buffer_flag
#undef _
    if (b->flags & VNET_BUFFER_F_OFFLOAD) a =
      format (a, "%U ", format_vnet_buffer_offload, b);

  if (b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
    a = format (a, "l2-hdr-offset %d ", vnet_buffer (b)->l2_hdr_offset);

  if (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    a = format (a, "l3-hdr-offset %d ", vnet_buffer (b)->l3_hdr_offset);

  if (b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID)
    a = format (a, "l4-hdr-offset %d ", vnet_buffer (b)->l4_hdr_offset);

  if (b->flags & VNET_BUFFER_F_GSO)
    a = format (a, "gso l4-hdr-len %d gso-size %d",
		vnet_buffer2 (b)->gso_l4_hdr_sz, vnet_buffer2 (b)->gso_size);

  if (b->flags & VNET_BUFFER_F_QOS_DATA_VALID)
    a = format (a, "qos %d.%d ",
		vnet_buffer2 (b)->qos.bits, vnet_buffer2 (b)->qos.source);

  if (b->flags & VNET_BUFFER_F_LOOP_COUNTER_VALID)
    a = format (a, "loop-counter %d ", vnet_buffer2 (b)->loop_counter);

  s = format (s, "%U",
	      no_chain ? format_vlib_buffer_no_chain : format_vlib_buffer, b);
  if (a)
    s = format (s, "\n%U%v", format_white_space, indent, a);
  vec_free (a);

  return s;
}

u8 *
format_vnet_buffer_no_chain (u8 *s, va_list *args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);
  return format_vnet_buffer_internal (s, b, 1 /* no_chain */);
}

u8 *
format_vnet_buffer (u8 *s, va_list *args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);
  return format_vnet_buffer_internal (s, b, 0 /* no_chain */);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
