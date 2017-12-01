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
format_vnet_buffer (u8 * s, va_list * args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);
  u32 indent = format_get_indent (s);
  u8 *a = 0;

#define _(bit, name, v) \
  if (v && (b->flags & VNET_BUFFER_F_##name)) \
    a = format (a, "%s ", v);
  foreach_vnet_buffer_field
#undef _
    if (b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
    a = format (a, "l2-hdr-offset %d ", vnet_buffer (b)->l2_hdr_offset);

  if (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    a = format (a, "l3-hdr-offset %d ", vnet_buffer (b)->l3_hdr_offset);

  if (b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID)
    a = format (a, "l4-hdr-offset %d ", vnet_buffer (b)->l4_hdr_offset);

  s = format (s, "%U", format_vlib_buffer, b);
  if (a)
    s = format (s, "\n%U%v", format_white_space, indent, a);
  vec_free (a);

  return s;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
