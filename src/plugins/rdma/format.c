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
#include <vnet/vnet.h>
#include <rdma/rdma.h>

u8 *
format_rdma_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, i);

  if (rd->name)
    return format (s, "%v", rd->name);

  s = format (s, "rdma-%u", rd->dev_instance);
  return s;
}

u8 *
format_rdma_device_flags (u8 * s, va_list * args)
{
  rdma_device_t *rd = va_arg (*args, rdma_device_t *);
  u8 *t = 0;

#define _(a, b, c) if (rd->flags & (1 << a)) \
t = format (t, "%s%s", t ? " ":"", c);
  foreach_rdma_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_rdma_device (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, i);
  u32 indent = format_get_indent (s);

  s = format (s, "netdev: %v\n", rd->linux_ifname);
  s = format (s, "%Uflags: %U", format_white_space, indent,
	      format_rdma_device_flags, rd);
  if (rd->error)
    s = format (s, "\n%Uerror %U", format_white_space, indent,
		format_clib_error, rd->error);

  return s;
}

u8 *
format_rdma_input_trace (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  rdma_input_trace_t *t = va_arg (*args, rdma_input_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "rdma: %v (%d) next-node %U",
	      hi->name, t->hw_if_index, format_vlib_next_node_name, vm,
	      node->index, t->next_index);

  return s;
}


/* mlx5dv specific format functions */


#define foreach_cqe_rx_field \
  _(0x1c, 26, 26, l4_ok)	\
  _(0x1c, 25, 25, l3_ok)	\
  _(0x1c, 24, 24, l2_ok)	\
  _(0x1c, 23, 23, ip_frag)	\
  _(0x1c, 22, 20, l4_hdr_type)	\
  _(0x1c, 19, 18, l3_hdr_type)	\
  _(0x1c, 17, 17, ip_ext_opts)	\
  _(0x1c, 16, 16, cv)	\
  _(0x2c, 31,  0, byte_cnt)	\
  _(0x30, 63,  0, timestamp)	\
  _(0x34, 7,  0, syndrome)	\
  _(0x38, 31, 24, rx_drop_counter)	\
  _(0x38, 23,  0, flow_tag)	\
  _(0x3c, 31, 16, wqe_counter)	\
  _(0x3c, 15,  8, signature)	\
  _(0x3c,  7,  4, opcode)	\
  _(0x3c,  3,  2, cqe_format)	\
  _(0x3c,  1,  1, sc)	\
  _(0x3c,  0,  0, owner)

static inline u32
mlx5_get_u32 (void *start, int offset)
{
  return clib_net_to_host_u32 (*(u32 *) (((u8 *) start) + offset));
}

static inline u32
mlx5_get_bits (void *start, int offset, int first, int last)
{
  u32 value = mlx5_get_u32 (start, offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline u64
mlx5_get_u64 (void *start, int offset)
{
  return clib_net_to_host_u64 (*(u64 *) (((u8 *) start) + offset));
}

static u8 *
format_mlx5_bits (u8 * s, va_list * args)
{
  void *ptr = va_arg (*args, void *);
  u32 offset = va_arg (*args, u32);
  u32 sb = va_arg (*args, u32);
  u32 eb = va_arg (*args, u32);

  if (sb == 63 && eb == 0)
    {
      u64 x = mlx5_get_u64 (ptr, offset);
      return format (s, "0x%lx", x);
    }

  u32 x = mlx5_get_bits (ptr, offset, sb, eb);
  s = format (s, "%d", x);
  if (x > 9)
    s = format (s, " (0x%x)", x);
  return s;
}

static u8 *
format_mlx5_field (u8 * s, va_list * args)
{
  void *ptr = va_arg (*args, void *);
  u32 offset = va_arg (*args, u32);
  u32 sb = va_arg (*args, u32);
  u32 eb = va_arg (*args, u32);
  char *name = va_arg (*args, char *);

  u8 *tmp = 0;

  tmp = format (0, "0x%02x %s ", offset, name);
  if (sb == eb)
    tmp = format (tmp, "[%u]", sb);
  else
    tmp = format (tmp, "[%u:%u]", sb, eb);
  s = format (s, "%-45v = %U", tmp, format_mlx5_bits, ptr, offset, sb, eb);
  vec_free (tmp);

  return s;
}

u8 *
format_mlx5_cqe_rx (u8 * s, va_list * args)
{
  void *cqe = va_arg (*args, void *);
  uword indent = format_get_indent (s);
  int line = 0;

#define _(a, b, c, d) if (mlx5_get_bits (cqe, a, b, c)) s = format (s, "%U%U\n",	\
				    format_white_space, line++ ? indent : 0,	\
				    format_mlx5_field, cqe, a, b, c, #d);
  foreach_cqe_rx_field;
#undef _
  return s;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
