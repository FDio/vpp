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
format_rdma_bit_flag (u8 * s, va_list * args)
{
  u64 flags = va_arg (*args, u64);
  char **strs = va_arg (*args, char **);
  u32 n_strs = va_arg (*args, u32);
  int i = 0;

  while (flags)
    {
      if ((flags & (1 << i)))
	{
	  if (i < n_strs && strs[i] != 0)
	    s = format (s, " %s", strs[i]);
	  else
	    s = format (s, " unknown(%u)", i);
	  flags ^= 1 << i;
	}
      i++;
    }

  return s;
}

u8 *
format_rdma_rss4 (u8 *s, va_list *args)
{
  const rdma_rss4_t *rss4 = va_arg (*args, const rdma_rss4_t *);
  switch (*rss4)
    {
    case RDMA_RSS4_IP:
      return format (s, "ipv4");
    case RDMA_RSS4_IP_UDP:
      return format (s, "ipv4-udp");
    case RDMA_RSS4_AUTO: /* fallthrough */
    case RDMA_RSS4_IP_TCP:
      return format (s, "ipv4-tcp");
    }
  ASSERT (0);
  return format (s, "unknown(%x)", *rss4);
}

u8 *
format_rdma_rss6 (u8 *s, va_list *args)
{
  const rdma_rss6_t *rss6 = va_arg (*args, const rdma_rss6_t *);
  switch (*rss6)
    {
    case RDMA_RSS6_IP:
      return format (s, "ipv6");
    case RDMA_RSS6_IP_UDP:
      return format (s, "ipv6-udp");
    case RDMA_RSS6_AUTO: /* fallthrough */
    case RDMA_RSS6_IP_TCP:
      return format (s, "ipv6-tcp");
    }
  ASSERT (0);
  return format (s, "unknown(%x)", *rss6);
}

u8 *
format_rdma_device (u8 * s, va_list * args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 i = va_arg (*args, u32);
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, i);
  vlib_pci_device_info_t *d;
  u32 indent = format_get_indent (s);

  s = format (s, "netdev %v pci-addr %U\n", rd->linux_ifname,
	      format_vlib_pci_addr, &rd->pci->addr);
  if ((d = vlib_pci_get_device_info (vm, &rd->pci->addr, 0)))
    {
      s = format (s, "%Uproduct name: %s\n", format_white_space, indent,
		  d->product_name ? (char *) d->product_name : "");
      s = format (s, "%Upart number: %U\n", format_white_space, indent,
		  format_vlib_pci_vpd, d->vpd_r, "PN");
      s = format (s, "%Urevision: %U\n", format_white_space, indent,
		  format_vlib_pci_vpd, d->vpd_r, "EC");
      s = format (s, "%Userial number: %U\n", format_white_space, indent,
		  format_vlib_pci_vpd, d->vpd_r, "SN");
      vlib_pci_free_device_info (d);
    }
  s = format (s, "%Uflags: %U\n", format_white_space, indent,
	      format_rdma_device_flags, rd);
  s = format (s, "%Urss: %U %U", format_white_space, indent, format_rdma_rss4,
	      &rd->rss4, format_rdma_rss6, &rd->rss6);
  if (rd->error)
    s = format (s, "\n%Uerror %U", format_white_space, indent,
		format_clib_error, rd->error);

  if (rd->flags & RDMA_DEVICE_F_MLX5DV)
    {
      struct mlx5dv_context c = { };
      const char *str_flags[7] = { "cqe-v1", "obsolete", "mpw-allowed",
	"enhanced-mpw", "cqe-128b-comp", "cqe-128b-pad",
	"packet-based-credit-mode"
      };

      if (mlx5dv_query_device (rd->ctx, &c) != 0)
	return s;

      s = format (s, "\n%Umlx5: version %u", format_white_space, indent,
		  c.version);
      s = format (s, "\n%Udevice flags: %U",
		  format_white_space, indent + 2,
		  format_rdma_bit_flag, c.flags, str_flags,
		  ARRAY_LEN (str_flags));
    }

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
  char *l4_hdr_types[8] =
    { 0, "tcp", "udp", "tcp-empty-ack", "tcp-with-acl" };
  char *l3_hdr_types[4] = { 0, "ip6", "ip4" };
  u8 l3_hdr_type = CQE_FLAG_L3_HDR_TYPE (t->cqe_flags);
  u8 l4_hdr_type = CQE_FLAG_L4_HDR_TYPE (t->cqe_flags);

  s = format (s, "rdma: %v (%d) next-node %U",
	      hi->name, t->hw_if_index, format_vlib_next_node_name, vm,
	      node->index, t->next_index);

  if (t->cqe_flags & CQE_FLAG_L2_OK)
    s = format (s, " l2-ok");

  if (t->cqe_flags & CQE_FLAG_L3_OK)
    s = format (s, " l3-ok");

  if (t->cqe_flags & CQE_FLAG_L4_OK)
    s = format (s, " l4-ok");

  if (t->cqe_flags & CQE_FLAG_IP_FRAG)
    s = format (s, " ip-frag");

  if (l3_hdr_type)
    s = format (s, " %s", l3_hdr_types[l3_hdr_type]);

  if (l4_hdr_type)
    s = format (s, " %s", l4_hdr_types[l4_hdr_type]);

  if ((t->cqe_flags & CQE_FLAG_IP_EXT_OPTS))
    {
      if (l3_hdr_type == CQE_FLAG_L3_HDR_TYPE_IP6)
	s = format (s, " ip4-ext-hdr");
      if (l3_hdr_type == CQE_FLAG_L3_HDR_TYPE_IP4)
	s = format (s, " ip4-opt");
    }

  return s;
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

#define _(a, b, c, d) \
  if (mlx5_get_bits (cqe, a, b, c)) \
    s = format (s, "%U%U\n", \
		format_white_space, line++ ? indent : 0, \
		format_mlx5_field, cqe, a, b, c, #d);
  foreach_cqe_rx_field;
#undef _
  return s;
}

u8 *
format_rdma_rxq (u8 * s, va_list * args)
{
  rdma_device_t *rd = va_arg (*args, rdma_device_t *);
  u32 queue_index = va_arg (*args, u32);
  rdma_rxq_t *rxq = vec_elt_at_index (rd->rxqs, queue_index);
  u32 indent = format_get_indent (s);

  s = format (s, "size %u head %u tail %u", rxq->size, rxq->head, rxq->tail);

  if (rd->flags & RDMA_DEVICE_F_MLX5DV)
    {
      u32 next_cqe_index = rxq->cq_ci & (rxq->size - 1);
      s = format (s, "\n%Uwq: stride %u wqe-cnt %u",
		  format_white_space, indent + 2, rxq->wq_stride,
		  rxq->wqe_cnt);
      s = format (s, "\n%Ucq: cqn %u cqe-cnt %u ci %u",
		  format_white_space, indent + 2, rxq->cqn,
		  1 << rxq->log2_cq_size, rxq->cq_ci);
      s = format (s, "\n%Unext-cqe(%u):", format_white_space, indent + 4,
		  next_cqe_index);
      s = format (s, "\n%U%U", format_white_space, indent + 6,
		  format_mlx5_cqe_rx, rxq->cqes + next_cqe_index);
      s = format (s, "\n%U%U", format_white_space, indent + 6,
		  format_hexdump, rxq->cqes + next_cqe_index,
		  sizeof (mlx5dv_cqe_t));
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
