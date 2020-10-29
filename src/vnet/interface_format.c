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
/*
 * interface_format.c: interface formatting
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/vnet.h>
#include <vppinfra/bitmap.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_vtr.h>

u8 *
format_vtr (u8 * s, va_list * args)
{
  u32 vtr_op = va_arg (*args, u32);
  u32 dot1q = va_arg (*args, u32);
  u32 tag1 = va_arg (*args, u32);
  u32 tag2 = va_arg (*args, u32);
  switch (vtr_op)
    {
    case L2_VTR_DISABLED:
      return format (s, "none");
    case L2_VTR_PUSH_1:
      return format (s, "push-1 %s %d", dot1q ? "dot1q" : "dot1ad", tag1);
    case L2_VTR_PUSH_2:
      return format (s, "push-2 %s %d %d", dot1q ? "dot1q" : "dot1ad", tag1,
		     tag2);
    case L2_VTR_POP_1:
      return format (s, "pop-1");
    case L2_VTR_POP_2:
      return format (s, "pop-2");
    case L2_VTR_TRANSLATE_1_1:
      return format (s, "trans-1-1 %s %d", dot1q ? "dot1q" : "dot1ad", tag1);
    case L2_VTR_TRANSLATE_1_2:
      return format (s, "trans-1-2 %s %d %d", dot1q ? "dot1q" : "dot1ad",
		     tag1, tag2);
    case L2_VTR_TRANSLATE_2_1:
      return format (s, "trans-2-1 %s %d", dot1q ? "dot1q" : "dot1ad", tag1);
    case L2_VTR_TRANSLATE_2_2:
      return format (s, "trans-2-2 %s %d %d", dot1q ? "dot1q" : "dot1ad",
		     tag1, tag2);
    default:
      return format (s, "none");
    }
}

u8 *
format_vnet_sw_interface_flags (u8 * s, va_list * args)
{
  u32 flags = va_arg (*args, u32);

  if (flags & VNET_SW_INTERFACE_FLAG_ERROR)
    s = format (s, "error");
  else
    {
      s = format (s, "%s",
		  (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "down");
      if (flags & VNET_SW_INTERFACE_FLAG_PUNT)
	s = format (s, "/punt");
    }

  return s;
}

u8 *
format_vnet_hw_if_rx_mode (u8 * s, va_list * args)
{
  vnet_hw_if_rx_mode mode = va_arg (*args, vnet_hw_if_rx_mode);

  if (mode == VNET_HW_IF_RX_MODE_POLLING)
    return format (s, "polling");

  if (mode == VNET_HW_IF_RX_MODE_INTERRUPT)
    return format (s, "interrupt");

  if (mode == VNET_HW_IF_RX_MODE_ADAPTIVE)
    return format (s, "adaptive");

  return format (s, "unknown");
}

u8 *
format_vnet_hw_interface_link_speed (u8 * s, va_list * args)
{
  u32 link_speed = va_arg (*args, u32);

  if (link_speed == 0)
    return format (s, "unknown");

  if (link_speed >= 1000000)
    return format (s, "%f Gbps", (f64) link_speed / 1000000);

  if (link_speed >= 1000)
    return format (s, "%f Mbps", (f64) link_speed / 1000);

  return format (s, "%u Kbps", link_speed);
}

u8 *
format_vnet_hw_interface_rss_queues (u8 * s, va_list * args)
{
  clib_bitmap_t *bitmap = va_arg (*args, clib_bitmap_t *);
  int i;

  if (bitmap == NULL)
    return s;

  if (bitmap)
    {
    /* *INDENT-OFF* */
    clib_bitmap_foreach (i, bitmap, ({
      s = format (s, "%u ", i);
    }));
    /* *INDENT-ON* */
    }

  return s;
}

u8 *
format_vnet_hw_interface (u8 * s, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  vnet_hw_interface_t *hi = va_arg (*args, vnet_hw_interface_t *);
  vnet_hw_interface_class_t *hw_class;
  vnet_device_class_t *dev_class;
  int verbose = va_arg (*args, int);
  u32 indent;

  if (!hi)
    return format (s, "%=32s%=6s%=8s%s", "Name", "Idx", "Link", "Hardware");

  indent = format_get_indent (s);

  s = format (s, "%-32v%=6d", hi->name, hi->hw_if_index);

  if (hi->bond_info == VNET_HW_INTERFACE_BOND_INFO_SLAVE)
    s = format (s, "%=8s", "slave");
  else
    s = format (s, "%=8s",
		hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP ? "up" : "down");

  hw_class = vnet_get_hw_interface_class (vnm, hi->hw_class_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (hi->bond_info && (hi->bond_info != VNET_HW_INTERFACE_BOND_INFO_SLAVE))
    {
      int hw_idx;
      s = format (s, "Slave-Idx:");
      clib_bitmap_foreach (hw_idx, hi->bond_info, s =
			   format (s, " %d", hw_idx));
    }
  else if (dev_class->format_device_name)
    s = format (s, "%U", dev_class->format_device_name, hi->dev_instance);
  else
    s = format (s, "%s%d", dev_class->name, hi->dev_instance);

  s = format (s, "\n%ULink speed: %U", format_white_space, indent + 2,
	      format_vnet_hw_interface_link_speed, hi->link_speed);

  if (hi->rss_queues)
    {
      s = format (s, "\n%URSS queues: %U", format_white_space, indent + 2,
		  format_vnet_hw_interface_rss_queues, hi->rss_queues);
    }

  if (verbose)
    {
      if (hw_class->format_device)
	s = format (s, "\n%U%U",
		    format_white_space, indent + 2,
		    hw_class->format_device, hi->hw_if_index, verbose);
      else
	{
	  s = format (s, "\n%U%s",
		      format_white_space, indent + 2, hw_class->name);
	  if (hw_class->format_address && vec_len (hi->hw_address) > 0)
	    s =
	      format (s, " address %U", hw_class->format_address,
		      hi->hw_address);
	}

      if (dev_class->format_device)
	s = format (s, "\n%U%U",
		    format_white_space, indent + 2,
		    dev_class->format_device, hi->dev_instance, verbose);
    }

  return s;
}

u8 *
format_vnet_sw_interface_name (u8 * s, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  vnet_sw_interface_t *si = va_arg (*args, vnet_sw_interface_t *);
  vnet_sw_interface_t *si_sup =
    vnet_get_sup_sw_interface (vnm, si->sw_if_index);
  vnet_hw_interface_t *hi_sup;

  ASSERT (si_sup->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
  hi_sup = vnet_get_hw_interface (vnm, si_sup->hw_if_index);

  s = format (s, "%v", hi_sup->name);

  if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    s = format (s, ".%d", si->sub.id);

  return s;
}

u8 *
format_vnet_sw_if_index_name (u8 * s, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 sw_if_index = va_arg (*args, u32);
  vnet_sw_interface_t *si;

  si = vnet_get_sw_interface_or_null (vnm, sw_if_index);

  if (NULL == si)
    {
      return format (s, "DELETED");
    }
  return format (s, "%U", format_vnet_sw_interface_name, vnm, si);
}

u8 *
format_vnet_hw_if_index_name (u8 * s, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 hw_if_index = va_arg (*args, u32);
  vnet_hw_interface_t *hi;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (hi == 0)
    return format (s, "DELETED");

  return format (s, "%v", hi->name);
}

u8 *
format_vnet_sw_interface_cntrs (u8 * s, vnet_interface_main_t * im,
				vnet_sw_interface_t * si, int json)
{
  u32 indent, n_printed;
  int j, n_counters;
  char *x = "";
  int json_need_comma_nl = 0;
  u8 *n = 0;

  /*
   * to output a json snippet, stick quotes in lots of places
   * definitely deserves a one-character variable name.
   */
  if (json)
    x = "\"";

  indent = format_get_indent (s);
  n_printed = 0;

  n_counters = vec_len (im->combined_sw_if_counters);

  /* rx, tx counters... */
  for (j = 0; j < n_counters; j++)
    {
      vlib_combined_counter_main_t *cm;
      vlib_counter_t v, vtotal;
      vtotal.packets = 0;
      vtotal.bytes = 0;

      cm = im->combined_sw_if_counters + j;
      vlib_get_combined_counter (cm, si->sw_if_index, &v);
      vtotal.packets += v.packets;
      vtotal.bytes += v.bytes;

      /* Only display non-zero counters. */
      if (vtotal.packets == 0)
	continue;

      if (json)
	{
	  if (json_need_comma_nl)
	    {
	      vec_add1 (s, ',');
	      vec_add1 (s, '\n');
	    }
	  s = format (s, "%s%s_packets%s: %s%Ld%s,\n", x, cm->name, x, x,
		      vtotal.packets, x);
	  s = format (s, "%s%s_bytes%s: %s%Ld%s", x, cm->name, x, x,
		      vtotal.bytes, x);
	  json_need_comma_nl = 1;
	  continue;
	}

      if (n_printed > 0)
	s = format (s, "\n%U", format_white_space, indent);
      n_printed += 2;

      if (n)
	_vec_len (n) = 0;
      n = format (n, "%s packets", cm->name);
      s = format (s, "%-16v%16Ld", n, vtotal.packets);

      _vec_len (n) = 0;
      n = format (n, "%s bytes", cm->name);
      s = format (s, "\n%U%-16v%16Ld",
		  format_white_space, indent, n, vtotal.bytes);
    }
  vec_free (n);

  {
    vlib_simple_counter_main_t *cm;
    u64 v, vtotal;

    n_counters = vec_len (im->sw_if_counters);

    for (j = 0; j < n_counters; j++)
      {
	vtotal = 0;

	cm = im->sw_if_counters + j;

	v = vlib_get_simple_counter (cm, si->sw_if_index);
	vtotal += v;

	/* Only display non-zero counters. */
	if (vtotal == 0)
	  continue;

	if (json)
	  {
	    if (json_need_comma_nl)
	      {
		vec_add1 (s, ',');
		vec_add1 (s, '\n');
	      }
	    s = format (s, "%s%s%s: %s%Ld%s", x, cm->name, x, x, vtotal, x);
	    json_need_comma_nl = 1;
	    continue;
	  }


	if (n_printed > 0)
	  s = format (s, "\n%U", format_white_space, indent);
	n_printed += 1;

	s = format (s, "%-16s%16Ld", cm->name, vtotal);
      }
  }

  return s;
}

static u8 *
format_vnet_sw_interface_mtu (u8 * s, va_list * args)
{
  vnet_sw_interface_t *si = va_arg (*args, vnet_sw_interface_t *);

  return format (s, "%d/%d/%d/%d", si->mtu[VNET_MTU_L3],
		 si->mtu[VNET_MTU_IP4],
		 si->mtu[VNET_MTU_IP6], si->mtu[VNET_MTU_MPLS]);
}

u8 *
format_vnet_sw_interface (u8 * s, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  vnet_sw_interface_t *si = va_arg (*args, vnet_sw_interface_t *);
  vnet_interface_main_t *im = &vnm->interface_main;

  if (!si)
    return format (s, "%=32s%=5s%=10s%=21s%=16s%=16s",
		   "Name", "Idx", "State", "MTU (L3/IP4/IP6/MPLS)", "Counter",
		   "Count");

  s = format (s, "%-32U%=5d%=10U%=21U",
	      format_vnet_sw_interface_name, vnm, si, si->sw_if_index,
	      format_vnet_sw_interface_flags, si->flags,
	      format_vnet_sw_interface_mtu, si);

  s = format_vnet_sw_interface_cntrs (s, im, si, 0 /* want json */ );

  return s;
}

u8 *
format_vnet_sw_interface_name_override (u8 * s, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  vnet_sw_interface_t *si = va_arg (*args, vnet_sw_interface_t *);
  /* caller supplied display name for this interface */
  u8 *name = va_arg (*args, u8 *);
  vnet_interface_main_t *im = &vnm->interface_main;


  if (!si)
    return format (s, "%=32s%=5s%=16s%=16s%=16s",
		   "Name", "Idx", "State", "Counter", "Count");

  s = format (s, "%-32v%=5d%=16U",
	      name, si->sw_if_index,
	      format_vnet_sw_interface_flags, si->flags);

  s = format_vnet_sw_interface_cntrs (s, im, si, 0 /* want json */ );

  return s;
}

u8 *
format_vnet_buffer_flags (u8 * s, va_list * args)
{
  vlib_buffer_t *buf = va_arg (*args, vlib_buffer_t *);

#define _(a,b,c,v) if (buf->flags & VNET_BUFFER_F_##b) s = format (s, "%s ", c);
  foreach_vnet_buffer_flag;
#undef _
  return s;
}

u8 *
format_vnet_buffer_opaque (u8 * s, va_list * args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);
  vnet_buffer_opaque_t *o = (vnet_buffer_opaque_t *) b->opaque;
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;
  vnet_buffer_opquae_formatter_t helper_fp;
  int i;

  s = format (s, "raw: ");

  for (i = 0; i < ARRAY_LEN (b->opaque); i++)
    s = format (s, "%08x ", b->opaque[i]);

  vec_add1 (s, '\n');

  s = format (s,
	      "sw_if_index[VLIB_RX]: %d, sw_if_index[VLIB_TX]: %d",
	      o->sw_if_index[0], o->sw_if_index[1]);
  vec_add1 (s, '\n');

  s = format (s,
	      "L2 offset %d, L3 offset %d, L4 offset %d, feature arc index %d",
	      (u32) (o->l2_hdr_offset),
	      (u32) (o->l3_hdr_offset),
	      (u32) (o->l4_hdr_offset), (u32) (o->feature_arc_index));
  vec_add1 (s, '\n');

  s = format (s,
	      "ip.adj_index[VLIB_RX]: %d, ip.adj_index[VLIB_TX]: %d",
	      (u32) (o->ip.adj_index[0]), (u32) (o->ip.adj_index[1]));
  vec_add1 (s, '\n');

  s = format (s,
	      "ip.flow_hash: 0x%x, ip.save_protocol: 0x%x, ip.fib_index: %d",
	      o->ip.flow_hash, o->ip.save_protocol, o->ip.fib_index);
  vec_add1 (s, '\n');

  s = format (s,
	      "ip.save_rewrite_length: %d, ip.rpf_id: %d",
	      o->ip.save_rewrite_length, o->ip.rpf_id);
  vec_add1 (s, '\n');

  s = format (s,
	      "ip.icmp.type: %d ip.icmp.code: %d, ip.icmp.data: 0x%x",
	      (u32) (o->ip.icmp.type),
	      (u32) (o->ip.icmp.code), o->ip.icmp.data);
  vec_add1 (s, '\n');

  s = format (s,
	      "ip.reass.next_index: %d, ip.reass.estimated_mtu: %d",
	      o->ip.reass.next_index, (u32) (o->ip.reass.estimated_mtu));
  vec_add1 (s, '\n');
  s = format (s,
	      "ip.reass.error_next_index: %d, ip.reass.owner_thread_index: %d",
	      o->ip.reass.error_next_index,
	      (u32) (o->ip.reass.owner_thread_index));
  vec_add1 (s, '\n');
  s = format (s,
	      "ip.reass.ip_proto: %d, ip.reass.l4_src_port: %d",
	      o->ip.reass.ip_proto, (u32) (o->ip.reass.l4_src_port));
  vec_add1 (s, '\n');
  s = format (s, "ip.reass.l4_dst_port: %d", o->ip.reass.l4_dst_port);
  vec_add1 (s, '\n');

  s = format (s,
	      "ip.reass.fragment_first: %d ip.reass.fragment_last: %d",
	      (u32) (o->ip.reass.fragment_first),
	      (u32) (o->ip.reass.fragment_last));
  vec_add1 (s, '\n');

  s = format (s,
	      "ip.reass.range_first: %d ip.reass.range_last: %d",
	      (u32) (o->ip.reass.range_first),
	      (u32) (o->ip.reass.range_last));
  vec_add1 (s, '\n');

  s = format (s,
	      "ip.reass.next_range_bi: 0x%x, ip.reass.ip6_frag_hdr_offset: %d",
	      o->ip.reass.next_range_bi,
	      (u32) (o->ip.reass.ip6_frag_hdr_offset));
  vec_add1 (s, '\n');

  s = format (s,
	      "mpls.ttl: %d, mpls.exp: %d, mpls.first: %d, "
	      "mpls.save_rewrite_length: %d, mpls.bier.n_bytes: %d",
	      (u32) (o->mpls.ttl), (u32) (o->mpls.exp), (u32) (o->mpls.first),
	      o->mpls.save_rewrite_length, (u32) (o->mpls.bier.n_bytes));
  vec_add1 (s, '\n');
  s = format (s, "mpls.mpls_hdr_length: %d", (u32) (o->mpls.mpls_hdr_length));
  vec_add1 (s, '\n');

  s = format (s,
	      "l2.feature_bitmap: %08x, l2.bd_index: %d, l2.l2fib_sn %d, "
	      "l2.l2_len: %d, l2.shg: %d, l2.bd_age: %d",
	      (u32) (o->l2.feature_bitmap), (u32) (o->l2.bd_index),
	      (u32) (o->l2.l2fib_sn),
	      (u32) (o->l2.l2_len), (u32) (o->l2.shg), (u32) (o->l2.bd_age));
  vec_add1 (s, '\n');

  s = format (s,
	      "l2.feature_bitmap_input: %U, L2.feature_bitmap_output: %U",
	      format_l2_input_feature_bitmap, o->l2.feature_bitmap, 0,
	      format_l2_output_features, o->l2.feature_bitmap, 0);
  vec_add1 (s, '\n');

  s = format (s,
	      "l2t.next_index: %d, l2t.session_index: %d",
	      (u32) (o->l2t.next_index), o->l2t.session_index);
  vec_add1 (s, '\n');

  s = format (s,
	      "l2_classify.table_index: %d, l2_classify.opaque_index: %d, "
	      "l2_classify.hash: 0x%llx",
	      o->l2_classify.table_index,
	      o->l2_classify.opaque_index, o->l2_classify.hash);
  vec_add1 (s, '\n');

  s = format (s, "policer.index: %d", o->policer.index);
  vec_add1 (s, '\n');

  s = format (s, "ipsec.sad_index: %d, ipsec.protect_index",
	      o->ipsec.sad_index, o->ipsec.protect_index);
  vec_add1 (s, '\n');

  s = format (s, "map.mtu: %d", (u32) (o->map.mtu));
  vec_add1 (s, '\n');

  s = format (s,
	      "map_t.map_domain_index: %d, map_t.v6.saddr: 0x%x, "
	      "map_t.v6.daddr: 0x%x, map_t.v6.frag_offset: %d, "
	      "map_t.v6.l4_offset: %d, map_t.v6.l4_protocol: %d, "
	      "map.t.checksum_offset: %d",
	      o->map_t.map_domain_index,
	      o->map_t.v6.saddr,
	      o->map_t.v6.daddr,
	      (u32) (o->map_t.v6.frag_offset), (u32) (o->map_t.v6.l4_offset),
	      (u32) (o->map_t.v6.l4_protocol),
	      (u32) (o->map_t.checksum_offset));
  vec_add1 (s, '\n');

  s = format (s,
	      "map_t.v6.l4_protocol: %d, map_t.checksum_offset: %d, "
	      "map_t.mtu: %d",
	      (u32) (o->map_t.v6.l4_protocol),
	      (u32) (o->map_t.checksum_offset), (u32) (o->map_t.mtu));
  vec_add1 (s, '\n');

  s = format (s,
	      "ip_frag.mtu: %d, ip_frag.next_index: %d, ip_frag.flags: 0x%x",
	      (u32) (o->ip_frag.mtu),
	      (u32) (o->ip_frag.next_index), (u32) (o->ip_frag.flags));
  vec_add1 (s, '\n');

  s = format (s, "cop.current_config_index: %d", o->cop.current_config_index);
  vec_add1 (s, '\n');

  s = format (s, "lisp.overlay_afi: %d", (u32) (o->lisp.overlay_afi));
  vec_add1 (s, '\n');

  s = format
    (s,
     "tcp.connection_index: %d, tcp.seq_number: %d, tcp.next_node_opaque: %d "
     "tcp.seq_end: %d, tcp.ack_number: %d, tcp.hdr_offset: %d, "
     "tcp.data_offset: %d", o->tcp.connection_index, o->tcp.next_node_opaque,
     o->tcp.seq_number, o->tcp.seq_end, o->tcp.ack_number,
     (u32) (o->tcp.hdr_offset), (u32) (o->tcp.data_offset));
  vec_add1 (s, '\n');

  s = format (s,
	      "tcp.data_len: %d, tcp.flags: 0x%x",
	      (u32) (o->tcp.data_len), (u32) (o->tcp.flags));
  vec_add1 (s, '\n');

  s = format (s, "snat.flags: 0x%x", o->snat.flags);
  vec_add1 (s, '\n');

  for (i = 0; i < vec_len (im->buffer_opaque_format_helpers); i++)
    {
      helper_fp = im->buffer_opaque_format_helpers[i];
      s = (*helper_fp) (b, s);
    }

  return s;
}

u8 *
format_vnet_buffer_opaque2 (u8 * s, va_list * args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);
  vnet_buffer_opaque2_t *o = (vnet_buffer_opaque2_t *) b->opaque2;
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;
  vnet_buffer_opquae_formatter_t helper_fp;

  int i;

  s = format (s, "raw: ");

  for (i = 0; i < ARRAY_LEN (b->opaque2); i++)
    s = format (s, "%08x ", b->opaque2[i]);
  vec_add1 (s, '\n');

  s = format (s, "qos.bits: %x, qos.source: %x",
	      (u32) (o->qos.bits), (u32) (o->qos.source));
  vec_add1 (s, '\n');
  s = format (s, "loop_counter: %d", o->loop_counter);
  vec_add1 (s, '\n');

  s = format (s, "gbp.flags: %x, gbp.sclass: %d",
	      (u32) (o->gbp.flags), (u32) (o->gbp.sclass));
  vec_add1 (s, '\n');

  s = format (s, "gso_size: %d, gso_l4_hdr_sz: %d",
	      (u32) (o->gso_size), (u32) (o->gso_l4_hdr_sz));
  vec_add1 (s, '\n');

  s = format (s, "pg_replay_timestamp: %llu", (u32) (o->pg_replay_timestamp));
  vec_add1 (s, '\n');

  for (i = 0; i < vec_len (im->buffer_opaque2_format_helpers); i++)
    {
      helper_fp = im->buffer_opaque2_format_helpers[i];
      s = (*helper_fp) (b, s);
    }

  return s;
}

void
vnet_register_format_buffer_opaque_helper (vnet_buffer_opquae_formatter_t fp)
{
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;
  vec_add1 (im->buffer_opaque_format_helpers, fp);
}

void
vnet_register_format_buffer_opaque2_helper (vnet_buffer_opquae_formatter_t fp)
{
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;
  vec_add1 (im->buffer_opaque2_format_helpers, fp);
}


uword
unformat_vnet_buffer_flags (unformat_input_t * input, va_list * args)
{
  u32 *flagp = va_arg (*args, u32 *);
  int rv = 0;
  u32 flags = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* Red herring, there is no such buffer flag */
      if (unformat (input, "avail10"))
	return 0;
#define _(bit,enum,str,verbose)                                 \
      else if (unformat (input, str))                           \
        {                                                       \
          flags |= (1 << LOG2_VLIB_BUFFER_FLAG_USER(bit));      \
          rv = 1;                                               \
        }
      foreach_vnet_buffer_flag
#undef _
	else
	break;
    }
  if (rv)
    *flagp = flags;
  return rv;
}

uword
unformat_vnet_buffer_offload_flags (unformat_input_t * input, va_list * args)
{
  u32 *flagp = va_arg (*args, u32 *);
  int rv = 0;
  u32 oflags = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* Red herring, there is no such buffer flag */
      if (unformat (input, "avail10"))
	return 0;
#define _(bit,enum,str,verbose)                                 \
      else if (unformat (input, str))                           \
        {                                                       \
          oflags |= (1 << bit);                                 \
          rv = 1;                                               \
        }
      foreach_vnet_buffer_offload_flag
#undef _
	else
	break;
    }
  if (rv)
    *flagp = oflags;
  return rv;
}

uword
unformat_vnet_hw_interface (unformat_input_t * input, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 *hw_if_index = va_arg (*args, u32 *);
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_device_class_t *c;

  /* Try per device class functions first. */
  vec_foreach (c, im->device_classes)
  {
    if (c->unformat_device_name
	&& unformat_user (input, c->unformat_device_name, hw_if_index))
      return 1;
  }

  return unformat_user (input, unformat_hash_vec_string,
			im->hw_interface_by_name, hw_if_index);
}

uword
unformat_vnet_sw_interface (unformat_input_t * input, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 *result = va_arg (*args, u32 *);
  vnet_hw_interface_t *hi;
  u32 hw_if_index, id, id_specified;
  u32 sw_if_index;
  u8 *if_name = 0;
  uword *p, error = 0;

  id = ~0;
  if (unformat (input, "%_%v.%d%_", &if_name, &id)
      && ((p = hash_get (vnm->interface_main.hw_interface_by_name, if_name))))
    {
      hw_if_index = p[0];
      id_specified = 1;
    }
  else
    if (unformat (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
    id_specified = 0;
  else
    goto done;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  if (!id_specified)
    {
      sw_if_index = hi->sw_if_index;
    }
  else
    {
      if (!(p = hash_get (hi->sub_interface_sw_if_index_by_id, id)))
	goto done;
      sw_if_index = p[0];
    }
  if (!vnet_sw_interface_is_api_visible (vnm, sw_if_index))
    goto done;
  *result = sw_if_index;
  error = 1;
done:
  vec_free (if_name);
  return error;
}

uword
unformat_vnet_sw_interface_flags (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 flags = 0;

  if (unformat (input, "up"))
    flags |= VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  else if (unformat (input, "down"))
    flags &= ~VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  else if (unformat (input, "punt"))
    flags |= VNET_SW_INTERFACE_FLAG_PUNT;
  else if (unformat (input, "enable"))
    flags &= ~VNET_SW_INTERFACE_FLAG_PUNT;
  else
    return 0;

  *result = flags;
  return 1;
}

uword
unformat_vnet_hw_interface_flags (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 flags = 0;

  if (unformat (input, "up"))
    flags |= VNET_HW_INTERFACE_FLAG_LINK_UP;
  else if (unformat (input, "down"))
    flags &= ~VNET_HW_INTERFACE_FLAG_LINK_UP;
  else
    return 0;

  *result = flags;
  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
