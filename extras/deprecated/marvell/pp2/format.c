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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/linux/syscall.h>
#include <vnet/plugin/plugin.h>
#include <marvell/pp2/pp2.h>

static inline u32
mrvl_get_u32_bits (void *start, int offset, int first, int last)
{
  u32 value = *(u32 *) (((u8 *) start) + offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

u8 *
format_mrvl_pp2_interface_name (u8 * s, va_list * args)
{
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  u32 dev_instance = va_arg (*args, u32);
  mrvl_pp2_if_t *ppif = pool_elt_at_index (ppm->interfaces, dev_instance);
  return format (s, "mv-ppio-%d/%d", ppif->ppio->pp2_id, ppif->ppio->port_id);
}

#define foreach_ppio_statistics_entry \
  _(rx_packets) \
  _(rx_fullq_dropped) \
  _(rx_bm_dropped) \
  _(rx_early_dropped) \
  _(rx_fifo_dropped) \
  _(rx_cls_dropped) \
  _(tx_packets)

#define foreach_ppio_inq_statistics_entry \
  _(enq_desc) \
  _(drop_early) \
  _(drop_fullq) \
  _(drop_bm)

#define foreach_ppio_outq_statistics_entry \
  _(enq_desc) \
  _(enq_dec_to_ddr) \
  _(enq_buf_to_ddr) \
  _(deq_desc)

u8 *
format_mrvl_pp2_interface (u8 * s, va_list * args)
{
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  u32 dev_instance = va_arg (*args, u32);
  u32 indent = format_get_indent (s);
  mrvl_pp2_if_t *ppif = pool_elt_at_index (ppm->interfaces, dev_instance);
  struct pp2_ppio_statistics stat;
  int i;
  u8 *s2 = 0;

  pp2_ppio_get_statistics (ppif->ppio, &stat, 0);

#define _(c) if (stat.c) \
  s2 = format (s2, "\n%U%-25U%16Ld", \
	      format_white_space, indent + 2, \
	      format_c_identifier, #c, stat.c);
  foreach_ppio_statistics_entry;

  if (vec_len (s2))
    s = format (s, "Interface statistics:%v", s2);
  vec_reset_length (s2);

  vec_foreach_index (i, ppif->inqs)
  {
    struct pp2_ppio_inq_statistics stat = { 0 };
    pp2_ppio_inq_get_statistics (ppif->ppio, 0, i, &stat, 0);

    foreach_ppio_inq_statistics_entry;

    if (vec_len (s2))
      s = format (s, "\n%UInput queue %u statistics:%v",
		  format_white_space, indent, i, s2);
    vec_reset_length (s2);
  }
  vec_foreach_index (i, ppif->outqs)
  {
    struct pp2_ppio_outq_statistics stat = { 0 };

    pp2_ppio_outq_get_statistics (ppif->ppio, i, &stat, 0);

    foreach_ppio_outq_statistics_entry;

    if (vec_len (s2))
      s = format (s, "\n%UOutput queue %u statistics:%v",
		  format_white_space, indent, i, s2);
    vec_reset_length (s2);
  }
#undef _
  vec_free (s2);
  return s;
}

#define foreach_pp2_rx_desc_field \
  _(0x00,  6,  0, l3_offset) \
  _(0x00, 12,  8, ip_hdlen) \
  _(0x00, 14, 13, ec) \
  _(0x00, 15, 15, es) \
  _(0x00, 19, 16, pool_id) \
  _(0x00, 21, 21, hwf_sync) \
  _(0x00, 22, 22, l4_chk_ok) \
  _(0x00, 23, 23, ip_frg) \
  _(0x00, 24, 24, ipv4_hdr_err) \
  _(0x00, 27, 25, l4_info) \
  _(0x00, 30, 28, l3_info) \
  _(0x00, 31, 31, buf_header) \
  _(0x04,  5,  0, lookup_id) \
  _(0x04,  8,  6, cpu_code) \
  _(0x04,  9,  9, pppoe) \
  _(0x04, 11, 10, l3_cast_info) \
  _(0x04, 13, 12, l2_cast_info) \
  _(0x04, 15, 14, vlan_info) \
  _(0x04, 31, 16, byte_count) \
  _(0x08, 11,  0, gem_port_id) \
  _(0x08, 13, 12, color) \
  _(0x08, 14, 14, gop_sop_u) \
  _(0x08, 15, 15, key_hash_enable) \
  _(0x08, 31, 16, l4chk) \
  _(0x0c, 31,  0, timestamp) \
  _(0x10, 31,  0, buf_phys_ptr_lo) \
  _(0x14,  7,  0, buf_phys_ptr_hi) \
  _(0x14, 31,  8, key_hash) \
  _(0x18, 31,  0, buf_virt_ptr_lo) \
  _(0x1c,  7,  0, buf_virt_ptr_hi) \
  _(0x1c, 14,  8, buf_qset_no) \
  _(0x1c, 15, 15, buf_type) \
  _(0x1c, 21, 16, mod_dscp) \
  _(0x1c, 24, 22, mod_pri) \
  _(0x1c, 25, 25, mdscp) \
  _(0x1c, 26, 26, mpri) \
  _(0x1c, 27, 27, mgpid) \
  _(0x1c, 31, 29, port_num)

u8 *
format_mrvl_pp2_input_trace (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  mrvl_pp2_input_trace_t *t = va_arg (*args, mrvl_pp2_input_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);
  struct pp2_ppio_desc *d = &t->desc;
  u32 r32;

  s = format (s, "pp2: %v (%d) next-node %U",
	      hi->name, t->hw_if_index, format_vlib_next_node_name, vm,
	      node->index, t->next_index);
  s = format (s, "\n%U", format_white_space, indent + 2);

#define _(a, b, c, n) \
  r32 = mrvl_get_u32_bits (d, a, b, c);				\
  if (r32 > 9)							\
    s = format (s, "%s %u (0x%x)", #n, r32, r32);		\
  else								\
    s = format (s, "%s %u", #n,r32);				\
  if (format_get_indent (s) > 72)				\
    s = format (s, "\n%U", format_white_space, indent + 2);	\
  else s = format (s, " ");

  foreach_pp2_rx_desc_field;
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
