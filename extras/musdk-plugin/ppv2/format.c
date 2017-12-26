/*
 *------------------------------------------------------------------
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
#include <ppv2/ppv2.h>

u8 *
format_ppv2_interface_name (u8 * s, va_list * args)
{
  ppv2_main_t *ppm = &ppv2_main;
  u32 dev_instance = va_arg (*args, u32);
  ppv2_if_t *ppif = pool_elt_at_index (ppm->interfaces, dev_instance);
  return format (s, "ppio%d/%d", ppif->ppio->pp2_id, ppif->ppio->port_id);
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
format_ppv2_interface (u8 * s, va_list * args)
{
  ppv2_main_t *ppm = &ppv2_main;
  u32 dev_instance = va_arg (*args, u32);
  u32 indent = format_get_indent (s);
  ppv2_if_t *ppif = pool_elt_at_index (ppm->interfaces, dev_instance);
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

u8 *
format_ppv2_input_trace (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  ppv2_input_trace_t *t = va_arg (*args, ppv2_input_trace_t *);
  u32 indent = format_get_indent (s);
  struct pp2_ppio_desc *d = &t->desc;

  s = format (s, "ppv2: hw_if_index %d next-node %U",
	      t->hw_if_index, format_vlib_next_node_name, vm, node->index,
	      t->next_index);
  s = format (s, "\n%Ul3-off %u iphdr-len %u ec %u es %u pool-id %u "
	      "hwf-sync %u l4-chk-ok %u l3-ip-frag %u"
	      "\n%Ul3-ip4-hdr-err %u, l4-prs-info %u l3-prs-info %u "
	      "buf-hdr %u vlan-info %u l2-cast-info %u l3-cast-info %u",
	      format_white_space, indent + 2,
	      DM_RXD_GET_L3_OFF (d),
	      DM_RXD_GET_IPHDR_LEN (d),
	      DM_RXD_GET_EC (d),
	      DM_RXD_GET_ES (d),
	      DM_RXD_GET_POOL_ID (d),
	      DM_RXD_GET_HWF_SYNC (d),
	      DM_RXD_GET_L4_CHK_OK (d),
	      DM_RXD_GET_L3_IP_FRAG (d),
	      format_white_space, indent + 2,
	      DM_RXD_GET_L3_IP4_HDR_ERR (d),
	      DM_RXD_GET_L4_PRS_INFO (d),
	      DM_RXD_GET_L3_PRS_INFO (d),
	      DM_RXD_GET_BUF_HDR (d),
	      DM_RXD_GET_VLAN_INFO (d),
	      DM_RXD_GET_L2_CAST_INFO (d), DM_RXD_GET_L3_CAST_INFO (d));
  s = format (s, "\n%Ucookie %x phys-addr %llx",
	      format_white_space, indent + 2,
	      pp2_ppio_inq_desc_get_cookie (d),
	      pp2_ppio_inq_desc_get_phys_addr (d));
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
