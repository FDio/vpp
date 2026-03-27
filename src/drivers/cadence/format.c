/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/bus/platform.h>

#include <cadence.h>

static u8 *
format_cdn_flag (u8 *s, va_list *args)
{
  char *name = va_arg (*args, char *);
  u32 v = va_arg (*args, u32);
  return format (s, "%s%c", name, v ? '+' : '-');
}

static u8 *
format_cdn_ip_type (u8 *s, va_list *args)
{
  u32 idnum = va_arg (*args, u32);

  if (idnum == CDN_MOD_ID_7021)
    return format (s, "7021");
  if (idnum == CDN_MOD_ID_7014)
    return format (s, "7014");

  return format (s, "unknown (idnum %u)", idnum);
}

u8 *
format_cdn_rx_desc (u8 *s, va_list *args)
{
  cdn_rx_desc_t *d = va_arg (*args, cdn_rx_desc_t *);

  return format (
    s,
    "addr 0x%08x addrh 0x%08x used%c wrap%c waddr 0x%x frm-len %u offset %u "
    "sof%c eof%c cfi%c vlan-pri %u pri-tag%c vlan-tag%c typeid-match%c "
    "sa4-match%c sa3-match%c sa2-match%c sa1-match%c ext-match%c "
    "uhash-match%c mhash-match%c broadcast%c",
    d->addr.as_u32, d->addrh, d->addr.used ? '+' : '-', d->addr.wrap ? '+' : '-', d->addr.waddr,
    d->ctrl.frm_len, d->ctrl.offset, d->ctrl.sof ? '+' : '-', d->ctrl.eof ? '+' : '-',
    d->ctrl.cfi ? '+' : '-', d->ctrl.vlan_pri, d->ctrl.pri_tag ? '+' : '-',
    d->ctrl.vlan_tag ? '+' : '-', d->ctrl.typeid_match ? '+' : '-', d->ctrl.sa4_match ? '+' : '-',
    d->ctrl.sa3_match ? '+' : '-', d->ctrl.sa2_match ? '+' : '-', d->ctrl.sa1_match ? '+' : '-',
    d->ctrl.ext_match ? '+' : '-', d->ctrl.uhash_match ? '+' : '-', d->ctrl.mhash_match ? '+' : '-',
    d->ctrl.broadcast ? '+' : '-');
}

u8 *
format_cdn_tx_desc (u8 *s, va_list *args)
{
  cdn_tx_desc_t *d = va_arg (*args, cdn_tx_desc_t *);

  return format (s,
		 "addr 0x%08x addrh 0x%08x frm-len %u last%c nocrc%c lso %u "
		 "tcp-seq-src%c buf-exhausted%c underrun%c error%c wrap%c used%c",
		 d->addr, d->addrh, d->ctrl.frm_len, d->ctrl.last ? '+' : '-',
		 d->ctrl.nocrc ? '+' : '-', d->ctrl.lso, d->ctrl.tcp_seq_src ? '+' : '-',
		 d->ctrl.buf_exhausted ? '+' : '-', d->ctrl.underrun ? '+' : '-',
		 d->ctrl.error ? '+' : '-', d->ctrl.wrap ? '+' : '-', d->ctrl.used ? '+' : '-');
}

u8 *
format_cdn_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  cdn_rx_trace_t *t = va_arg (*args, cdn_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s) + 2;

  s = format (s, "cadence: %v (%u) qid %u next-node %U buffer %u", hi->name, t->hw_if_index,
	      t->queue_id, format_vlib_next_node_name, vm, node->index, t->next_index,
	      t->buffer_index);
  s = format_newline (s, indent);
  s = format (s, "desc: %U", format_cdn_rx_desc, &t->desc);

  return s;
}

u8 *
format_cdn_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm __clib_unused = va_arg (*args, vlib_main_t *);
  vlib_node_t *node __clib_unused = va_arg (*args, vlib_node_t *);
  cdn_tx_trace_t *t = va_arg (*args, cdn_tx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s) + 2;

  s = format (s, "cadence: %v (%u) qid %u buffer %u", hi->name, t->hw_if_index, t->queue_id,
	      t->buffer_index);
  s = format_newline (s, indent);
  s = format (s, "desc: %U", format_cdn_tx_desc, &t->desc);

  return s;
}

u8 *
format_cdn_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_mid_t mid;
  cdn_dcfg1_t dcfg1;
  cdn_dcfg2_t dcfg2;
  cdn_dcfg5_t dcfg5;
  cdn_dcfg6_t dcfg6;
  cdn_dcfg10_t dcfg10;
  cdn_dcfg12_t dcfg12;
  u32 indent = format_get_indent (s);

  s = format (s, "Device-tree path: %v", dd->node->path);

  if (cd->regs == 0)
    {
      s = format_newline (s, indent);
      return format (s, "UIO registers: not mapped");
    }

  mid.as_u32 = cdn_readl (cd, CDN_MID);
  dcfg1.as_u32 = cdn_readl (cd, CDN_DCFG1);
  dcfg2.as_u32 = cdn_readl (cd, CDN_DCFG2);
  dcfg5.as_u32 = cdn_readl (cd, CDN_DCFG5);
  dcfg6.as_u32 = cdn_readl (cd, CDN_DCFG6);
  dcfg10.as_u32 = cdn_readl (cd, CDN_DCFG10);
  dcfg12.as_u32 = cdn_readl (cd, CDN_DCFG12);

  s = format_newline (s, indent);
  s = format (s, "MID:");
  s = format_newline (s, indent);
  s = format (s, "  device-type %U idnum %u rev %u", format_cdn_ip_type, mid.idnum, mid.idnum,
	      mid.rev);
  s = format_newline (s, indent);
  s = format (s, "DCFG1:");
  s = format_newline (s, indent);
  s = format (s, "  %U %U %U dbwdef %u", format_cdn_flag, "no-pcs", dcfg1.no_pcs, format_cdn_flag,
	      "pcs", dcfg1.no_pcs == 0, format_cdn_flag, "irq-clear-on-write", dcfg1.irqcor == 0,
	      dcfg1.dbwdef);
  s = format_newline (s, indent);
  s = format (s, "DCFG2:");
  s = format_newline (s, indent);
  s = format (s, "  %U %U %U rx-pbuf-addr %u", format_cdn_flag, "rx-pkt-buf", dcfg2.rx_pkt_buf,
	      format_cdn_flag, "tx-pkt-buf", dcfg2.tx_pkt_buf, format_cdn_flag, "fifo-mode",
	      dcfg2.rx_pkt_buf == 0 && dcfg2.tx_pkt_buf == 0, dcfg2.rx_pbuf_addr);
  s = format_newline (s, indent);
  s = format (s, "DCFG5:");
  s = format_newline (s, indent);
  s = format (s, "  %U %U", format_cdn_flag, "tsu", dcfg5.tsu, format_cdn_flag, "ptp", dcfg5.tsu);
  s = format_newline (s, indent);
  s = format (s, "DCFG6:");
  s = format_newline (s, indent);
  s = format (s, "  queue-mask 0x%x %U %U", dcfg6.queue_mask, format_cdn_flag, "daw64", dcfg6.daw64,
	      format_cdn_flag, "pbuf-lso", dcfg6.pbuf_lso);
  s = format_newline (s, indent);
  s = format (s, "DCFG10:");
  s = format_newline (s, indent);
  s = format (s, "  axi-pipe-bits: %u", dcfg10.axi_pipe_bits);
  s = format_newline (s, indent);
  s = format (s, "DCFG12:");
  s = format_newline (s, indent);
  s = format (s, "  %U", format_cdn_flag, "high-speed", dcfg12.high_speed);
  s = format_newline (s, indent);
  s = format (s, "Capabilities:");
  s = format_newline (s, indent);
  s = format (s, "  %U %U %U %U %U axi-pipe-bits %u", format_cdn_flag, "pcs", dcfg1.no_pcs == 0,
	      format_cdn_flag, "high-speed", dcfg12.high_speed, format_cdn_flag, "fifo-mode",
	      dcfg2.rx_pkt_buf == 0 && dcfg2.tx_pkt_buf == 0, format_cdn_flag, "ptp", dcfg5.tsu,
	      format_cdn_flag, "64-bit-dma", dcfg6.daw64, dcfg10.axi_pipe_bits);
  s = format (s, " ");
  s = format (s, "%U", format_cdn_flag, "lso", dcfg6.pbuf_lso);

  return s;
}
