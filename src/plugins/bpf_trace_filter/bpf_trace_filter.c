/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <bpf_trace_filter/bpf_trace_filter.h>

clib_error_t *
bpf_trace_filter_init (vlib_main_t *vm)
{
  bpf_trace_filter_main_t *btm = &bpf_trace_filter_main;
  btm->pcap = pcap_open_dead (DLT_EN10MB, 65535);
  btm->pcap_raw = pcap_open_dead (DLT_RAW, 65535);

  return 0;
}

int vnet_is_packet_traced (vlib_buffer_t *b, u32 classify_table_index,
			   int func);

u8 *
format_bpf_trace_filter (u8 *s, va_list *a)
{
  bpf_trace_filter_main_t *btm = va_arg (*a, bpf_trace_filter_main_t *);
  struct bpf_insn *insn;

  if (!btm->prog_set)
    return format (s, "bpf trace filter is not set");

  insn = btm->prog.bf_insns;
  for (int i = 0; i < btm->prog.bf_len; insn++, i++)
    s = format (s, "%s\n", bpf_image (insn, i));

  return s;
}

clib_error_t *
bpf_trace_filter_set_unset (const char *bpf_expr, u8 is_del, u8 optimize)
{
  bpf_trace_filter_main_t *btm = &bpf_trace_filter_main;
  if (is_del)
    {
      if (btm->prog_set)
	{
	  btm->prog_set = 0;
	  pcap_freecode (&btm->prog);
	}
      if (btm->prog_raw_set)
	{
	  btm->prog_raw_set = 0;
	  pcap_freecode (&btm->prog_raw);
	}
    }
  else if (bpf_expr)
    {
      if (btm->prog_set)
	pcap_freecode (&btm->prog);
      btm->prog_set = 0;
      if (pcap_compile (btm->pcap, &btm->prog, (char *) bpf_expr, optimize,
			PCAP_NETMASK_UNKNOWN))
	{
	  return clib_error_return (0, "Failed pcap_compile of %s", bpf_expr);
	}
      btm->prog_set = 1;

      /* Also compile for raw IP to support packets without Ethernet header */
      if (btm->prog_raw_set)
	pcap_freecode (&btm->prog_raw);
      btm->prog_raw_set = 0;
      if (pcap_compile (btm->pcap_raw, &btm->prog_raw, (char *) bpf_expr,
			optimize, PCAP_NETMASK_UNKNOWN) == 0)
	{
	  btm->prog_raw_set = 1;
	}
    }
  return 0;
};

static inline int
bpf_is_raw_ip_packet (vlib_buffer_t *b)
{
  /* Detect if packet starts with raw IP header (no Ethernet header).
   *
   * For IPv4: version=4, IHL (header length) is typically 5-15 (20-60 bytes)
   * For IPv6: version=6, next byte is traffic class (any value valid)
   * For Ethernet: first 6 bytes are dest MAC, next 6 are src MAC.
   *
   * If first byte is 0x45 (IPv4, IHL=5), second byte would be TOS/DSCP.
   * If first byte is 0x60 (IPv6), it's ambiguous with MAC starting 0x60. */
  u8 *data = vlib_buffer_get_current (b);
  u8 version = (data[0] >> 4);
  u8 ihl = (data[0] & 0x0F);

  if (version == 4 && ihl >= 5 && ihl <= 15)
    return 1;
  if (version == 6)
    {
      /* For IPv6, check that bytes 4-5 (payload length) are reasonable.
       * In Ethernet, these would be bytes 4-5 of dest MAC. */
      u16 payload_len = (data[4] << 8) | data[5];
      /* Payload should be <= 65535 (u16) and packet should be
       * at least as long as the header (40 bytes) + payload */
      if (b->current_length >= 40 &&
	  (payload_len == 0 || b->current_length >= 40 + payload_len))
	return 1;
    }
  return 0;
}

int
bpf_is_packet_traced (vlib_buffer_t *b, u32 classify_table_index, int func)
{
  bpf_trace_filter_main_t *bfm = &bpf_trace_filter_main;
  struct pcap_pkthdr phdr = { 0 };
  int res;
  int res1;

  if (classify_table_index != ~0 &&
      (res1 = vnet_is_packet_traced (b, classify_table_index, 0)) != 1)
    return res1;

  if (!bfm->prog_set)
    return 1;

  phdr.caplen = b->current_length;
  phdr.len = b->current_length;

  /* Check if packet starts with raw IP header (no Ethernet header) */
  if (bfm->prog_raw_set && bpf_is_raw_ip_packet (b))
    {
      res = pcap_offline_filter (&bfm->prog_raw, &phdr,
				 vlib_buffer_get_current (b));
    }
  else
    {
      res =
	pcap_offline_filter (&bfm->prog, &phdr, vlib_buffer_get_current (b));
    }
  return res != 0;
}

VLIB_REGISTER_TRACE_FILTER_FUNCTION (bpf_trace_filter_fn, static) = {
  .name = "bpf_trace_filter",
  .description = "bpf based trace filter",
  .priority = 10,
  .function = bpf_is_packet_traced
};

VLIB_INIT_FUNCTION (bpf_trace_filter_init);
bpf_trace_filter_main_t bpf_trace_filter_main;
