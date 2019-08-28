/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019, LabN Consulting, L.L.C.
 * May 29 2019, Christian Hopps <chopps@labn.net>
 */

#include <stddef.h>
#include <vppinfra/types.h>
#include <vnet/vnet.h>
#include <vnet/ipsec/esp.h>
#include <iptfs/ipsec_iptfs.h>
#include <iptfs/iptfs_zpool.h>

static char *iptfs_mode_strings[] = {
#define _(sym, string) string,
  foreach_iptfs_mode_type
#undef _
};

u8 *
format_iptfs_data (u8 *s, va_list *args)
{
  u32 sa_index = va_arg (*args, u32);
  iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
  vlib_main_t *vm = vlib_get_main ();
  f64 nsperclock = 1e9 * vm->clib_time.seconds_per_clock;
  f64 msperclock = 1e3 * vm->clib_time.seconds_per_clock;

  if (satd->tfs_is_inbound)
    {
      u32 tval, last_time, actual, our_rtt, loss_rate;
      u32 actual_delay, xmit_delay;
      iptfs_rx_get_lastvals (satd, &tval, &last_time);
      iptfs_rx_get_delay_actual_for_show (satd, &actual_delay, &xmit_delay, &actual);
      iptfs_rx_get_loss_info (satd, &our_rtt, &loss_rate);

      s = format (s,
		  "INBOUND: nextseq %llu fragnext %llu frag_buffer 0x%x "
		  "lcl-rtt %u lcl-loss-rate %u remote-tval 0x%x "
		  "remote-last-time %u remote-rtt %u remote-loss-rate %u "
		  "cc-actual-delay %u cc-xmit-delay %u, cc-actual %u "
		  "decrypt-thread %u decap-thread %u",
		  satd->tfs_rx.nextseq, satd->tfs_rx.frag_nseq, satd->tfs_rx.frag_bi, our_rtt,
		  clib_host_to_net_u32 (satd->tfs_rx.cc_llrate_net), tval, last_time,
		  satd->tfs_rx.cc_rrtt, loss_rate, actual_delay, xmit_delay, actual,
		  satd->tfs_rx.decrypt_thread_index, satd->tfs_rx.decap_thread_index);
    }
  else
    {
      u64 pdelay = satd->tfs_tx.pdelay;
      f64 cur_pps = satd->tfs_encap.cc_x;
      f64 cur_max = cur_pps * satd->tfs_encap.tfs_payload_size;

      /* Get a copy of the data inside the lock */
      s = format (s,
		  "OUTBOUND: encap qsize %u/%u qlen %u/%u tx ring %u/%u lastdue %llu "
		  "cur pdelay %lluns (%0.3fms) cur pps: %.12f orig pps: %.12f ipsec "
		  "payload size: %u iptfs payload size: %u max payload rate: %.8fbps "
		  "orig max payload rate: %.8fbps inbound_sa %u zpool_target %u "
		  "encap-thread %u encap-zpool-thread %u output-thread %u "
		  "output-zpool-thread %u",
		  satd->tfs_encap.limit.size, satd->tfs_encap.limit.max_size,
		  iptfs_bufq_n_enq (&satd->tfs_encap.outq),
		  iptfs_bufq_capacity (&satd->tfs_encap.outq), SRING_NELT (&satd->tfs_tx.q),
		  SRING_QSIZE (&satd->tfs_tx.q), satd->tfs_tx.lastdue, (u64) (pdelay * nsperclock),
		  (f64) pdelay * msperclock, cur_pps, iptfs_conf_pps (satd->tfs_config),
		  satd->tfs_encap.tfs_ipsec_payload_size, ipsec_iptfs_get_payload_size (sa_index),
		  cur_max * 8, ipsec_iptfs_get_conf_payload_rate (sa_index) * (f64) 8,
		  satd->tfs_encap.cc_inb_sa_index, satd->tfs_encap.zpool->queue_size,
		  satd->tfs_encap.encap_thread_index, satd->tfs_encap.zpool_thread_index,
		  satd->tfs_encap.output_thread_index, satd->tfs_tx.zpool_thread_index);
    }
  return s;
}

static u8 *
_format_iptfs_config (u8 *s, const ipsec_iptfs_config_t *conf)
{
  const char *chaining;
  if (conf->tfs_encap_chaining && conf->tfs_decap_chaining)
    chaining = "iptfs-use-chaining ";
  else if (conf->tfs_encap_chaining)
    chaining = "iptfs-encap-chaining ";
  else if (conf->tfs_decap_chaining)
    chaining = "iptfs-decap-chaining ";
  else
    chaining = "";

  if (conf)
    {
      s = format (s,
		  "%s%s%s%siptfs-mode %s iptfs-max-delay-us %llu "
		  "iptfs-packet-size %u %s %llubps iptfs-reorder-window %u",
		  chaining, (conf->tfs_df ? "iptfs-dont-fragment " : ""),
		  (conf->tfs_no_pad_only ? "iptfs-no-pad-only " : ""),
		  (conf->tfs_no_pad_trace ? "iptfs-no-pad-trace " : ""),
		  iptfs_mode_strings[conf->tfs_mode_type], conf->tfs_max_delay, conf->tfs_mtu,
		  conf->tfs_ebyterate ? "iptfs-ethernet-bitrate" : "iptfs-bitrate",
		  conf->tfs_ebyterate ? conf->tfs_ebyterate * 8 : conf->tfs_byterate * 8,
		  conf->tfs_rewin);
      if (conf->tfs_inbound_sa_id != ~0)
	s = format (s, " iptfs-inbound-sa-id %u", conf->tfs_inbound_sa_id);
      if (conf->tfs_encap_thread_index)
	s = format (s, " iptfs-encap-worker %u", conf->tfs_encap_thread_index - 1);
      if (conf->tfs_output_thread_index)
	s = format (s, " iptfs-output-worker %u", conf->tfs_output_thread_index - 1);
      if (conf->tfs_decap_thread_index)
	s = format (s, " iptfs-decap-worker %u", conf->tfs_decap_thread_index - 1);
      if (conf->tfs_decrypt_thread_index)
	s = format (s, " iptfs-decrypt-worker %u", conf->tfs_decrypt_thread_index - 1);
      if (conf->tfs_encap_zpool_thread_index)
	s = format (s, " iptfs-encap-zpool-worker %u", conf->tfs_encap_zpool_thread_index - 1);
      if (conf->tfs_output_zpool_thread_index)
	s = format (s, " iptfs-output-zpool-worker %u", conf->tfs_output_zpool_thread_index - 1);
    }
  return s;
}

u8 *
format_iptfs_config (u8 *s, va_list *args)
{
  u32 sa_index = va_arg (*args, u32);
  if (iptfs_is_sa_index_valid (sa_index))
    {
      iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);
      return _format_iptfs_config (s, satd->tfs_config);
    }
  return format (s, "");
}

u8 *
format_iptfs_config_early (u8 *s, va_list *args)
{
  return _format_iptfs_config (s, va_arg (*args, ipsec_iptfs_config_t *));
}

/*
 * An unusual unformat function in that it allocates memory.
 */
uword
unformat_iptfs_config (unformat_input_t *input, va_list *args)
{
  u8 *result, **resultp = va_arg (*args, u8 **);
  ipsec_iptfs_config_t conf;
  bool gotone = 0;
  bool gotmode = 0;
  u32 uval;

  memcpy (&conf, &iptfs_default_config, sizeof (conf));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "iptfs-max-delay-us %llu", &conf.tfs_max_delay))
	gotone = 1;
      else if (unformat (input, "iptfs-ethernet-bitrate %U", unformat_base10, &conf.tfs_ebyterate))
	gotone = 1;
      else if (unformat (input, "iptfs-bitrate %U", unformat_base10, &conf.tfs_byterate))
	gotone = 1;
      // Deprecated argument name.
      else if (unformat (input, "iptfs-mtu %u", &uval))
	{
	  conf.tfs_mtu = uval;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-packet-size %u", &uval))
	{
	  conf.tfs_mtu = uval;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-inbound-sa-id %u", &uval))
	{
	  index_t sa_index = ipsec_sa_find_and_lock (uval);
	  if (sa_index == INDEX_INVALID)
	    {
	      clib_warning ("Unknown iptfs-inbound-sa-id: %u", uval);
	      return 0;
	    }
	  ipsec_sa_unlock (sa_index);
	  conf.tfs_inbound_sa_id = uval;
	}
      else if (unformat (input, "iptfs-reorder-window %u", &uval))
	{
	  if (uval > IPTFS_MAX_REORDER_WINDOW)
	    {
	      clib_warning ("Using maximum reorder window of %u instead of %u",
			    IPTFS_MAX_REORDER_WINDOW, uval);
	      uval = IPTFS_MAX_REORDER_WINDOW;
	    }
	  conf.tfs_rewin = uval;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-output-worker %u", &uval) ||
	       unformat (input, "iptfs-worker %u", &uval))
	{
	  if (uval >= vlib_num_workers ())
	    {
	      clib_warning ("Invalid worker, %u doesn't exist", uval);
	      return 0;
	    }
	  conf.tfs_output_thread_index = uval + 1;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-decap-worker %u", &uval))
	{
	  if (uval >= vlib_num_workers ())
	    {
	      clib_warning ("Invalid decap-worker, %u doesn't exist", uval);
	      return 0;
	    }
	  conf.tfs_decap_thread_index = uval + 1;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-decrypt-worker %u", &uval))
	{
	  if (uval >= vlib_num_workers ())
	    {
	      clib_warning ("Invalid decap-worker, %u doesn't exist", uval);
	      return 0;
	    }
	  conf.tfs_decrypt_thread_index = uval + 1;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-encap-worker %u", &uval))
	{
	  if (uval >= vlib_num_workers ())
	    {
	      clib_warning ("Invalid encap-worker, %u doesn't exist", uval);
	      return 0;
	    }
	  conf.tfs_encap_thread_index = uval + 1;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-output-zpool-worker %u", &uval) ||
	       unformat (input, "iptfs-zpool-worker %u", &uval))
	{
	  if (uval >= vlib_num_workers ())
	    {
	      clib_warning ("Invalid output-zpool-worker, %u doesn't exist", uval);
	      return 0;
	    }
	  conf.tfs_output_zpool_thread_index = uval + 1;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-encap-zpool-worker %u", &uval))
	{
	  if (uval >= vlib_num_workers ())
	    {
	      clib_warning ("Invalid encap-zpool-worker, %u doesn't exist", uval);
	      return 0;
	    }
	  conf.tfs_encap_zpool_thread_index = uval + 1;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-no-pad-only"))
	{
	  conf.tfs_no_pad_only = 1;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-dont-fragment"))
	{
	  conf.tfs_df = 1;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-use-chaining"))
	{
	  conf.tfs_decap_chaining = true;
	  conf.tfs_encap_chaining = true;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-encap-chaining"))
	{
	  conf.tfs_encap_chaining = true;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-decap-chaining"))
	{
	  conf.tfs_decap_chaining = true;
	  gotone = 1;
	}
      else if (unformat (input, "iptfs-no-pad-trace"))
	{
	  conf.tfs_no_pad_trace = true;
	  gotone = 1;
	}
#define _(n, s)                                                                                    \
  else if (unformat (input, "iptfs-mode " s))                                                      \
  {                                                                                                \
    if (gotmode)                                                                                   \
      {                                                                                            \
	clib_warning ("Specify only one mode type");                                               \
	return 0;                                                                                  \
      }                                                                                            \
    conf.tfs_mode_type = n;                                                                        \
    gotone = 1;                                                                                    \
    gotmode = 1;                                                                                   \
  }
      foreach_iptfs_mode_type
#undef _
	else
      {
	if (gotone)
	  clib_warning ("Invalid input to unformat_tfs_args");
	return 0;
      }
    }
  if (!gotone)
    {
      iptfs_debug ("%s: No IPTFS config", __FUNCTION__);
      return 0;
    }
  if (conf.tfs_byterate && conf.tfs_ebyterate)
    {
      clib_warning ("Specify only one of iptfs-bitrate or iptfs-ether-bitrate");
      return 0;
    }
  conf.tfs_ebyterate /= 8;
  conf.tfs_byterate /= 8;

  /* Encap only implies no pad only */
  if (conf.tfs_mode_type == IPTFS_MODE_TYPE_ENCAP_ONLY)
    conf.tfs_no_pad_only = 1;

  /* We need to allocate as void *, b/c that's how it'll be freed */
  /* gpz 241207: vppinfra vec code now disallows void*, so do as u8* */
  vec_add2 (*resultp, result, sizeof (conf));
  memcpy (result, &conf, sizeof (conf));

  iptfs_debug ("%s: config %U", __FUNCTION__, format_iptfs_config_early, result);
  return 1;
}

void
iptfs_header_trace_store (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b)
{
  ipsec_iptfs_basic_header_t *h = vlib_buffer_get_current (b);
  iptfs_header_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
  u16 hlen = sizeof (*h);
  u16 copylen;
  if (b->current_length >= 1 && (h->subtype == IPTFS_SUBTYPE_CC))
    hlen = sizeof (ipsec_iptfs_cc_header_t);
  if ((copylen = clib_min (b->current_length, hlen)) < hlen)
    clib_memset (t, 0, sizeof (*t));
  clib_memcpy_fast (&t->h, h, copylen);
}

/* packet trace format function */
u8 *
format_iptfs_header (u8 *s, va_list *args)
{
  ipsec_iptfs_header_t *h = va_arg (*args, ipsec_iptfs_header_t *);
  if (h->basic.subtype == IPTFS_SUBTYPE_CC)
    {
      u32 r, a, x;
      iptfs_cc_get_rtt_and_delays (&h->cc, &r, &a, &x);

      s = format (s,
		  "TFS CC Header: subtype: %x flags %x offset %u rtt %u actual-delay "
		  "%u xmit-delay %u timeval %u timeecho %u loss_rate %u",
		  h->cc.subtype, h->cc.flags, clib_net_to_host_u16 (h->cc.block_offset), r, a, x,
		  h->cc.tval, h->cc.techo, clib_net_to_host_u32 (h->cc.loss_rate));
    }
  else
    {
      s = format (s, "IPTFS Basic Header: subtype: %x resv %x offset %u", h->basic.subtype,
		  h->basic.resv, clib_net_to_host_u16 (h->basic.block_offset));
    }
  return s;
}

/* packet trace format function */
u8 *
format_iptfs_header_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  iptfs_header_trace_t *t = va_arg (*args, iptfs_header_trace_t *);
  return format (s, "%U", format_iptfs_header, &t->h);
}

/* packet trace format function */
u8 *
format_ip46_header (u8 *s, va_list *args)
{
  va_list *orig_args = args;
  u8 *ip = va_arg (*args, u8 *);
  if ((ip[0] & 0xF0) == 0x40)
    return format_ip4_header (s, orig_args);
  return format_ip6_header (s, orig_args);
}

static inline u8 *
get_data_p (vlib_main_t *vm, vlib_buffer_t **bp, u16 *piovlen, u16 offset)
{
  u16 len, plen = *piovlen;
  vlib_buffer_t *b = *bp;

  offset -= plen;
  while (offset >= (len = b->current_length))
    {
      offset -= len;
      *piovlen += len;
      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  *bp = NULL;
	  return NULL;
	}
      *bp = b = vlib_get_buffer (vm, b->next_buffer);
    }
  return vlib_buffer_get_current (b) + offset;
}

void
iptfs_encapped_packet_trace_store (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b0,
				   u32 gen, u16 ord, u16 last_ord, bool bad_header)
{
  ipsec_iptfs_basic_header_t *h = vlib_buffer_get_current (b0);
  iptfs_datablock_trace_t *cdb, *db = NULL;
  vlib_buffer_t *b = b0;
  bool bad_decode = false;
  bool header_straddle = false;

  /* This assumes that the IPTFS header is in the first buffer */
  u16 hlen = sizeof (*h);
  if (b->current_length >= 1 && (h->subtype == IPTFS_SUBTYPE_CC))
    hlen = sizeof (ipsec_iptfs_cc_header_t);

  /* Expect the IPTFS header in the first buffer */
  if (bad_header || b0->current_length < hlen)
    goto walk_done;

  u16 piovlen = 0;
  u16 offset = hlen + clib_net_to_host_unaligned_mem_u16 (&h->block_offset);
  u8 *data;

  while ((data = get_data_p (vm, &b, &piovlen, offset)))
    {
      vec_add2 (db, cdb, 1);
      cdb->type = *data & 0xF0;
      cdb->offset = offset;
      cdb->pktlen = 0;
      u8 lenoff, *len0, *len1;

      if (cdb->type == 0x40)
	lenoff = offsetof (ip4_header_t, length);
      else if (cdb->type == 0x60)
	lenoff = offsetof (ip6_header_t, payload_length);
      else
	{
	  if ((b->flags & VLIB_BUFFER_NEXT_PRESENT))
	    bad_decode = true;
	  cdb->pktlen = piovlen + b->current_length - offset;
	  break;
	}

      /* Can probably predict false the straddle case to optimize this */
      if ((len0 = get_data_p (vm, &b, &piovlen, offset + lenoff)))
	len1 = get_data_p (vm, &b, &piovlen, offset + lenoff + 1);
      if (!len0 || !len1)
	{
	  header_straddle = true;
	  break;
	}

      cdb->pktlen = ((u16) *len0 << 8) + *len1;
      if (cdb->type == 0x60)
	cdb->pktlen += sizeof (ip6_header_t);
      /* Check for corrupt pktlen which doesn't include the length bytes */
      if (cdb->pktlen < lenoff + 2)
	{
	  bad_decode = true;
	  break;
	}
      offset += cdb->pktlen;
    }
walk_done:;

  iptfs_packet_trace_t *t =
    vlib_add_trace (vm, node, b0, sizeof (*t) + sizeof (iptfs_datablock_trace_t) * vec_len (db));
  t->is_decap = false;
  t->bad_header = bad_header;
  t->bad_decode = bad_decode;
  t->header_straddle = header_straddle;
  t->output_gen = (u16) gen;
  t->output_ord = ord;
  t->output_last_ord = last_ord;
  t->ndb = vec_len (db);
  t->iptfs_len = vlib_buffer_length_in_chain (vm, b0);
  t->sad_index = vnet_buffer (b0)->ipsec.sad_index;

  /* Copy the header */
  u16 copylen;
  if ((copylen = clib_min (b0->current_length, hlen)) < hlen)
    clib_memset (t, 0, sizeof (*t));
  clib_memcpy_fast (&t->h, h, copylen);

  /* Copy the datablock info */
  if (t->ndb)
    clib_memcpy_fast (t->db, db, t->ndb * sizeof (*db));

  vec_free (db);
}

u8 *
format_iptfs_datablock_type (u8 *s, va_list *args)
{
  uint type = va_arg (*args, uint);

  if (type == 0x40)
    return format (s, "IPv4");
  else if (type == 0x60)
    return format (s, "IPv6");
  else if (type == 0x0)
    return format (s, "Pad ");
  else
    return format (s, "Unknown(%u)", type);
}

/* packet trace format function */
u8 *
format_iptfs_packet_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  iptfs_packet_trace_t *t = va_arg (*args, iptfs_packet_trace_t *);
  iptfs_datablock_trace_t *db, *edb;
  u32 indent = format_get_indent (s);

  if (t->is_decap)
    {
      s = format (s, "from iptfs-decap esp_seq %u block_number %u", t->esp_seq, t->block_number);
      return s;
    }

  s = format (s, "iptfs_len %u, sad_index %u\n", t->iptfs_len, t->sad_index);
  s = format (s, "%U%s%s%s%U:", format_white_space, indent, t->bad_header ? "[bad header] " : "",
	      t->bad_decode ? "[bad decode] " : "", t->header_straddle ? "[header straddle] " : "",
	      format_iptfs_header, &t->h);
  if (t->output_gen != (u16) ~0u)
    s = format (s, "[output gen: %u pkt %u of %u]:", t->output_gen, t->output_ord,
		t->output_last_ord + 1);

  indent += 2;
  db = t->db;
  edb = db + t->ndb;
  u16 i = 0;
  for (; db < edb; db++, i++)
    s = format (s, "\n%Udatablock %2u: type: %U offset: %4u pktlen: %4u", format_white_space,
		indent, i, format_iptfs_datablock_type, (uint) db->type, db->offset, db->pktlen);
  return s;
}
