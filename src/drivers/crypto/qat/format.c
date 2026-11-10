/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <qat.h>

static char *qat_svc_names[] = {
  [QAT_SVC_UNUSED] = "unused", [QAT_SVC_CRYPTO] = "crypto", [QAT_SVC_COMPRESSION] = "dc",
  [QAT_SVC_SYM] = "sym",       [QAT_SVC_ASYM] = "asym",
};

static char *qat_alg_type_names[] = {
  [QAT_ALG_TYPE_NONE] = "none",
  [QAT_ALG_TYPE_CIPHER] = "cipher",
  [QAT_ALG_TYPE_AEAD] = "aead",
  [QAT_ALG_TYPE_COMBINED] = "cipher-hash",
};

u8 *
format_qat_svc (u8 *s, va_list *args)
{
  u32 svc = va_arg (*args, u32);

  if (svc < ARRAY_LEN (qat_svc_names) && qat_svc_names[svc])
    return format (s, "%s", qat_svc_names[svc]);
  return format (s, "unknown(%u)", svc);
}

static char *qat_pf2vf_msgtype_names[] = {
#define _(v, n, str) [v] = str,
  foreach_qat_pf2vf_msgtype
#undef _
};

static char *qat_vf2pf_msgtype_names[] = {
#define _(v, n, str) [v] = str,
  foreach_qat_vf2pf_msgtype
#undef _
};

static char *qat_pf2vf_compat_names[] = {
#define _(v, n, str) [v] = str,
  foreach_qat_pf2vf_compat
#undef _
};

static char *qat_blkmsg_type_names[] = {
#define _(v, n, str) [v] = str,
  foreach_qat_blkmsg_type
#undef _
};

static u8 *
format_qat_name (u8 *s, char **names, u32 n_names, u32 v)
{
  if (v < n_names && names[v])
    return format (s, "%s", names[v]);
  return format (s, "unknown(0x%x)", v);
}

u8 *
format_qat_pf2vf_msgtype (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);
  return format_qat_name (s, qat_pf2vf_msgtype_names, ARRAY_LEN (qat_pf2vf_msgtype_names), v);
}

u8 *
format_qat_vf2pf_msgtype (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);
  return format_qat_name (s, qat_vf2pf_msgtype_names, ARRAY_LEN (qat_vf2pf_msgtype_names), v);
}

u8 *
format_qat_pf2vf_compat (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);
  return format_qat_name (s, qat_pf2vf_compat_names, ARRAY_LEN (qat_pf2vf_compat_names), v);
}

u8 *
format_qat_blkmsg_type (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);
  return format_qat_name (s, qat_blkmsg_type_names, ARRAY_LEN (qat_blkmsg_type_names), v);
}

u8 *
format_qat_ring_to_svc_map (u8 *s, va_list *args)
{
  qat_ring_to_svc_map_t map = { .as_u16 = va_arg (*args, u32) };
  u8 done = 0;

  for (u32 i = 0; i < QAT_GEN4_VF_N_BANKS; i++)
    {
      u8 svc = qat_ring_to_svc_map_get (map, i);
      char *sep = " ";

      if (done & (1 << i))
	continue;

      s = format (s, "%s%U", i ? " " : "", format_qat_svc, svc);
      for (u32 j = i; j < QAT_GEN4_VF_N_BANKS; j++)
	if (qat_ring_to_svc_map_get (map, j) == svc)
	  {
	    s = format (s, "%s%u", sep, j);
	    sep = ",";
	    done |= 1 << j;
	  }
    }
  return s;
}

static char *qat_capability_names[] = {
#define _(b, n, str) [b] = str,
  foreach_qat_capability
#undef _
};

u8 *
format_qat_capabilities (u8 *s, va_list *args)
{
  u32 caps = va_arg (*args, u32);
  char *sep = "";

  while (caps)
    {
      u32 b = count_trailing_zeros (caps);

      if (b < ARRAY_LEN (qat_capability_names) && qat_capability_names[b])
	s = format (s, "%s%s", sep, qat_capability_names[b]);
      else
	s = format (s, "%sbit%u", sep, b);
      sep = " ";
      caps = clear_lowest_set_bit (caps);
    }

  return s;
}

u8 *
format_qat_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qat_device_t *qd = vnet_dev_get_data (dev);
  qat_blkmsg_caps_t *caps = &qd->caps;
  vlib_main_t *vm = vlib_get_main ();
  u32 indent = format_get_indent (s);
  vlib_pci_config_hdr_t cfg = {};
  clib_error_t *err;

  s = format (s, "PF/VF protocol version %u", qd->pf_version);

  s = format_newline (s, indent);
  if (caps->len < QAT_BLKMSG_CAPS_V2_LEN)
    s = format (s, "capabilities: not provided by PF");
  else
    s = format (s, "capabilities: %U", format_qat_capabilities, caps->capabilities);

  if (caps->len >= QAT_BLKMSG_CAPS_V3_LEN)
    {
      s = format_newline (s, indent);
      s = format (s, "engine clock: %u MHz", caps->frequency / 1000000);
    }

  s = format_newline (s, indent);
  if (qd->gen == QAT_GEN2)
    {
      s = format (s, "symmetric crypto rings:");
      for (u32 i = 0; i < qd->n_sym_ring_pairs; i++)
	s = format (s, " %u/%u", qd->sym_ring_pairs[i].tx_ring, qd->sym_ring_pairs[i].rx_ring);
    }
  else
    s = format (s, "ring pairs: %U", format_qat_ring_to_svc_map, qd->ring_to_svc_map.as_u16);

  if (a->debug == 0)
    return s;

  s = format_newline (s, indent);
  err = vlib_pci_read_write_config (vm, vnet_dev_get_pci_handle (dev), VLIB_READ, 0, &cfg,
				    sizeof (cfg));
  if (err)
    {
      s = format (s, "PCI config read failed: %U", format_clib_error, err);
      clib_error_free (err);
    }
  else
    s = format (s, "PCI device %04x:%04x, command 0x%04x, status 0x%04x", cfg.vendor_id,
		cfg.device_id, cfg.command.as_u16, cfg.status.as_u16);
  if (qd->gen != QAT_GEN2)
    {
      s = format_newline (s, indent);
      s = format (s, "ring to service map 0x%04x", qd->ring_to_svc_map.as_u16);
    }
  s = format_newline (s, indent);
  s = format (s,
	      "capability summary: version %u length %u capabilities 0x%08x ext-dc 0x%08x "
	      "frequency %u",
	      caps->version, caps->len, caps->capabilities, caps->ext_dc_caps, caps->frequency);
  s = format_newline (s, indent);
  if (qd->gen == QAT_GEN2)
    return format (s, "mailbox: 0x%08x", qat_reg_read (qd->bar2, QAT_GEN2_VF_PFVF));
  return format (s, "mailbox: pf2vm 0x%08x vm2pf 0x%08x",
		 qat_reg_read (qd->bar2, QAT_GEN4_VF_PF2VM),
		 qat_reg_read (qd->bar2, QAT_GEN4_VF_VM2PF));
}

u8 *
format_qat_ring_csrs (u8 *s, va_list *args)
{
  qat_device_t *qd = va_arg (*args, qat_device_t *);
  u32 bank = va_arg (*args, u32);
  u32 ring = va_arg (*args, u32);
  qat_ring_config_t cfg = {
    .as_u32 = qat_reg_read (qd->bar0, qat_ring_cfg_reg (qd, bank, QAT_RING_CSR_CONFIG (ring))),
  };
  u64 base = qat_reg_read (qd->bar0, qat_ring_cfg_reg (qd, bank, QAT_RING_CSR_BASE_LO (ring))) |
	     (u64) qat_reg_read (qd->bar0, qat_ring_cfg_reg (qd, bank, QAT_RING_CSR_BASE_HI (ring)))
	       << 32;

  return format (s, "base 0x%lx size-code %u near-full %u near-empty %u head 0x%x tail 0x%x",
		 base << qd->cfg->ring_base_shift, cfg.ring_size, cfg.near_full_wm,
		 cfg.near_empty_wm,
		 qat_reg_read (qd->bar0, qat_bank_reg (qd, bank, QAT_RING_CSR_HEAD (ring))),
		 qat_reg_read (qd->bar0, qat_bank_reg (qd, bank, QAT_RING_CSR_TAIL (ring))));
}

/* called from the device process */
u8 *
format_qat_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_crypto_queue_t *cq = va_arg (*args, vnet_dev_crypto_queue_t *);
  qat_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  qat_device_t *qd = vnet_dev_get_data (cq->dev);
  qat_ring_pair_t *rp = &q->rp;
  u32 indent = format_get_indent (s);
  u32 tx_head =
    qat_reg_read (qd->bar0, qat_bank_reg (qd, rp->bank, QAT_RING_CSR_HEAD (rp->tx_ring)));
  u32 tx_tail =
    qat_reg_read (qd->bar0, qat_bank_reg (qd, rp->bank, QAT_RING_CSR_TAIL (rp->tx_ring)));
  u32 rx_head =
    qat_reg_read (qd->bar0, qat_bank_reg (qd, rp->bank, QAT_RING_CSR_HEAD (rp->rx_ring)));
  u32 rx_tail =
    qat_reg_read (qd->bar0, qat_bank_reg (qd, rp->bank, QAT_RING_CSR_TAIL (rp->rx_ring)));
  u32 tx_sz = cq->size * QAT_TX_MSG_SIZE, rx_sz = cq->size * QAT_RX_MSG_SIZE;

  if (qd->gen == QAT_GEN2)
    s = format (s, "rings %u/%u", rp->tx_ring, rp->rx_ring);
  else
    s = format (s, "ring pair %u", rp->bank);
  s = format (s, ", %u requests pending in hardware, %u responses not consumed",
	      ((tx_tail - tx_head) & (tx_sz - 1)) / QAT_TX_MSG_SIZE,
	      ((rx_tail - rx_head) & (rx_sz - 1)) / QAT_RX_MSG_SIZE);

  if (a->debug == 0)
    return s;

  s = format_newline (s, indent);
  s = format (s, "tx: %U", format_qat_ring_csrs, qd, rp->bank, rp->tx_ring);
  s = format_newline (s, indent);
  s = format (s, "rx: %U", format_qat_ring_csrs, qd, rp->bank, rp->rx_ring);
  s = format_newline (s, indent);
  return format (s, "arbiter enable 0x%x",
		 qat_reg_read (qd->bar0, qat_bank_reg (qd, rp->bank, QAT_RING_CSR_SRV_ARB_EN)));
}

u8 *
format_qat_ring_dump (u8 *s, va_list *args)
{
  vnet_dev_crypto_queue_t *cq = va_arg (*args, vnet_dev_crypto_queue_t *);
  u32 count = va_arg (*args, u32);
  qat_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  qat_device_t *qd = vnet_dev_get_data (cq->dev);
  vnet_dev_format_args_t fa = { .debug = 1 };
  u32 tx_tail, rx_head;

  tx_tail =
    qat_reg_read (qd->bar0, qat_bank_reg (qd, q->rp.bank, QAT_RING_CSR_TAIL (q->rp.tx_ring)));
  rx_head =
    qat_reg_read (qd->bar0, qat_bank_reg (qd, q->rp.bank, QAT_RING_CSR_HEAD (q->rp.rx_ring)));
  tx_tail /= QAT_TX_MSG_SIZE;
  rx_head /= QAT_RX_MSG_SIZE;
  count = clib_min (count, cq->size);

  s = format (s, "%U", format_qat_queue_info, &fa, cq);

  s = format (s, "\nlast %u requests before hardware tail:", count);
  for (u32 i = count; i > 0; i--)
    {
      u32 slot = (tx_tail - i) & q->mask;
      s = format (s, "\n  [%u] %U", slot, format_qat_fw_req, q->tx_ring + slot);
    }

  s = format (s, "\n%u responses from hardware head:", count);
  for (u32 i = 0; i < count; i++)
    {
      u32 slot = (rx_head + i) & q->mask;
      s = format (s, "\n  [%u] %U", slot, format_qat_fw_resp, q->rx_ring + slot);
    }

  return s;
}

u8 *
format_qat_fw_req (u8 *s, va_list *args)
{
  qat_fw_la_req_t *r = va_arg (*args, qat_fw_la_req_t *);
  qat_fw_cd_ctrl_t *cc = &r->cd_ctrl;
  qat_fw_la_flags_t f = r->hdr.la_flags;
  u32 indent = format_get_indent (s);

  s = format (s, "valid %u service %u cmd %u sgl %u flags 0x%04x", r->hdr.valid,
	      r->hdr.service_type, r->hdr.service_cmd_id, r->hdr.ptr_type_sgl, f.as_u16);
  s = format (s, " [%s%s%s%s%s slice %u]", f.ret_auth_res ? " ret-auth" : "",
	      f.cmp_auth_res ? " cmp-auth" : "", f.single_pass ? " single-pass" : "",
	      f.gcm_iv_len_12_octets ? " iv12" : "", f.ciph_iv_16byte_data ? " iv-inline" : "",
	      f.slice_type);
  s = format_newline (s, indent);
  s = format (s, "cd 0x%lx size %u, opaque 0x%lx", r->cd_pars.content_desc_addr,
	      r->cd_pars.content_desc_params_sz * 8, r->mid.opaque);
  s = format_newline (s, indent);
  s = format (s, "src 0x%lx len %u, dst 0x%lx len %u", r->mid.src_data_addr, r->mid.src_length,
	      r->mid.dst_data_addr, r->mid.dst_length);
  s = format_newline (s, indent);
  s = format (s, "cipher offset %u len %u iv %U", r->cipher_auth.cipher_offset,
	      r->cipher_auth.cipher_length, format_hex_bytes, r->cipher_auth.cipher_iv, 16);
  s = format_newline (s, indent);
  if (f.single_pass)
    s = format (s, "aad 0x%lx size %u, digest 0x%lx size %u", r->ucs.spc_aad_addr,
		r->ucs.spc_aad_sz, r->ucs.spc_auth_res_addr, r->ucs.spc_auth_res_sz);
  else
    s = format (s, "auth offset %u len %u, digest 0x%lx size %u", r->cipher_auth.auth_off,
		r->cipher_auth.auth_len, r->cipher_auth.auth_res_addr, r->cipher_auth.auth_res_sz);
  s = format_newline (s, indent);
  return format (s,
		 "cd ctrl: cipher cfg %u key %u state %u ids %u->%u, hash cfg %u ids %u->%u "
		 "state1 %u state2 %u@%u res %u final %u",
		 cc->cipher_cfg_offset, cc->cipher_key_sz, cc->cipher_state_sz, cc->cipher_curr_id,
		 cc->cipher_next_id, cc->hash_cfg_offset, cc->auth_curr_id, cc->auth_next_id,
		 cc->inner_state1_sz, cc->inner_state2_sz, cc->inner_state2_offset,
		 cc->inner_res_sz, cc->final_sz);
}

u8 *
format_qat_fw_resp (u8 *s, va_list *args)
{
  qat_fw_resp_t *r = va_arg (*args, qat_fw_resp_t *);

  if (*(u32 *) r == QAT_RING_EMPTY_SIG)
    return format (s, "empty");

  return format (s, "service %u type %u status 0x%02x%s%s%s cmd %u opaque 0x%lx", r->service_id,
		 r->response_type, r->status.as_u8, r->status.crypto_error ? " crypto-error" : "",
		 r->status.invalid_param ? " invalid-param" : "",
		 r->status.unsupported_request ? " unsupported" : "", r->cmd_id, r->opaque);
}

u8 *
format_qat_session (u8 *s, va_list *args)
{
  qat_key_t *k = va_arg (*args, qat_key_t *);
  vnet_crypto_alg_t alg = va_arg (*args, u32);
  const qat_alg_t *a = qat_algs + alg;
  u32 indent = format_get_indent (s);

  s = format (s, "alg %U type %s key %u iv %u digest %u aad %u", format_vnet_crypto_alg, alg,
	      qat_alg_type_names[a->type], a->key_len, a->iv_len, a->digest_len, a->aad_len);
  foreach_int (t, VNET_CRYPTO_OP_TYPE_ENCRYPT, VNET_CRYPTO_OP_TYPE_DECRYPT)
    {
      qat_fw_la_req_t r = k->tmpl->req[t], *req = &r;

      req->cd_pars.content_desc_addr = k->cd_dma + t * QAT_CD_SIZE;

      s = format_newline (s, indent);
      s = format (s, "%s template:", t == VNET_CRYPTO_OP_TYPE_ENCRYPT ? "encrypt" : "decrypt");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_qat_fw_req, req);
      s = format_newline (s, indent + 2);
      s = format (s, "content descriptor:");
      s = format_newline (s, indent + 4);
      s = format (s, "%U", format_hexdump, k->cd->cd[t], req->cd_pars.content_desc_params_sz * 8);
    }
  return s;
}
