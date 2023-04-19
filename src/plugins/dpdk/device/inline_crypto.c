/*
 * Copyright (c) 2023 Intel and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <dpdk/device/dpdk.h>
#include <vnet/ipsec/ipsec_tun.h>

always_inline dpdk_device_t *
dpdk_get_device (u32 sw_if_index)
{
  vnet_main_t * vm = vnet_get_main ();
  vnet_hw_interface_t * hw;

  if (sw_if_index == INDEX_INVALID)
    return NULL;
  hw = vnet_get_sup_hw_interface_api_visible_or_null (vm, sw_if_index);
  return hw ? vec_elt_at_index (dpdk_main.devices, hw->dev_instance) : NULL;
}

always_inline struct rte_flow *
dpdk_get_inline_crypto_flow (dpdk_inline_crypto_t * ic, u32 sa_index)
{
  if (sa_index == INDEX_INVALID)
    return NULL;
  vec_validate_init_empty(ic->sa_index_to_flow, sa_index, NULL);
  return ic->sa_index_to_flow[sa_index];
}

always_inline struct rte_security_session *
dpdk_get_inline_crypto_session (dpdk_inline_crypto_t * ic, u32 sa_index)
{
  if (sa_index == INDEX_INVALID)
    return NULL;
  vec_validate_init_empty(ic->sa_index_to_session, sa_index, NULL);
  return ic->sa_index_to_session[sa_index];
}

/* TODO: Support more algorithms */
static struct rte_crypto_sym_xform xform = {
  .type = RTE_CRYPTO_SYM_XFORM_AEAD,
  {
    .aead = {
      .algo = RTE_CRYPTO_AEAD_AES_GCM,
    }
  },
};

static struct rte_security_session_conf sess_conf_template = {
	.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_CRYPTO,
	.protocol = RTE_SECURITY_PROTOCOL_IPSEC,
	{.ipsec = {
		.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP,
                .mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL,
                .tunnel = {
                        .type = RTE_SECURITY_IPSEC_TUNNEL_IPV4,
                },
	}},
	.crypto_xform = &xform,
};

static int
dpdk_sa_index_to_security_session_conf (ipsec_tun_protect_t * itp,
                                        struct rte_security_session_conf * c,
                                        u32 sa_index, int is_ingress)
{
  ipsec_sa_t * sa = ipsec_sa_get (sa_index);

  if (ipsec_sa_is_set_IS_TUNNEL (sa) || ipsec_sa_is_set_IS_TUNNEL_V6 (sa) ||
      ipsec_sa_is_set_IS_ASYNC (sa))
    {
      dpdk_log_err ("SA %u has unsupported tunnel or async flags", sa_index);
      return -1;
    }

  if (!ipsec_sa_is_set_IS_INLINE (sa))
    {
      dpdk_log_err ("SA %u is not inline", sa_index);
      return -1;
    }

  if (sa->protocol != IPSEC_PROTOCOL_ESP)
    {
      dpdk_log_err ("SA %u is not ESP", sa_index);
      return -1;
    }

  /* TODO: Support more algorithms */
  if (sa->crypto_calg != VNET_CRYPTO_ALG_AES_128_GCM ||
      sa->crypto_alg != IPSEC_CRYPTO_ALG_AES_GCM_128 ||
      sa->crypto_iv_size != 8 || sa->integ_icv_size != 16)
    {
      dpdk_log_err ("SA %u is not AES 128 GCM", sa_index);
      return -1;
    }

  clib_memcpy (c, &sess_conf_template, sizeof(sess_conf_template));

  c->ipsec.salt = sa->salt;
  c->ipsec.spi = sa->spi;

  c->crypto_xform->aead.key.data = sa->crypto_key.data;
  c->crypto_xform->aead.key.length = sa->crypto_key.len;
  c->crypto_xform->aead.digest_length = sa->integ_icv_size;

  if (is_ingress)
    {
      c->ipsec.tunnel.ipv4.dst_ip.s_addr = itp->itp_crypto.src.ip4.data_u32;
      c->ipsec.direction = RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
    }
  else
    {
      c->ipsec.tunnel.ipv4.dst_ip.s_addr = itp->itp_crypto.dst.ip4.data_u32;
      c->ipsec.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
    }

  return 0;
}

static int
dpdk_ipsec_tun_protect_delete (dpdk_device_t * xd, ipsec_tun_protect_t * itp)
{
  dpdk_inline_crypto_t * ic = &xd->inline_crypto;
  struct rte_security_session * s;
  struct rte_flow * f;
  int rv;
  u32 i;

  for (i = 0; i < itp->itp_n_sa_in; i++)
    {
      f = dpdk_get_inline_crypto_flow (ic, itp->itp_in_sas[i]);
      if (f != NULL)
        {
          struct rte_flow_error err;

          rv = rte_flow_destroy (xd->port_id, f, &err);
          if (rv < 0)
            dpdk_log_err ("TODO: Handle error destroying in SA[%u] flow", i);
          ic->sa_index_to_flow[itp->itp_in_sas[i]] = NULL;
        }

      s = dpdk_get_inline_crypto_session (ic, itp->itp_in_sas[i]);
      if (s != NULL)
        {
          rv = rte_security_session_destroy (ic->security_ctx, s);
          if (rv)
            dpdk_log_err ("TODO: Handle error destroying in SA[%u]", i);
          ic->sa_index_to_session[itp->itp_in_sas[i]] = NULL;
        }
    }

  s = dpdk_get_inline_crypto_session (ic, itp->itp_out_sa);
  if (s != NULL)
    {
      rv = rte_security_session_destroy (ic->security_ctx, s);
      if (rv < 0)
        dpdk_log_err ("TODO: Handle error destroying out SA");
      ic->sa_index_to_session[itp->itp_out_sa] = NULL;
    }

  return 0;
}

static const struct rte_flow_item_ipv4 rte_flow_item_ipv4_dst_mask = {
  .hdr = {
    .dst_addr = RTE_BE32(0xffffffff),
  },
};

static int
dpdk_itp_update_flow (dpdk_device_t * xd, ipsec_tun_protect_t * itp, u32 i)
{
#define DPDK_INLINE_CRYPTO_MAX_RTE_FLOW_ACTIONS 2
  struct rte_flow_action action[DPDK_INLINE_CRYPTO_MAX_RTE_FLOW_ACTIONS];
#define DPDK_INLINE_CRYPTO_MAX_RTE_FLOW_PATTERN 4
  struct rte_flow_item pattern[DPDK_INLINE_CRYPTO_MAX_RTE_FLOW_PATTERN];
  dpdk_inline_crypto_t * ic = &xd->inline_crypto;
  struct rte_flow_item_ipv4 ipv4_spec;
  struct rte_flow_item_esp esp_spec;
  struct rte_flow_attr attr;
  struct rte_flow_error err;
  struct rte_flow * f;
  ipsec_sa_t * sa;

  f = dpdk_get_inline_crypto_flow (ic, itp->itp_in_sas[i]);
  if (f != NULL)
    {
      dpdk_log_err ("TODO: Overwrite existing in SA[%u] flow", i);
      return -1;
    }

  memset(action, 0, sizeof(action));
  memset(pattern, 0, sizeof(pattern));
  memset(&ipv4_spec, 0, sizeof(ipv4_spec));
  memset(&esp_spec, 0, sizeof(esp_spec));
  memset(&attr, 0, sizeof(attr));
  memset(&err, 0, sizeof(err));

  attr.ingress = 1;

  pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

  pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
  /* Received packets have the tunnel's source address as the destination */
  ipv4_spec.hdr.dst_addr = itp->itp_crypto.src.ip4.data_u32;
  pattern[1].spec = &ipv4_spec;
  pattern[1].mask = &rte_flow_item_ipv4_dst_mask;

  sa = ipsec_sa_get (itp->itp_in_sas[i]);
  pattern[2].type = RTE_FLOW_ITEM_TYPE_ESP;
  esp_spec.hdr.spi = rte_cpu_to_be_32(sa->spi);
  pattern[2].spec = &esp_spec;
  pattern[2].mask = &rte_flow_item_esp_mask;
  pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

  action[0].type = RTE_FLOW_ACTION_TYPE_SECURITY;
  action[0].conf = ic->sa_index_to_session[itp->itp_in_sas[i]];
  action[1].type = RTE_FLOW_ACTION_TYPE_END;

  if (rte_flow_validate(xd->port_id, &attr, pattern, action, &err) < 0)
    {
      dpdk_log_err ("Failed in SA[%u] flow validation: %s", i, err.message);
      return -1;
    }

  f = rte_flow_create(xd->port_id, &attr, pattern, action, &err);
  if (f == NULL)
    {
      dpdk_log_err ("Failed in SA[%u] flow creation: %s", i, err.message);
      return -1;
    }
  ic->sa_index_to_flow[itp->itp_in_sas[i]] = f;
  return 0;
}

static int
dpdk_itp_update_in_sa (dpdk_device_t * xd, ipsec_tun_protect_t * itp, u32 i)
{
  dpdk_inline_crypto_t * ic = &xd->inline_crypto;
  struct rte_security_session_conf sc;
  struct rte_security_session * s;

  s = dpdk_get_inline_crypto_session (ic, itp->itp_in_sas[i]);
  if (s != NULL)
    {
      dpdk_log_err ("TODO: Overwrite existing in SA[%u]", i);
      return -1;
    }

  if (itp->itp_in_sas[i] == INDEX_INVALID)
    {
      dpdk_log_debug ("No in SA[%u]", i);
      return 0;
    }

  if (dpdk_sa_index_to_security_session_conf(itp, &sc, itp->itp_in_sas[i], 1) < 0)
    {
      dpdk_log_err ("TODO: Handle error converting in SA[%u]", i);
      return -1;
    }

  s = rte_security_session_create (ic->security_ctx, &sc, ic->session_pool,
                                   ic->session_priv_pool);
  if (s == NULL)
    {
      dpdk_log_err ("TODO: Handle error creating in SA");
      return -1;
    }

  ic->sa_index_to_session[itp->itp_in_sas[i]] = s;

  if (dpdk_itp_update_flow (xd, itp, i) < 0)
    return -1;

  dpdk_log_info ("Created in SA[%u] on %U", i, format_dpdk_device_name,
                 xd->port_id);
  return 0;
}

static int
dpdk_itp_update_in_sas (dpdk_device_t * xd, ipsec_tun_protect_t * itp)
{
  u32 i;

  for (i = 0; i < itp->itp_n_sa_in; i++)
    if (dpdk_itp_update_in_sa (xd, itp, i) < 0)
      return -1;
  return 0;
}

static int
dpdk_itp_update_out_sa (dpdk_device_t * xd, ipsec_tun_protect_t * itp)
{
  dpdk_inline_crypto_t * ic = &xd->inline_crypto;
  struct rte_security_session_conf sc;
  struct rte_security_session * s;

  s = dpdk_get_inline_crypto_session (ic, itp->itp_out_sa);
  if (s != NULL)
    {
      dpdk_log_err ("TODO: Overwrite existing out SA");
      return -1;
    }

  if (itp->itp_out_sa == INDEX_INVALID)
    {
      dpdk_log_debug ("No out SA");
      return 0;
    }

  if (dpdk_sa_index_to_security_session_conf(itp, &sc, itp->itp_out_sa, 0) < 0)
    {
      dpdk_log_err ("TODO: Handle error converting out SA");
      return -1;
    }

  s = rte_security_session_create (ic->security_ctx, &sc, ic->session_pool,
                                   ic->session_priv_pool);
  if (s == NULL)
    {
      dpdk_log_err ("TODO: Handle error creating out SA");
      return -1;
    }

  ic->sa_index_to_session[itp->itp_out_sa] = s;
  dpdk_log_info ("Created out SA on %U", format_dpdk_device_name, xd->port_id);
  return 0;
}

static int
dpdk_ipsec_tun_protect_update (dpdk_device_t * xd, ipsec_tun_protect_t * itp)
{
  if (dpdk_itp_update_in_sas (xd, itp) < 0)
    goto err_del_sa_entries;

  if (dpdk_itp_update_out_sa (xd, itp) < 0)
    goto err_del_sa_entries;

  return 0;

err_del_sa_entries:
  if (dpdk_ipsec_tun_protect_delete (xd, itp) < 0)
    dpdk_log_err ("TODO: Handle error deleting SA entries");
  return -1;
}

int
dpdk_ipsec_tun_protect_callback (ipsec_tun_protect_t * itp, u8 is_add)
{
  dpdk_device_t * xd = dpdk_get_device (itp->itp_inl_sw_if_index);

  if (xd == NULL || xd->inline_crypto.security_ctx == NULL)
    {
      dpdk_log_info ("%U is not a DPDK device or it has no security context",
                     format_vnet_sw_if_index_name, vnet_get_main (),
                     itp->itp_inl_sw_if_index);
      return 0;
    }

  if (is_add)
    return dpdk_ipsec_tun_protect_update (xd, itp);
  else
    return dpdk_ipsec_tun_protect_delete (xd, itp);
}

int
dpdk_inline_crypto_device_setup (dpdk_device_t * xd)
{
  dpdk_inline_crypto_t *ic = &xd->inline_crypto;
  size_t session_size;
  int rv = -1;
  u8 *name;

  ic->security_ctx = rte_eth_dev_get_sec_ctx (xd->port_id);
  if (ic->security_ctx == NULL)
    return rv;

  session_size = rte_security_session_get_size (ic->security_ctx);

  name = format(0, "inl_crypto_sess_mp_%u", xd->port_id);
#define DPDK_INLINE_CRYPTO_MAX_SESSIONS 16384
  ic->session_pool = rte_cryptodev_sym_session_pool_create ((char *)name,
          DPDK_INLINE_CRYPTO_MAX_SESSIONS, session_size, 0, 0, xd->cpu_socket);
  if (!ic->session_pool)
    goto leave;

  name = format(0, "inl_crypto_sess_mp_pri_%u", xd->port_id);
  ic->session_priv_pool = rte_mempool_create ((char *)name,
          DPDK_INLINE_CRYPTO_MAX_SESSIONS, session_size, 0, 0,
          NULL, NULL, NULL, NULL, xd->cpu_socket, 0);
  if (ic->session_priv_pool == NULL)
    goto leave;

  rv = 0;
leave:
  vec_free (name);
  if (rv < 0)
    {
      dpdk_log_err ("Failed to setup inline crypto on %U",
                    format_dpdk_device_name, xd->port_id);
      ic->security_ctx = NULL;
    }
  else
    dpdk_log_info ("Setup inline crypto on %U", format_dpdk_device_name,
                   xd->port_id);
  return rv;
}

void
dpdk_inline_crypto_init (void)
{
  /* TODO: Fix bug in DPDK vpmd that fails to set SECURITY_OFFLOAD metadata */
  rte_vect_set_max_simd_bitwidth(RTE_VECT_SIMD_DISABLED);
  ipsec_tun_protect_register_callback (dpdk_ipsec_tun_protect_callback);
}
