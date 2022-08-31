/*
 *------------------------------------------------------------------
 * ipsec_api.c - ipsec api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ipsec/ipsec_types_api.h>
#include <vnet/tunnel/tunnel_types_api.h>
#include <vnet/fib/fib.h>
#include <vnet/ipip/ipip.h>
#include <vnet/tunnel/tunnel_types_api.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/ipsec_itf.h>

#include <vnet/format_fns.h>
#include <vnet/ipsec/ipsec.api_enum.h>
#include <vnet/ipsec/ipsec.api_types.h>

#define REPLY_MSG_ID_BASE ipsec_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_ipsec_spd_add_del_t_handler (vl_api_ipsec_spd_add_del_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_spd_add_del_reply_t *rmp;
  int rv;

  rv = ipsec_add_del_spd (vm, ntohl (mp->spd_id), mp->is_add);

  REPLY_MACRO (VL_API_IPSEC_SPD_ADD_DEL_REPLY);
}

static void vl_api_ipsec_interface_add_del_spd_t_handler
  (vl_api_ipsec_interface_add_del_spd_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_interface_add_del_spd_reply_t *rmp;
  int rv;
  u32 sw_if_index __attribute__ ((unused));
  u32 spd_id __attribute__ ((unused));

  sw_if_index = ntohl (mp->sw_if_index);
  spd_id = ntohl (mp->spd_id);

  VALIDATE_SW_IF_INDEX (mp);

  rv = ipsec_set_interface_spd (vm, sw_if_index, spd_id, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY);
}

static void vl_api_ipsec_tunnel_protect_update_t_handler
  (vl_api_ipsec_tunnel_protect_update_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_tunnel_protect_update_reply_t *rmp;
  u32 sw_if_index, ii, *sa_ins = NULL;
  ip_address_t nh;
  int rv;

  sw_if_index = ntohl (mp->tunnel.sw_if_index);

  VALIDATE_SW_IF_INDEX (&(mp->tunnel));

  for (ii = 0; ii < mp->tunnel.n_sa_in; ii++)
    vec_add1 (sa_ins, ntohl (mp->tunnel.sa_in[ii]));

  ip_address_decode2 (&mp->tunnel.nh, &nh);

  rv = ipsec_tun_protect_update (sw_if_index, &nh,
				 ntohl (mp->tunnel.sa_out), sa_ins);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY);
}

static void vl_api_ipsec_tunnel_protect_del_t_handler
  (vl_api_ipsec_tunnel_protect_del_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_tunnel_protect_del_reply_t *rmp;
  ip_address_t nh;
  u32 sw_if_index;
  int rv;

  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  ip_address_decode2 (&mp->nh, &nh);
  rv = ipsec_tun_protect_del (sw_if_index, &nh);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY);
}

typedef struct ipsec_dump_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
  u32 sw_if_index;
} ipsec_dump_walk_ctx_t;

static walk_rc_t
send_ipsec_tunnel_protect_details (index_t itpi, void *arg)
{
  ipsec_dump_walk_ctx_t *ctx = arg;
  vl_api_ipsec_tunnel_protect_details_t *mp;
  ipsec_tun_protect_t *itp;
  u32 ii = 0;
  ipsec_sa_t *sa;

  itp = ipsec_tun_protect_get (itpi);

  mp = vl_msg_api_alloc (sizeof (*mp) + (sizeof (u32) * itp->itp_n_sa_in));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_TUNNEL_PROTECT_DETAILS);
  mp->context = ctx->context;

  mp->tun.sw_if_index = htonl (itp->itp_sw_if_index);
  ip_address_encode2 (itp->itp_key, &mp->tun.nh);

  sa = ipsec_sa_get (itp->itp_out_sa);
  mp->tun.sa_out = htonl (sa->id);
  mp->tun.n_sa_in = itp->itp_n_sa_in;
  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SA(itp, sa,
  ({
    mp->tun.sa_in[ii++] = htonl (sa->id);
  }));
  /* *INDENT-ON* */

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_ipsec_tunnel_protect_dump_t_handler (vl_api_ipsec_tunnel_protect_dump_t
					    * mp)
{
  vl_api_registration_t *reg;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ipsec_dump_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      ipsec_tun_protect_walk (send_ipsec_tunnel_protect_details, &ctx);
    }
  else
    {
      ipsec_tun_protect_walk_itf (sw_if_index,
				  send_ipsec_tunnel_protect_details, &ctx);
    }
}

static int
ipsec_spd_action_decode (vl_api_ipsec_spd_action_t in,
			 ipsec_policy_action_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
#define _(v,f,s) case IPSEC_API_SPD_ACTION_##f: \
      *out = IPSEC_POLICY_ACTION_##f;              \
      return (0);
      foreach_ipsec_policy_action
#undef _
    }
  return (VNET_API_ERROR_UNIMPLEMENTED);
}

static void vl_api_ipsec_spd_entry_add_del_t_handler
  (vl_api_ipsec_spd_entry_add_del_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_spd_entry_add_del_reply_t *rmp;
  ip46_type_t itype;
  u32 stat_index;
  int rv;

  stat_index = ~0;

  ipsec_policy_t p;

  clib_memset (&p, 0, sizeof (p));

  p.id = ntohl (mp->entry.spd_id);
  p.priority = ntohl (mp->entry.priority);

  itype = ip_address_decode (&mp->entry.remote_address_start, &p.raddr.start);
  ip_address_decode (&mp->entry.remote_address_stop, &p.raddr.stop);
  ip_address_decode (&mp->entry.local_address_start, &p.laddr.start);
  ip_address_decode (&mp->entry.local_address_stop, &p.laddr.stop);

  p.is_ipv6 = (itype == IP46_TYPE_IP6);

  p.protocol =
    mp->entry.protocol ? mp->entry.protocol : IPSEC_POLICY_PROTOCOL_ANY;
  p.rport.start = ntohs (mp->entry.remote_port_start);
  p.rport.stop = ntohs (mp->entry.remote_port_stop);
  p.lport.start = ntohs (mp->entry.local_port_start);
  p.lport.stop = ntohs (mp->entry.local_port_stop);

  rv = ipsec_spd_action_decode (mp->entry.policy, &p.policy);

  if (rv)
    goto out;

  /* policy action resolve unsupported */
  if (p.policy == IPSEC_POLICY_ACTION_RESOLVE)
    {
      clib_warning ("unsupported action: 'resolve'");
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }
  p.sa_id = ntohl (mp->entry.sa_id);
  rv =
    ipsec_policy_mk_type (mp->entry.is_outbound, p.is_ipv6, p.policy,
			  &p.type);
  if (rv)
    goto out;

  rv = ipsec_add_del_policy (vm, &p, mp->is_add, &stat_index);
  if (rv)
    goto out;

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY,
  ({
    rmp->stat_index = ntohl(stat_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_ipsec_spd_entry_add_del_v2_t_handler (
  vl_api_ipsec_spd_entry_add_del_v2_t *mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_spd_entry_add_del_reply_t *rmp;
  ip46_type_t itype;
  u32 stat_index;
  int rv;

  stat_index = ~0;

  ipsec_policy_t p;

  clib_memset (&p, 0, sizeof (p));

  p.id = ntohl (mp->entry.spd_id);
  p.priority = ntohl (mp->entry.priority);

  itype = ip_address_decode (&mp->entry.remote_address_start, &p.raddr.start);
  ip_address_decode (&mp->entry.remote_address_stop, &p.raddr.stop);
  ip_address_decode (&mp->entry.local_address_start, &p.laddr.start);
  ip_address_decode (&mp->entry.local_address_stop, &p.laddr.stop);

  p.is_ipv6 = (itype == IP46_TYPE_IP6);

  p.protocol = mp->entry.protocol;
  p.rport.start = ntohs (mp->entry.remote_port_start);
  p.rport.stop = ntohs (mp->entry.remote_port_stop);
  p.lport.start = ntohs (mp->entry.local_port_start);
  p.lport.stop = ntohs (mp->entry.local_port_stop);

  rv = ipsec_spd_action_decode (mp->entry.policy, &p.policy);

  if (rv)
    goto out;

  /* policy action resolve unsupported */
  if (p.policy == IPSEC_POLICY_ACTION_RESOLVE)
    {
      clib_warning ("unsupported action: 'resolve'");
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }
  p.sa_id = ntohl (mp->entry.sa_id);
  rv =
    ipsec_policy_mk_type (mp->entry.is_outbound, p.is_ipv6, p.policy, &p.type);
  if (rv)
    goto out;

  rv = ipsec_add_del_policy (vm, &p, mp->is_add, &stat_index);
  if (rv)
    goto out;

out:
  REPLY_MACRO2 (VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_REPLY,
		({ rmp->stat_index = ntohl (stat_index); }));
}

static void vl_api_ipsec_sad_entry_add_del_t_handler
  (vl_api_ipsec_sad_entry_add_del_t * mp)
{
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
  ipsec_key_t crypto_key, integ_key;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  ipsec_protocol_t proto;
  ipsec_sa_flags_t flags;
  u32 id, spi, sa_index = ~0;
  tunnel_t tun = {
    .t_flags = TUNNEL_FLAG_NONE,
    .t_encap_decap_flags = TUNNEL_ENCAP_DECAP_FLAG_NONE,
    .t_dscp = 0,
    .t_mode = TUNNEL_MODE_P2P,
    .t_table_id = 0,
    .t_hop_limit = 255,
  };
  int rv;

  id = ntohl (mp->entry.sad_id);
  if (!mp->is_add)
    {
      rv = ipsec_sa_unlock_id (id);
      goto out;
    }
  spi = ntohl (mp->entry.spi);

  rv = ipsec_proto_decode (mp->entry.protocol, &proto);

  if (rv)
    goto out;

  rv = ipsec_crypto_algo_decode (mp->entry.crypto_algorithm, &crypto_alg);

  if (rv)
    goto out;

  rv = ipsec_integ_algo_decode (mp->entry.integrity_algorithm, &integ_alg);

  if (rv)
    goto out;

  ipsec_key_decode (&mp->entry.crypto_key, &crypto_key);
  ipsec_key_decode (&mp->entry.integrity_key, &integ_key);

  flags = ipsec_sa_flags_decode (mp->entry.flags);

  ip_address_decode2 (&mp->entry.tunnel_src, &tun.t_src);
  ip_address_decode2 (&mp->entry.tunnel_dst, &tun.t_dst);

  rv = ipsec_sa_add_and_lock (id, spi, proto, crypto_alg, &crypto_key,
			      integ_alg, &integ_key, flags, mp->entry.salt,
			      htons (mp->entry.udp_src_port),
			      htons (mp->entry.udp_dst_port), &tun, &sa_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY,
  {
    rmp->stat_index = htonl (sa_index);
  });
  /* *INDENT-ON* */
}

static void vl_api_ipsec_sad_entry_add_del_v2_t_handler
  (vl_api_ipsec_sad_entry_add_del_v2_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_sad_entry_add_del_v2_reply_t *rmp;
  ipsec_key_t crypto_key, integ_key;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  ipsec_protocol_t proto;
  ipsec_sa_flags_t flags;
  u32 id, spi, sa_index = ~0;
  int rv;
  tunnel_t tun = {
    .t_flags = TUNNEL_FLAG_NONE,
    .t_encap_decap_flags = TUNNEL_ENCAP_DECAP_FLAG_NONE,
    .t_dscp = 0,
    .t_mode = TUNNEL_MODE_P2P,
    .t_table_id = htonl (mp->entry.tx_table_id),
    .t_hop_limit = 255,
  };

  id = ntohl (mp->entry.sad_id);
  if (!mp->is_add)
    {
      rv = ipsec_sa_unlock_id (id);
      goto out;
    }

  spi = ntohl (mp->entry.spi);

  rv = ipsec_proto_decode (mp->entry.protocol, &proto);

  if (rv)
    goto out;

  rv = ipsec_crypto_algo_decode (mp->entry.crypto_algorithm, &crypto_alg);

  if (rv)
    goto out;

  rv = ipsec_integ_algo_decode (mp->entry.integrity_algorithm, &integ_alg);

  if (rv)
    goto out;

  rv = tunnel_encap_decap_flags_decode (mp->entry.tunnel_flags,
					&tun.t_encap_decap_flags);

  if (rv)
    goto out;

  ipsec_key_decode (&mp->entry.crypto_key, &crypto_key);
  ipsec_key_decode (&mp->entry.integrity_key, &integ_key);

  flags = ipsec_sa_flags_decode (mp->entry.flags);
  tun.t_dscp = ip_dscp_decode (mp->entry.dscp);

  ip_address_decode2 (&mp->entry.tunnel_src, &tun.t_src);
  ip_address_decode2 (&mp->entry.tunnel_dst, &tun.t_dst);

    rv = ipsec_sa_add_and_lock (
      id, spi, proto, crypto_alg, &crypto_key, integ_alg, &integ_key, flags,
      mp->entry.salt, htons (mp->entry.udp_src_port),
      htons (mp->entry.udp_dst_port), &tun, &sa_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_REPLY,
  {
    rmp->stat_index = htonl (sa_index);
  });
  /* *INDENT-ON* */
}

static int
ipsec_sad_entry_add_v3 (const vl_api_ipsec_sad_entry_v3_t *entry,
			u32 *sa_index)
{
  ipsec_key_t crypto_key, integ_key;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  ipsec_protocol_t proto;
  ipsec_sa_flags_t flags;
  u32 id, spi;
  tunnel_t tun = { 0 };
  int rv;

  id = ntohl (entry->sad_id);
  spi = ntohl (entry->spi);

  rv = ipsec_proto_decode (entry->protocol, &proto);

  if (rv)
    return (rv);

  rv = ipsec_crypto_algo_decode (entry->crypto_algorithm, &crypto_alg);

  if (rv)
    return (rv);

  rv = ipsec_integ_algo_decode (entry->integrity_algorithm, &integ_alg);

  if (rv)
    return (rv);

  flags = ipsec_sa_flags_decode (entry->flags);

  if (flags & IPSEC_SA_FLAG_IS_TUNNEL)
    {
      rv = tunnel_decode (&entry->tunnel, &tun);

      if (rv)
	return (rv);
    }

  ipsec_key_decode (&entry->crypto_key, &crypto_key);
  ipsec_key_decode (&entry->integrity_key, &integ_key);

  return ipsec_sa_add_and_lock (id, spi, proto, crypto_alg, &crypto_key,
				integ_alg, &integ_key, flags, entry->salt,
				htons (entry->udp_src_port),
				htons (entry->udp_dst_port), &tun, sa_index);
}

static void
vl_api_ipsec_sad_entry_add_del_v3_t_handler (
  vl_api_ipsec_sad_entry_add_del_v3_t *mp)
{
  vl_api_ipsec_sad_entry_add_del_v3_reply_t *rmp;
  u32 id, sa_index = ~0;
  int rv;

  id = ntohl (mp->entry.sad_id);

  if (!mp->is_add)
    {
      rv = ipsec_sa_unlock_id (id);
    }
  else
    {
      rv = ipsec_sad_entry_add_v3 (&mp->entry, &sa_index);
    }

  REPLY_MACRO2 (VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY,
		{ rmp->stat_index = htonl (sa_index); });
}

static void
vl_api_ipsec_sad_entry_del_t_handler (vl_api_ipsec_sad_entry_del_t *mp)
{
  vl_api_ipsec_sad_entry_del_reply_t *rmp;
  int rv;

  rv = ipsec_sa_unlock_id (ntohl (mp->id));

  REPLY_MACRO (VL_API_IPSEC_SAD_ENTRY_DEL_REPLY);
}

static void
vl_api_ipsec_sad_entry_add_t_handler (vl_api_ipsec_sad_entry_add_t *mp)
{
  vl_api_ipsec_sad_entry_add_reply_t *rmp;
  u32 sa_index = ~0;
  int rv;

  rv = ipsec_sad_entry_add_v3 (&mp->entry, &sa_index);

  REPLY_MACRO2 (VL_API_IPSEC_SAD_ENTRY_ADD_REPLY,
		{ rmp->stat_index = htonl (sa_index); });
}

static void
vl_api_ipsec_sad_entry_update_t_handler (vl_api_ipsec_sad_entry_update_t *mp)
{
  vl_api_ipsec_sad_entry_update_reply_t *rmp;
  u32 id;
  tunnel_t tun = { 0 };
  int rv;

  id = ntohl (mp->sad_id);

  if (mp->is_tun)
    {
      rv = tunnel_decode (&mp->tunnel, &tun);

      if (rv)
	goto out;
    }

  rv = ipsec_sa_update (id, htons (mp->udp_src_port), htons (mp->udp_dst_port),
			&tun, mp->is_tun);

out:
  REPLY_MACRO (VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY);
}

static void
send_ipsec_spds_details (ipsec_spd_t * spd, vl_api_registration_t * reg,
			 u32 context)
{
  vl_api_ipsec_spds_details_t *mp;
  u32 n_policies = 0;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_SPDS_DETAILS);
  mp->context = context;

  mp->spd_id = htonl (spd->id);
#define _(s, n) n_policies += vec_len (spd->policies[IPSEC_SPD_POLICY_##s]);
  foreach_ipsec_spd_policy_type
#undef _
    mp->npolicies = htonl (n_policies);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_ipsec_spds_dump_t_handler (vl_api_ipsec_spds_dump_t * mp)
{
  vl_api_registration_t *reg;
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (spd, im->spds)  {
    send_ipsec_spds_details (spd, reg, mp->context);
  }
}

vl_api_ipsec_spd_action_t
ipsec_spd_action_encode (ipsec_policy_action_t in)
{
  vl_api_ipsec_spd_action_t out = IPSEC_API_SPD_ACTION_BYPASS;

  switch (in)
    {
#define _(v,f,s) case IPSEC_POLICY_ACTION_##f: \
      out = IPSEC_API_SPD_ACTION_##f;          \
      break;
      foreach_ipsec_policy_action
#undef _
    }
  return (clib_host_to_net_u32 (out));
}

static void
send_ipsec_spd_details (ipsec_policy_t * p, vl_api_registration_t * reg,
			u32 context)
{
  vl_api_ipsec_spd_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_SPD_DETAILS);
  mp->context = context;

  mp->entry.spd_id = htonl (p->id);
  mp->entry.priority = htonl (p->priority);
  mp->entry.is_outbound = ((p->type == IPSEC_SPD_POLICY_IP6_OUTBOUND) ||
			   (p->type == IPSEC_SPD_POLICY_IP4_OUTBOUND));

  ip_address_encode (&p->laddr.start, IP46_TYPE_ANY,
		     &mp->entry.local_address_start);
  ip_address_encode (&p->laddr.stop, IP46_TYPE_ANY,
		     &mp->entry.local_address_stop);
  ip_address_encode (&p->raddr.start, IP46_TYPE_ANY,
		     &mp->entry.remote_address_start);
  ip_address_encode (&p->raddr.stop, IP46_TYPE_ANY,
		     &mp->entry.remote_address_stop);
  mp->entry.local_port_start = htons (p->lport.start);
  mp->entry.local_port_stop = htons (p->lport.stop);
  mp->entry.remote_port_start = htons (p->rport.start);
  mp->entry.remote_port_stop = htons (p->rport.stop);
  mp->entry.protocol = p->protocol;
  mp->entry.policy = ipsec_spd_action_encode (p->policy);
  mp->entry.sa_id = htonl (p->sa_id);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_ipsec_spd_dump_t_handler (vl_api_ipsec_spd_dump_t * mp)
{
  vl_api_registration_t *reg;
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_policy_type_t ptype;
  ipsec_policy_t *policy;
  ipsec_spd_t *spd;
  uword *p;
  u32 spd_index, *ii;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  p = hash_get (im->spd_index_by_spd_id, ntohl (mp->spd_id));
  if (!p)
    return;

  spd_index = p[0];
  spd = pool_elt_at_index (im->spds, spd_index);

  FOR_EACH_IPSEC_SPD_POLICY_TYPE(ptype) {
    vec_foreach(ii, spd->policies[ptype])
      {
        policy = pool_elt_at_index(im->policies, *ii);

        if (mp->sa_id == ~(0) || ntohl (mp->sa_id) == policy->sa_id)
          send_ipsec_spd_details (policy, reg, mp->context);
      }
  }
}

static void
send_ipsec_spd_interface_details (vl_api_registration_t * reg, u32 spd_index,
				  u32 sw_if_index, u32 context)
{
  vl_api_ipsec_spd_interface_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_SPD_INTERFACE_DETAILS);
  mp->context = context;

  mp->spd_index = htonl (spd_index);
  mp->sw_if_index = htonl (sw_if_index);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_ipsec_spd_interface_dump_t_handler (vl_api_ipsec_spd_interface_dump_t *
					   mp)
{
  ipsec_main_t *im = &ipsec_main;
  vl_api_registration_t *reg;
  u32 k, v, spd_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->spd_index_valid)
    {
      spd_index = ntohl (mp->spd_index);
      /* *INDENT-OFF* */
      hash_foreach(k, v, im->spd_index_by_sw_if_index, ({
        if (v == spd_index)
          send_ipsec_spd_interface_details(reg, v, k, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      hash_foreach(k, v, im->spd_index_by_sw_if_index, ({
        send_ipsec_spd_interface_details(reg, v, k, mp->context);
      }));
    }
}

static void
vl_api_ipsec_itf_create_t_handler (vl_api_ipsec_itf_create_t * mp)
{
  vl_api_ipsec_itf_create_reply_t *rmp;
  tunnel_mode_t mode;
  u32 sw_if_index = ~0;
  int rv;

  rv = tunnel_mode_decode (mp->itf.mode, &mode);

  if (!rv)
    rv = ipsec_itf_create (ntohl (mp->itf.user_instance), mode, &sw_if_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IPSEC_ITF_CREATE_REPLY,
  ({
    rmp->sw_if_index = htonl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_ipsec_itf_delete_t_handler (vl_api_ipsec_itf_delete_t * mp)
{
  vl_api_ipsec_itf_delete_reply_t *rmp;
  int rv;

  rv = ipsec_itf_delete (ntohl (mp->sw_if_index));

  REPLY_MACRO (VL_API_IPSEC_ITF_DELETE_REPLY);
}

static walk_rc_t
send_ipsec_itf_details (ipsec_itf_t *itf, void *arg)
{
  ipsec_dump_walk_ctx_t *ctx = arg;
  vl_api_ipsec_itf_details_t *mp;

  if (~0 != ctx->sw_if_index && ctx->sw_if_index != itf->ii_sw_if_index)
    return (WALK_CONTINUE);

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_ITF_DETAILS);
  mp->context = ctx->context;

  mp->itf.mode = tunnel_mode_encode (itf->ii_mode);
  mp->itf.user_instance = htonl (itf->ii_user_instance);
  mp->itf.sw_if_index = htonl (itf->ii_sw_if_index);
  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_ipsec_itf_dump_t_handler (vl_api_ipsec_itf_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ipsec_dump_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
    .sw_if_index = ntohl (mp->sw_if_index),
  };

  ipsec_itf_walk (send_ipsec_itf_details, &ctx);
}

typedef struct ipsec_sa_dump_match_ctx_t_
{
  index_t sai;
  u32 sw_if_index;
} ipsec_sa_dump_match_ctx_t;

static walk_rc_t
ipsec_sa_dump_match_sa (index_t itpi, void *arg)
{
  ipsec_sa_dump_match_ctx_t *ctx = arg;
  ipsec_tun_protect_t *itp;
  index_t sai;

  itp = ipsec_tun_protect_get (itpi);

  if (itp->itp_out_sa == ctx->sai)
    {
      ctx->sw_if_index = itp->itp_sw_if_index;
      return (WALK_STOP);
    }

  FOR_EACH_IPSEC_PROTECT_INPUT_SAI (itp, sai,
  ({
    if (sai == ctx->sai)
      {
        ctx->sw_if_index = itp->itp_sw_if_index;
        return (WALK_STOP);
      }
  }));

  return (WALK_CONTINUE);
}

static walk_rc_t
send_ipsec_sa_details (ipsec_sa_t * sa, void *arg)
{
  ipsec_dump_walk_ctx_t *ctx = arg;
  vl_api_ipsec_sa_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_SA_DETAILS);
  mp->context = ctx->context;

  mp->entry.sad_id = htonl (sa->id);
  mp->entry.spi = htonl (sa->spi);
  mp->entry.protocol = ipsec_proto_encode (sa->protocol);
  mp->entry.tx_table_id = htonl (sa->tunnel.t_table_id);

  mp->entry.crypto_algorithm = ipsec_crypto_algo_encode (sa->crypto_alg);
  ipsec_key_encode (&sa->crypto_key, &mp->entry.crypto_key);

  mp->entry.integrity_algorithm = ipsec_integ_algo_encode (sa->integ_alg);
  ipsec_key_encode (&sa->integ_key, &mp->entry.integrity_key);

  mp->entry.flags = ipsec_sad_flags_encode (sa);
  mp->entry.salt = clib_host_to_net_u32 (sa->salt);

  if (ipsec_sa_is_set_IS_PROTECT (sa))
    {
      ipsec_sa_dump_match_ctx_t ctx = {
	.sai = sa - ipsec_sa_pool,
	.sw_if_index = ~0,
      };
      ipsec_tun_protect_walk (ipsec_sa_dump_match_sa, &ctx);

      mp->sw_if_index = htonl (ctx.sw_if_index);
    }
  else
    mp->sw_if_index = ~0;

  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      ip_address_encode2 (&sa->tunnel.t_src, &mp->entry.tunnel_src);
      ip_address_encode2 (&sa->tunnel.t_dst, &mp->entry.tunnel_dst);
    }
  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      mp->entry.udp_src_port = sa->udp_hdr.src_port;
      mp->entry.udp_dst_port = sa->udp_hdr.dst_port;
    }

  mp->seq_outbound = clib_host_to_net_u64 (((u64) sa->seq));
  mp->last_seq_inbound = clib_host_to_net_u64 (((u64) sa->seq));
  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      mp->seq_outbound |= (u64) (clib_host_to_net_u32 (sa->seq_hi));
      mp->last_seq_inbound |= (u64) (clib_host_to_net_u32 (sa->seq_hi));
    }
  if (ipsec_sa_is_set_USE_ANTI_REPLAY (sa))
    mp->replay_window = clib_host_to_net_u64 (sa->replay_window);

  mp->stat_index = clib_host_to_net_u32 (sa->stat_index);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_ipsec_sa_dump_t_handler (vl_api_ipsec_sa_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ipsec_dump_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  ipsec_sa_walk (send_ipsec_sa_details, &ctx);
}

static walk_rc_t
send_ipsec_sa_v2_details (ipsec_sa_t * sa, void *arg)
{
  ipsec_dump_walk_ctx_t *ctx = arg;
  vl_api_ipsec_sa_v2_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_SA_V2_DETAILS);
  mp->context = ctx->context;

  mp->entry.sad_id = htonl (sa->id);
  mp->entry.spi = htonl (sa->spi);
  mp->entry.protocol = ipsec_proto_encode (sa->protocol);
  mp->entry.tx_table_id = htonl (sa->tunnel.t_table_id);

  mp->entry.crypto_algorithm = ipsec_crypto_algo_encode (sa->crypto_alg);
  ipsec_key_encode (&sa->crypto_key, &mp->entry.crypto_key);

  mp->entry.integrity_algorithm = ipsec_integ_algo_encode (sa->integ_alg);
  ipsec_key_encode (&sa->integ_key, &mp->entry.integrity_key);

  mp->entry.flags = ipsec_sad_flags_encode (sa);
  mp->entry.salt = clib_host_to_net_u32 (sa->salt);

  if (ipsec_sa_is_set_IS_PROTECT (sa))
    {
      ipsec_sa_dump_match_ctx_t ctx = {
	.sai = sa - ipsec_sa_pool,
	.sw_if_index = ~0,
      };
      ipsec_tun_protect_walk (ipsec_sa_dump_match_sa, &ctx);

      mp->sw_if_index = htonl (ctx.sw_if_index);
    }
  else
    mp->sw_if_index = ~0;

  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      ip_address_encode2 (&sa->tunnel.t_src, &mp->entry.tunnel_src);
      ip_address_encode2 (&sa->tunnel.t_dst, &mp->entry.tunnel_dst);
    }
  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      mp->entry.udp_src_port = sa->udp_hdr.src_port;
      mp->entry.udp_dst_port = sa->udp_hdr.dst_port;
    }

  mp->entry.tunnel_flags =
    tunnel_encap_decap_flags_encode (sa->tunnel.t_encap_decap_flags);
  mp->entry.dscp = ip_dscp_encode (sa->tunnel.t_dscp);

  mp->seq_outbound = clib_host_to_net_u64 (((u64) sa->seq));
  mp->last_seq_inbound = clib_host_to_net_u64 (((u64) sa->seq));
  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      mp->seq_outbound |= (u64) (clib_host_to_net_u32 (sa->seq_hi));
      mp->last_seq_inbound |= (u64) (clib_host_to_net_u32 (sa->seq_hi));
    }
  if (ipsec_sa_is_set_USE_ANTI_REPLAY (sa))
    mp->replay_window = clib_host_to_net_u64 (sa->replay_window);

  mp->stat_index = clib_host_to_net_u32 (sa->stat_index);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_ipsec_sa_v2_dump_t_handler (vl_api_ipsec_sa_v2_dump_t *mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ipsec_dump_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  ipsec_sa_walk (send_ipsec_sa_v2_details, &ctx);
}

static walk_rc_t
send_ipsec_sa_v3_details (ipsec_sa_t *sa, void *arg)
{
  ipsec_dump_walk_ctx_t *ctx = arg;
  vl_api_ipsec_sa_v3_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_SA_V3_DETAILS);
  mp->context = ctx->context;

  mp->entry.sad_id = htonl (sa->id);
  mp->entry.spi = htonl (sa->spi);
  mp->entry.protocol = ipsec_proto_encode (sa->protocol);

  mp->entry.crypto_algorithm = ipsec_crypto_algo_encode (sa->crypto_alg);
  ipsec_key_encode (&sa->crypto_key, &mp->entry.crypto_key);

  mp->entry.integrity_algorithm = ipsec_integ_algo_encode (sa->integ_alg);
  ipsec_key_encode (&sa->integ_key, &mp->entry.integrity_key);

  mp->entry.flags = ipsec_sad_flags_encode (sa);
  mp->entry.salt = clib_host_to_net_u32 (sa->salt);

  if (ipsec_sa_is_set_IS_PROTECT (sa))
    {
      ipsec_sa_dump_match_ctx_t ctx = {
	.sai = sa - ipsec_sa_pool,
	.sw_if_index = ~0,
      };
      ipsec_tun_protect_walk (ipsec_sa_dump_match_sa, &ctx);

      mp->sw_if_index = htonl (ctx.sw_if_index);
    }
  else
    mp->sw_if_index = ~0;

  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    tunnel_encode (&sa->tunnel, &mp->entry.tunnel);

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      mp->entry.udp_src_port = sa->udp_hdr.src_port;
      mp->entry.udp_dst_port = sa->udp_hdr.dst_port;
    }

  mp->seq_outbound = clib_host_to_net_u64 (((u64) sa->seq));
  mp->last_seq_inbound = clib_host_to_net_u64 (((u64) sa->seq));
  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      mp->seq_outbound |= (u64) (clib_host_to_net_u32 (sa->seq_hi));
      mp->last_seq_inbound |= (u64) (clib_host_to_net_u32 (sa->seq_hi));
    }
  if (ipsec_sa_is_set_USE_ANTI_REPLAY (sa))
    mp->replay_window = clib_host_to_net_u64 (sa->replay_window);

  mp->stat_index = clib_host_to_net_u32 (sa->stat_index);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_ipsec_sa_v3_dump_t_handler (vl_api_ipsec_sa_v3_dump_t *mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ipsec_dump_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  ipsec_sa_walk (send_ipsec_sa_v3_details, &ctx);
}

static void
vl_api_ipsec_backend_dump_t_handler (vl_api_ipsec_backend_dump_t * mp)
{
  vl_api_registration_t *rp;
  ipsec_main_t *im = &ipsec_main;
  u32 context = mp->context;

  rp = vl_api_client_index_to_registration (mp->client_index);

  if (rp == 0)
    {
      clib_warning ("Client %d AWOL", mp->client_index);
      return;
    }

  ipsec_ah_backend_t *ab;
  ipsec_esp_backend_t *eb;
  /* *INDENT-OFF* */
  pool_foreach (ab, im->ah_backends) {
    vl_api_ipsec_backend_details_t *mp = vl_msg_api_alloc (sizeof (*mp));
    clib_memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_BACKEND_DETAILS);
    mp->context = context;
    snprintf ((char *)mp->name, sizeof (mp->name), "%.*s", vec_len (ab->name),
              ab->name);
    mp->protocol = ntohl (IPSEC_API_PROTO_AH);
    mp->index = ab - im->ah_backends;
    mp->active = mp->index == im->ah_current_backend ? 1 : 0;
    vl_api_send_msg (rp, (u8 *)mp);
  }
  pool_foreach (eb, im->esp_backends) {
    vl_api_ipsec_backend_details_t *mp = vl_msg_api_alloc (sizeof (*mp));
    clib_memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_IPSEC_BACKEND_DETAILS);
    mp->context = context;
    snprintf ((char *)mp->name, sizeof (mp->name), "%.*s", vec_len (eb->name),
              eb->name);
    mp->protocol = ntohl (IPSEC_API_PROTO_ESP);
    mp->index = eb - im->esp_backends;
    mp->active = mp->index == im->esp_current_backend ? 1 : 0;
    vl_api_send_msg (rp, (u8 *)mp);
  }
  /* *INDENT-ON* */
}

static void
vl_api_ipsec_select_backend_t_handler (vl_api_ipsec_select_backend_t * mp)
{
  ipsec_main_t *im = &ipsec_main;
  vl_api_ipsec_select_backend_reply_t *rmp;
  ipsec_protocol_t protocol;
  int rv = 0;
  if (pool_elts (ipsec_sa_pool) > 0)
    {
      rv = VNET_API_ERROR_INSTANCE_IN_USE;
      goto done;
    }

  rv = ipsec_proto_decode (mp->protocol, &protocol);

  if (rv)
    goto done;

  switch (protocol)
    {
    case IPSEC_PROTOCOL_ESP:
      rv = ipsec_select_esp_backend (im, mp->index);
      break;
    case IPSEC_PROTOCOL_AH:
      rv = ipsec_select_ah_backend (im, mp->index);
      break;
    default:
      rv = VNET_API_ERROR_INVALID_PROTOCOL;
      break;
    }
done:
  REPLY_MACRO (VL_API_IPSEC_SELECT_BACKEND_REPLY);
}

static void
vl_api_ipsec_set_async_mode_t_handler (vl_api_ipsec_set_async_mode_t * mp)
{
  vl_api_ipsec_set_async_mode_reply_t *rmp;
  int rv = 0;

  ipsec_set_async_mode (mp->async_enable);

  REPLY_MACRO (VL_API_IPSEC_SET_ASYNC_MODE_REPLY);
}

#include <vnet/ipsec/ipsec.api.c>
static clib_error_t *
ipsec_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (ipsec_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
