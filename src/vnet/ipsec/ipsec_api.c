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
#include <vnet/fib/fib.h>

#include <vnet/vnet_msg_enum.h>

#if WITH_LIBSSL > 0
#include <vnet/ipsec/ipsec.h>
#endif /* IPSEC */

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                                     \
_(IPSEC_SPD_ADD_DEL, ipsec_spd_add_del)                         \
_(IPSEC_INTERFACE_ADD_DEL_SPD, ipsec_interface_add_del_spd)     \
_(IPSEC_SPD_ENTRY_ADD_DEL, ipsec_spd_entry_add_del)             \
_(IPSEC_SAD_ENTRY_ADD_DEL, ipsec_sad_entry_add_del)             \
_(IPSEC_SA_SET_KEY, ipsec_sa_set_key)                           \
_(IPSEC_SA_DUMP, ipsec_sa_dump)                                 \
_(IPSEC_SPDS_DUMP, ipsec_spds_dump)                             \
_(IPSEC_SPD_DUMP, ipsec_spd_dump)                               \
_(IPSEC_SPD_INTERFACE_DUMP, ipsec_spd_interface_dump)		\
_(IPSEC_TUNNEL_IF_ADD_DEL, ipsec_tunnel_if_add_del)             \
_(IPSEC_TUNNEL_IF_SET_KEY, ipsec_tunnel_if_set_key)             \
_(IPSEC_TUNNEL_IF_SET_SA, ipsec_tunnel_if_set_sa)               \
_(IPSEC_SELECT_BACKEND, ipsec_select_backend)                   \
_(IPSEC_BACKEND_DUMP, ipsec_backend_dump)

static void
vl_api_ipsec_spd_add_del_t_handler (vl_api_ipsec_spd_add_del_t * mp)
{
#if WITH_LIBSSL == 0
  clib_warning ("unimplemented");
#else

  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_spd_add_del_reply_t *rmp;
  int rv;

  rv = ipsec_add_del_spd (vm, ntohl (mp->spd_id), mp->is_add);

  REPLY_MACRO (VL_API_IPSEC_SPD_ADD_DEL_REPLY);
#endif
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

#if WITH_LIBSSL > 0
  rv = ipsec_set_interface_spd (vm, sw_if_index, spd_id, mp->is_add);
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY);
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

#if WITH_LIBSSL > 0
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
  /* leave the ports in network order */
  p.rport.start = mp->entry.remote_port_start;
  p.rport.stop = mp->entry.remote_port_stop;
  p.lport.start = mp->entry.local_port_start;
  p.lport.stop = mp->entry.local_port_stop;

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

#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
  goto out;
#endif

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY,
  ({
    rmp->stat_index = ntohl(stat_index);
  }));
  /* *INDENT-ON* */
}

static int
ipsec_proto_decode (vl_api_ipsec_proto_t in, ipsec_protocol_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
    case IPSEC_API_PROTO_ESP:
      *out = IPSEC_PROTOCOL_ESP;
      return (0);
    case IPSEC_API_PROTO_AH:
      *out = IPSEC_PROTOCOL_AH;
      return (0);
    }
  return (VNET_API_ERROR_INVALID_PROTOCOL);
}

static vl_api_ipsec_proto_t
ipsec_proto_encode (ipsec_protocol_t p)
{
  switch (p)
    {
    case IPSEC_PROTOCOL_ESP:
      return clib_host_to_net_u32 (IPSEC_API_PROTO_ESP);
    case IPSEC_PROTOCOL_AH:
      return clib_host_to_net_u32 (IPSEC_API_PROTO_AH);
    }
  return (VNET_API_ERROR_UNIMPLEMENTED);
}

static int
ipsec_crypto_algo_decode (vl_api_ipsec_crypto_alg_t in,
			  ipsec_crypto_alg_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
#define _(v,f,s) case IPSEC_API_CRYPTO_ALG_##f: \
      *out = IPSEC_CRYPTO_ALG_##f;              \
      return (0);
      foreach_ipsec_crypto_alg
#undef _
    }
  return (VNET_API_ERROR_INVALID_ALGORITHM);
}

static vl_api_ipsec_crypto_alg_t
ipsec_crypto_algo_encode (ipsec_crypto_alg_t c)
{
  switch (c)
    {
#define _(v,f,s) case IPSEC_CRYPTO_ALG_##f:                     \
      return clib_host_to_net_u32(IPSEC_API_CRYPTO_ALG_##f);
      foreach_ipsec_crypto_alg
#undef _
    case IPSEC_CRYPTO_N_ALG:
      break;
    }
  ASSERT (0);
  return (VNET_API_ERROR_UNIMPLEMENTED);
}


static int
ipsec_integ_algo_decode (vl_api_ipsec_integ_alg_t in, ipsec_integ_alg_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
#define _(v,f,s) case IPSEC_API_INTEG_ALG_##f:  \
      *out = IPSEC_INTEG_ALG_##f;               \
      return (0);
      foreach_ipsec_integ_alg
#undef _
    }
  return (VNET_API_ERROR_INVALID_ALGORITHM);
}

static vl_api_ipsec_integ_alg_t
ipsec_integ_algo_encode (ipsec_integ_alg_t i)
{
  switch (i)
    {
#define _(v,f,s) case IPSEC_INTEG_ALG_##f:                      \
      return (clib_host_to_net_u32(IPSEC_API_INTEG_ALG_##f));
      foreach_ipsec_integ_alg
#undef _
    case IPSEC_INTEG_N_ALG:
      break;
    }
  ASSERT (0);
  return (VNET_API_ERROR_UNIMPLEMENTED);
}

static void
ipsec_key_decode (const vl_api_key_t * key, ipsec_key_t * out)
{
  ipsec_mk_key (out, key->data, key->length);
}

static void
ipsec_key_encode (const ipsec_key_t * in, vl_api_key_t * out)
{
  out->length = in->len;
  clib_memcpy (out->data, in->data, out->length);
}

static ipsec_sa_flags_t
ipsec_sa_flags_decode (vl_api_ipsec_sad_flags_t in)
{
  ipsec_sa_flags_t flags = IPSEC_SA_FLAG_NONE;
  in = clib_net_to_host_u32 (in);

  if (in & IPSEC_API_SAD_FLAG_USE_ESN)
    flags |= IPSEC_SA_FLAG_USE_ESN;
  if (in & IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY)
    flags |= IPSEC_SA_FLAG_USE_ANTI_REPLAY;
  if (in & IPSEC_API_SAD_FLAG_IS_TUNNEL)
    flags |= IPSEC_SA_FLAG_IS_TUNNEL;
  if (in & IPSEC_API_SAD_FLAG_IS_TUNNEL_V6)
    flags |= IPSEC_SA_FLAG_IS_TUNNEL_V6;
  if (in & IPSEC_API_SAD_FLAG_UDP_ENCAP)
    flags |= IPSEC_SA_FLAG_UDP_ENCAP;

  return (flags);
}

static vl_api_ipsec_sad_flags_t
ipsec_sad_flags_encode (const ipsec_sa_t * sa)
{
  vl_api_ipsec_sad_flags_t flags = IPSEC_API_SAD_FLAG_NONE;

  if (ipsec_sa_is_set_USE_ESN (sa))
    flags |= IPSEC_API_SAD_FLAG_USE_ESN;
  if (ipsec_sa_is_set_USE_ANTI_REPLAY (sa))
    flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
    flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;

  return clib_host_to_net_u32 (flags);
}

static void vl_api_ipsec_sad_entry_add_del_t_handler
  (vl_api_ipsec_sad_entry_add_del_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
  ip46_address_t tun_src = { }, tun_dst =
  {
  };
  ipsec_key_t crypto_key, integ_key;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  ipsec_protocol_t proto;
  ipsec_sa_flags_t flags;
  u32 id, spi, sa_index = ~0;
  int rv;

#if WITH_LIBSSL > 0

  id = ntohl (mp->entry.sad_id);
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

  ip_address_decode (&mp->entry.tunnel_src, &tun_src);
  ip_address_decode (&mp->entry.tunnel_dst, &tun_dst);

  if (mp->is_add)
    rv = ipsec_sa_add (id, spi, proto,
		       crypto_alg, &crypto_key,
		       integ_alg, &integ_key, flags,
		       0, mp->entry.salt, &tun_src, &tun_dst, &sa_index);
  else
    rv = ipsec_sa_del (id);

#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY,
  {
    rmp->stat_index = htonl (sa_index);
  });
  /* *INDENT-ON* */
}

static void
send_ipsec_spds_details (ipsec_spd_t * spd, vl_api_registration_t * reg,
			 u32 context)
{
  vl_api_ipsec_spds_details_t *mp;
  u32 n_policies = 0;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IPSEC_SPDS_DETAILS);
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
#if WITH_LIBSSL > 0
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (spd, im->spds, ({
    send_ipsec_spds_details (spd, reg, mp->context);
  }));
  /* *INDENT-ON* */
#else
  clib_warning ("unimplemented");
#endif
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
  mp->_vl_msg_id = ntohs (VL_API_IPSEC_SPD_DETAILS);
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
  mp->entry.local_port_start = p->lport.start;
  mp->entry.local_port_stop = p->lport.stop;
  mp->entry.remote_port_start = p->rport.start;
  mp->entry.remote_port_stop = p->rport.stop;
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
#if WITH_LIBSSL > 0
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  p = hash_get (im->spd_index_by_spd_id, ntohl (mp->spd_id));
  if (!p)
    return;

  spd_index = p[0];
  spd = pool_elt_at_index (im->spds, spd_index);

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_SPD_POLICY_TYPE(ptype) {
    vec_foreach(ii, spd->policies[ptype])
      {
        policy = pool_elt_at_index(im->policies, *ii);

        if (mp->sa_id == ~(0) || ntohl (mp->sa_id) == policy->sa_id)
          send_ipsec_spd_details (policy, reg, mp->context);
      }
  }
  /* *INDENT-ON* */
#else
  clib_warning ("unimplemented");
#endif
}

static void
send_ipsec_spd_interface_details (vl_api_registration_t * reg, u32 spd_index,
				  u32 sw_if_index, u32 context)
{
  vl_api_ipsec_spd_interface_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IPSEC_SPD_INTERFACE_DETAILS);
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

#if WITH_LIBSSL > 0
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
      /* *INDENT-OFF* */
      hash_foreach(k, v, im->spd_index_by_sw_if_index, ({
        send_ipsec_spd_interface_details(reg, v, k, mp->context);
      }));
      /* *INDENT-ON* */
    }

#else
  clib_warning ("unimplemented");
#endif
}

static void
vl_api_ipsec_sa_set_key_t_handler (vl_api_ipsec_sa_set_key_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_sa_set_key_reply_t *rmp;
  ipsec_key_t ck, ik;
  u32 id;
  int rv;
#if WITH_LIBSSL > 0

  id = ntohl (mp->sa_id);

  ipsec_key_decode (&mp->crypto_key, &ck);
  ipsec_key_decode (&mp->integrity_key, &ik);

  rv = ipsec_set_sa_key (id, &ck, &ik);
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IPSEC_SA_SET_KEY_REPLY);
}

static void
vl_api_ipsec_tunnel_if_add_del_t_handler (vl_api_ipsec_tunnel_if_add_del_t *
					  mp)
{
  vl_api_ipsec_tunnel_if_add_del_reply_t *rmp;
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  u32 sw_if_index = ~0;
  ip46_type_t itype;
  int rv;

#if WITH_LIBSSL > 0
  ipsec_add_del_tunnel_args_t tun;

  clib_memset (&tun, 0, sizeof (ipsec_add_del_tunnel_args_t));

  tun.is_add = mp->is_add;
  tun.esn = mp->esn;
  tun.anti_replay = mp->anti_replay;
  tun.local_spi = ntohl (mp->local_spi);
  tun.remote_spi = ntohl (mp->remote_spi);
  tun.crypto_alg = mp->crypto_alg;
  tun.local_crypto_key_len = mp->local_crypto_key_len;
  tun.remote_crypto_key_len = mp->remote_crypto_key_len;
  tun.integ_alg = mp->integ_alg;
  tun.local_integ_key_len = mp->local_integ_key_len;
  tun.remote_integ_key_len = mp->remote_integ_key_len;
  tun.udp_encap = mp->udp_encap;
  tun.tx_table_id = ntohl (mp->tx_table_id);
  tun.salt = mp->salt;
  itype = ip_address_decode (&mp->local_ip, &tun.local_ip);
  itype = ip_address_decode (&mp->remote_ip, &tun.remote_ip);
  tun.is_ip6 = (IP46_TYPE_IP6 == itype);
  memcpy (&tun.local_crypto_key, &mp->local_crypto_key,
	  mp->local_crypto_key_len);
  memcpy (&tun.remote_crypto_key, &mp->remote_crypto_key,
	  mp->remote_crypto_key_len);
  memcpy (&tun.local_integ_key, &mp->local_integ_key,
	  mp->local_integ_key_len);
  memcpy (&tun.remote_integ_key, &mp->remote_integ_key,
	  mp->remote_integ_key_len);
  tun.renumber = mp->renumber;
  tun.show_instance = ntohl (mp->show_instance);

  rv = ipsec_add_del_tunnel_if_internal (vnm, &tun, &sw_if_index);

#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IPSEC_TUNNEL_IF_ADD_DEL_REPLY,
  ({
    rmp->sw_if_index = htonl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
send_ipsec_sa_details (ipsec_sa_t * sa, vl_api_registration_t * reg,
		       u32 context, u32 sw_if_index)
{
  vl_api_ipsec_sa_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IPSEC_SA_DETAILS);
  mp->context = context;

  mp->entry.sad_id = htonl (sa->id);
  mp->entry.spi = htonl (sa->spi);
  mp->entry.protocol = ipsec_proto_encode (sa->protocol);
  mp->entry.tx_table_id =
    htonl (fib_table_get_table_id (sa->tx_fib_index, FIB_PROTOCOL_IP4));

  mp->entry.crypto_algorithm = ipsec_crypto_algo_encode (sa->crypto_alg);
  ipsec_key_encode (&sa->crypto_key, &mp->entry.crypto_key);

  mp->entry.integrity_algorithm = ipsec_integ_algo_encode (sa->integ_alg);
  ipsec_key_encode (&sa->integ_key, &mp->entry.integrity_key);

  mp->entry.flags = ipsec_sad_flags_encode (sa);

  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      ip_address_encode (&sa->tunnel_src_addr, IP46_TYPE_ANY,
			 &mp->entry.tunnel_src);
      ip_address_encode (&sa->tunnel_dst_addr, IP46_TYPE_ANY,
			 &mp->entry.tunnel_dst);
    }

  mp->sw_if_index = htonl (sw_if_index);
  mp->salt = clib_host_to_net_u32 (sa->salt);
  mp->seq_outbound = clib_host_to_net_u64 (((u64) sa->seq));
  mp->last_seq_inbound = clib_host_to_net_u64 (((u64) sa->last_seq));
  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      mp->seq_outbound |= (u64) (clib_host_to_net_u32 (sa->seq_hi));
      mp->last_seq_inbound |= (u64) (clib_host_to_net_u32 (sa->last_seq_hi));
    }
  if (ipsec_sa_is_set_USE_ANTI_REPLAY (sa))
    mp->replay_window = clib_host_to_net_u64 (sa->replay_window);

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_ipsec_sa_dump_t_handler (vl_api_ipsec_sa_dump_t * mp)
{
  vl_api_registration_t *reg;
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  ipsec_sa_t *sa;
  ipsec_tunnel_if_t *t;
  u32 *sa_index_to_tun_if_index = 0;

#if WITH_LIBSSL > 0
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg || pool_elts (im->sad) == 0)
    return;

  vec_validate_init_empty (sa_index_to_tun_if_index, vec_len (im->sad) - 1,
			   ~0);

  /* *INDENT-OFF* */
  pool_foreach (t, im->tunnel_interfaces,
  ({
    vnet_hw_interface_t *hi;
    u32 sw_if_index = ~0;

    hi = vnet_get_hw_interface (vnm, t->hw_if_index);
    sw_if_index = hi->sw_if_index;
    sa_index_to_tun_if_index[t->input_sa_index] = sw_if_index;
    sa_index_to_tun_if_index[t->output_sa_index] = sw_if_index;
  }));

  pool_foreach (sa, im->sad,
  ({
    if (mp->sa_id == ~(0) || ntohl (mp->sa_id) == sa->id)
      send_ipsec_sa_details (sa, reg, mp->context,
			     sa_index_to_tun_if_index[sa - im->sad]);
  }));
  /* *INDENT-ON* */

  vec_free (sa_index_to_tun_if_index);
#else
  clib_warning ("unimplemented");
#endif
}


static void
vl_api_ipsec_tunnel_if_set_key_t_handler (vl_api_ipsec_tunnel_if_set_key_t *
					  mp)
{
  vl_api_ipsec_tunnel_if_set_key_reply_t *rmp;
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  vnet_sw_interface_t *sw;
  u8 *key = 0;
  int rv;

#if WITH_LIBSSL > 0
  sw = vnet_get_sw_interface (vnm, ntohl (mp->sw_if_index));

  switch (mp->key_type)
    {
    case IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO:
    case IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO:
      if (mp->alg < IPSEC_CRYPTO_ALG_AES_CBC_128 ||
	  mp->alg >= IPSEC_CRYPTO_N_ALG)
	{
	  rv = VNET_API_ERROR_INVALID_ALGORITHM;
	  goto out;
	}
      break;
    case IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG:
    case IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG:
      if (mp->alg >= IPSEC_INTEG_N_ALG)
	{
	  rv = VNET_API_ERROR_INVALID_ALGORITHM;
	  goto out;
	}
      break;
    case IPSEC_IF_SET_KEY_TYPE_NONE:
    default:
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
      break;
    }

  key = vec_new (u8, mp->key_len);
  clib_memcpy (key, mp->key, mp->key_len);

  rv = ipsec_set_interface_key (vnm, sw->hw_if_index, mp->key_type, mp->alg,
				key);
  vec_free (key);
#else
  clib_warning ("unimplemented");
#endif

out:
  REPLY_MACRO (VL_API_IPSEC_TUNNEL_IF_SET_KEY_REPLY);
}


static void
vl_api_ipsec_tunnel_if_set_sa_t_handler (vl_api_ipsec_tunnel_if_set_sa_t * mp)
{
  vl_api_ipsec_tunnel_if_set_sa_reply_t *rmp;
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  vnet_sw_interface_t *sw;
  int rv;

#if WITH_LIBSSL > 0
  sw = vnet_get_sw_interface (vnm, ntohl (mp->sw_if_index));

  rv = ipsec_set_interface_sa (vnm, sw->hw_if_index, ntohl (mp->sa_id),
			       mp->is_outbound);
#else
  clib_warning ("unimplemented");
#endif

  REPLY_MACRO (VL_API_IPSEC_TUNNEL_IF_SET_SA_REPLY);
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
  pool_foreach (ab, im->ah_backends, {
    vl_api_ipsec_backend_details_t *mp = vl_msg_api_alloc (sizeof (*mp));
    clib_memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (VL_API_IPSEC_BACKEND_DETAILS);
    mp->context = context;
    snprintf ((char *)mp->name, sizeof (mp->name), "%.*s", vec_len (ab->name),
              ab->name);
    mp->protocol = ntohl (IPSEC_API_PROTO_AH);
    mp->index = ab - im->ah_backends;
    mp->active = mp->index == im->ah_current_backend ? 1 : 0;
    vl_api_send_msg (rp, (u8 *)mp);
  });
  pool_foreach (eb, im->esp_backends, {
    vl_api_ipsec_backend_details_t *mp = vl_msg_api_alloc (sizeof (*mp));
    clib_memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (VL_API_IPSEC_BACKEND_DETAILS);
    mp->context = context;
    snprintf ((char *)mp->name, sizeof (mp->name), "%.*s", vec_len (eb->name),
              eb->name);
    mp->protocol = ntohl (IPSEC_API_PROTO_ESP);
    mp->index = eb - im->esp_backends;
    mp->active = mp->index == im->esp_current_backend ? 1 : 0;
    vl_api_send_msg (rp, (u8 *)mp);
  });
  /* *INDENT-ON* */
}

static void
vl_api_ipsec_select_backend_t_handler (vl_api_ipsec_select_backend_t * mp)
{
  ipsec_main_t *im = &ipsec_main;
  vl_api_ipsec_select_backend_reply_t *rmp;
  ipsec_protocol_t protocol;
  int rv = 0;
  if (pool_elts (im->sad) > 0)
    {
      rv = VNET_API_ERROR_INSTANCE_IN_USE;
      goto done;
    }

  rv = ipsec_proto_decode (mp->protocol, &protocol);

  if (rv)
    goto done;

#if WITH_LIBSSL > 0
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
#else
  clib_warning ("unimplemented");	/* FIXME */
#endif
done:
  REPLY_MACRO (VL_API_IPSEC_SELECT_BACKEND_REPLY);
}

/*
 * ipsec_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_ipsec;
#undef _
}

static clib_error_t *
ipsec_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

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
