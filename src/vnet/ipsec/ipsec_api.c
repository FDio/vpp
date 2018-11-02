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

#include <vnet/vnet_msg_enum.h>

#if WITH_LIBSSL > 0
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ikev2.h>
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

#define foreach_vpe_api_msg                                             \
_(IPSEC_SPD_ADD_DEL, ipsec_spd_add_del)                                 \
_(IPSEC_INTERFACE_ADD_DEL_SPD, ipsec_interface_add_del_spd)             \
_(IPSEC_SPD_ADD_DEL_ENTRY, ipsec_spd_add_del_entry)                     \
_(IPSEC_SAD_ADD_DEL_ENTRY, ipsec_sad_add_del_entry)                     \
_(IPSEC_SA_SET_KEY, ipsec_sa_set_key)                                   \
_(IPSEC_SA_DUMP, ipsec_sa_dump)                                         \
_(IPSEC_SPDS_DUMP, ipsec_spds_dump)                                     \
_(IPSEC_SPD_DUMP, ipsec_spd_dump)                                       \
_(IPSEC_SPD_INTERFACE_DUMP, ipsec_spd_interface_dump)			\
_(IPSEC_TUNNEL_IF_ADD_DEL, ipsec_tunnel_if_add_del)                     \
_(IPSEC_TUNNEL_IF_SET_KEY, ipsec_tunnel_if_set_key)                     \
_(IPSEC_TUNNEL_IF_SET_SA, ipsec_tunnel_if_set_sa)                       \
_(IKEV2_PROFILE_ADD_DEL, ikev2_profile_add_del)                         \
_(IKEV2_PROFILE_SET_AUTH, ikev2_profile_set_auth)                       \
_(IKEV2_PROFILE_SET_ID, ikev2_profile_set_id)                           \
_(IKEV2_PROFILE_SET_TS, ikev2_profile_set_ts)                           \
_(IKEV2_SET_LOCAL_KEY, ikev2_set_local_key)                             \
_(IKEV2_SET_RESPONDER, ikev2_set_responder)                             \
_(IKEV2_SET_IKE_TRANSFORMS, ikev2_set_ike_transforms)                   \
_(IKEV2_SET_ESP_TRANSFORMS, ikev2_set_esp_transforms)                   \
_(IKEV2_SET_SA_LIFETIME, ikev2_set_sa_lifetime)                         \
_(IKEV2_INITIATE_SA_INIT, ikev2_initiate_sa_init)                       \
_(IKEV2_INITIATE_DEL_IKE_SA, ikev2_initiate_del_ike_sa)                 \
_(IKEV2_INITIATE_DEL_CHILD_SA, ikev2_initiate_del_child_sa)             \
_(IKEV2_INITIATE_REKEY_CHILD_SA, ikev2_initiate_rekey_child_sa)

static void vl_api_ipsec_spd_add_del_t_handler
  (vl_api_ipsec_spd_add_del_t * mp)
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

static void vl_api_ipsec_spd_add_del_entry_t_handler
  (vl_api_ipsec_spd_add_del_entry_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_spd_add_del_entry_reply_t *rmp;
  int rv;

#if WITH_LIBSSL > 0
  ipsec_policy_t p;

  clib_memset (&p, 0, sizeof (p));

  p.id = ntohl (mp->spd_id);
  p.priority = ntohl (mp->priority);
  p.is_outbound = mp->is_outbound;
  p.is_ipv6 = mp->is_ipv6;

  if (mp->is_ipv6 || mp->is_ip_any)
    {
      clib_memcpy (&p.raddr.start, mp->remote_address_start, 16);
      clib_memcpy (&p.raddr.stop, mp->remote_address_stop, 16);
      clib_memcpy (&p.laddr.start, mp->local_address_start, 16);
      clib_memcpy (&p.laddr.stop, mp->local_address_stop, 16);
    }
  else
    {
      clib_memcpy (&p.raddr.start.ip4.data, mp->remote_address_start, 4);
      clib_memcpy (&p.raddr.stop.ip4.data, mp->remote_address_stop, 4);
      clib_memcpy (&p.laddr.start.ip4.data, mp->local_address_start, 4);
      clib_memcpy (&p.laddr.stop.ip4.data, mp->local_address_stop, 4);
    }
  p.protocol = mp->protocol;
  p.rport.start = ntohs (mp->remote_port_start);
  p.rport.stop = ntohs (mp->remote_port_stop);
  p.lport.start = ntohs (mp->local_port_start);
  p.lport.stop = ntohs (mp->local_port_stop);
  /* policy action resolve unsupported */
  if (mp->policy == IPSEC_POLICY_ACTION_RESOLVE)
    {
      clib_warning ("unsupported action: 'resolve'");
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }
  p.policy = mp->policy;
  p.sa_id = ntohl (mp->sa_id);

  rv = ipsec_add_del_policy (vm, &p, mp->is_add);
  if (rv)
    goto out;

  if (mp->is_ip_any)
    {
      p.is_ipv6 = 1;
      rv = ipsec_add_del_policy (vm, &p, mp->is_add);
    }
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
  goto out;
#endif

out:
  REPLY_MACRO (VL_API_IPSEC_SPD_ADD_DEL_ENTRY_REPLY);
}

static void vl_api_ipsec_sad_add_del_entry_t_handler
  (vl_api_ipsec_sad_add_del_entry_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_sad_add_del_entry_reply_t *rmp;
  int rv;
#if WITH_LIBSSL > 0
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t sa;

  clib_memset (&sa, 0, sizeof (sa));

  sa.id = ntohl (mp->sad_id);
  sa.spi = ntohl (mp->spi);
  sa.protocol = mp->protocol;
  /* check for unsupported crypto-alg */
  if (mp->crypto_algorithm >= IPSEC_CRYPTO_N_ALG)
    {
      clib_warning ("unsupported crypto-alg: '%U'", format_ipsec_crypto_alg,
		    mp->crypto_algorithm);
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }
  sa.crypto_alg = mp->crypto_algorithm;
  sa.crypto_key_len = mp->crypto_key_length;
  clib_memcpy (&sa.crypto_key, mp->crypto_key, sizeof (sa.crypto_key));
  /* check for unsupported integ-alg */
  if (mp->integrity_algorithm >= IPSEC_INTEG_N_ALG)
    {
      clib_warning ("unsupported integ-alg: '%U'", format_ipsec_integ_alg,
		    mp->integrity_algorithm);
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }

  sa.integ_alg = mp->integrity_algorithm;
  sa.integ_key_len = mp->integrity_key_length;
  clib_memcpy (&sa.integ_key, mp->integrity_key, sizeof (sa.integ_key));
  sa.use_esn = mp->use_extended_sequence_number;
  sa.is_tunnel = mp->is_tunnel;
  sa.is_tunnel_ip6 = mp->is_tunnel_ipv6;
  sa.udp_encap = mp->udp_encap;
  if (sa.is_tunnel_ip6)
    {
      clib_memcpy (&sa.tunnel_src_addr, mp->tunnel_src_address, 16);
      clib_memcpy (&sa.tunnel_dst_addr, mp->tunnel_dst_address, 16);
    }
  else
    {
      clib_memcpy (&sa.tunnel_src_addr.ip4.data, mp->tunnel_src_address, 4);
      clib_memcpy (&sa.tunnel_dst_addr.ip4.data, mp->tunnel_dst_address, 4);
    }
  sa.use_anti_replay = mp->use_anti_replay;

  ASSERT (im->cb.check_support_cb);
  clib_error_t *err = im->cb.check_support_cb (&sa);
  if (err)
    {
      clib_warning ("%s", err->what);
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }

  rv = ipsec_add_del_sa (vm, &sa, mp->is_add);
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
  goto out;
#endif

out:
  REPLY_MACRO (VL_API_IPSEC_SAD_ADD_DEL_ENTRY_REPLY);
}

static void
send_ipsec_spds_details (ipsec_spd_t * spd, vl_api_registration_t * reg,
			 u32 context)
{
  vl_api_ipsec_spds_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IPSEC_SPDS_DETAILS);
  mp->context = context;

  mp->spd_id = htonl (spd->id);
  mp->npolicies = htonl (pool_len (spd->policies));

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

static void
send_ipsec_spd_details (ipsec_policy_t * p, vl_api_registration_t * reg,
			u32 context)
{
  vl_api_ipsec_spd_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IPSEC_SPD_DETAILS);
  mp->context = context;

  mp->spd_id = htonl (p->id);
  mp->priority = htonl (p->priority);
  mp->is_outbound = p->is_outbound;
  mp->is_ipv6 = p->is_ipv6;
  if (p->is_ipv6)
    {
      memcpy (mp->local_start_addr, &p->laddr.start.ip6, 16);
      memcpy (mp->local_stop_addr, &p->laddr.stop.ip6, 16);
      memcpy (mp->remote_start_addr, &p->raddr.start.ip6, 16);
      memcpy (mp->remote_stop_addr, &p->raddr.stop.ip6, 16);
    }
  else
    {
      memcpy (mp->local_start_addr, &p->laddr.start.ip4, 4);
      memcpy (mp->local_stop_addr, &p->laddr.stop.ip4, 4);
      memcpy (mp->remote_start_addr, &p->raddr.start.ip4, 4);
      memcpy (mp->remote_stop_addr, &p->raddr.stop.ip4, 4);
    }
  mp->local_start_port = htons (p->lport.start);
  mp->local_stop_port = htons (p->lport.stop);
  mp->remote_start_port = htons (p->rport.start);
  mp->remote_stop_port = htons (p->rport.stop);
  mp->protocol = p->protocol;
  mp->policy = p->policy;
  mp->sa_id = htonl (p->sa_id);
  mp->bytes = clib_host_to_net_u64 (p->counter.bytes);
  mp->packets = clib_host_to_net_u64 (p->counter.packets);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_ipsec_spd_dump_t_handler (vl_api_ipsec_spd_dump_t * mp)
{
  vl_api_registration_t *reg;
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *policy;
  ipsec_spd_t *spd;
  uword *p;
  u32 spd_index;
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
  pool_foreach (policy, spd->policies,
  ({
    if (mp->sa_id == ~(0) || ntohl (mp->sa_id) == policy->sa_id)
      send_ipsec_spd_details (policy, reg,
                              mp->context);}
    ));
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
  int rv;
#if WITH_LIBSSL > 0
  ipsec_sa_t sa;
  sa.id = ntohl (mp->sa_id);
  sa.crypto_key_len = mp->crypto_key_length;
  clib_memcpy (&sa.crypto_key, mp->crypto_key, sizeof (sa.crypto_key));
  sa.integ_key_len = mp->integrity_key_length;
  clib_memcpy (&sa.integ_key, mp->integrity_key, sizeof (sa.integ_key));

  rv = ipsec_set_sa_key (vm, &sa);
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
  memcpy (&tun.local_ip, mp->local_ip, 4);
  memcpy (&tun.remote_ip, mp->remote_ip, 4);
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

  REPLY_MACRO2 (VL_API_IPSEC_TUNNEL_IF_ADD_DEL_REPLY, (
							{
							rmp->sw_if_index =
							htonl (sw_if_index);
							}));
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

  mp->sa_id = htonl (sa->id);
  mp->sw_if_index = htonl (sw_if_index);

  mp->spi = htonl (sa->spi);
  mp->protocol = sa->protocol;

  mp->crypto_alg = sa->crypto_alg;
  mp->crypto_key_len = sa->crypto_key_len;
  memcpy (mp->crypto_key, sa->crypto_key, sa->crypto_key_len);

  mp->integ_alg = sa->integ_alg;
  mp->integ_key_len = sa->integ_key_len;
  memcpy (mp->integ_key, sa->integ_key, sa->integ_key_len);

  mp->use_esn = sa->use_esn;
  mp->use_anti_replay = sa->use_anti_replay;

  mp->is_tunnel = sa->is_tunnel;
  mp->is_tunnel_ip6 = sa->is_tunnel_ip6;

  if (sa->is_tunnel)
    {
      if (sa->is_tunnel_ip6)
	{
	  memcpy (mp->tunnel_src_addr, &sa->tunnel_src_addr.ip6, 16);
	  memcpy (mp->tunnel_dst_addr, &sa->tunnel_dst_addr.ip6, 16);
	}
      else
	{
	  memcpy (mp->tunnel_src_addr, &sa->tunnel_src_addr.ip4, 4);
	  memcpy (mp->tunnel_dst_addr, &sa->tunnel_dst_addr.ip4, 4);
	}
    }

  mp->salt = clib_host_to_net_u32 (sa->salt);
  mp->seq_outbound = clib_host_to_net_u64 (((u64) sa->seq));
  mp->last_seq_inbound = clib_host_to_net_u64 (((u64) sa->last_seq));
  if (sa->use_esn)
    {
      mp->seq_outbound |= (u64) (clib_host_to_net_u32 (sa->seq_hi));
      mp->last_seq_inbound |= (u64) (clib_host_to_net_u32 (sa->last_seq_hi));
    }
  if (sa->use_anti_replay)
    mp->replay_window = clib_host_to_net_u64 (sa->replay_window);
  mp->total_data_size = clib_host_to_net_u64 (sa->total_data_size);
  mp->udp_encap = sa->udp_encap;

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
	  rv = VNET_API_ERROR_UNIMPLEMENTED;
	  goto out;
	}
      break;
    case IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG:
    case IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG:
      if (mp->alg >= IPSEC_INTEG_N_ALG)
	{
	  rv = VNET_API_ERROR_UNIMPLEMENTED;
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
vl_api_ikev2_profile_add_del_t_handler (vl_api_ikev2_profile_add_del_t * mp)
{
  vl_api_ikev2_profile_add_del_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  error = ikev2_add_del_profile (vm, tmp, mp->is_add);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_ADD_DEL_REPLY);
}

static void
  vl_api_ikev2_profile_set_auth_t_handler
  (vl_api_ikev2_profile_set_auth_t * mp)
{
  vl_api_ikev2_profile_set_auth_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  u8 *data = vec_new (u8, mp->data_len);
  clib_memcpy (data, mp->data, mp->data_len);
  error = ikev2_set_profile_auth (vm, tmp, mp->auth_method, data, mp->is_hex);
  vec_free (tmp);
  vec_free (data);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_SET_AUTH_REPLY);
}

static void
vl_api_ikev2_profile_set_id_t_handler (vl_api_ikev2_profile_set_id_t * mp)
{
  vl_api_ikev2_profile_add_del_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  u8 *data = vec_new (u8, mp->data_len);
  clib_memcpy (data, mp->data, mp->data_len);
  error = ikev2_set_profile_id (vm, tmp, mp->id_type, data, mp->is_local);
  vec_free (tmp);
  vec_free (data);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_SET_ID_REPLY);
}

static void
vl_api_ikev2_profile_set_ts_t_handler (vl_api_ikev2_profile_set_ts_t * mp)
{
  vl_api_ikev2_profile_set_ts_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  error = ikev2_set_profile_ts (vm, tmp, mp->proto, mp->start_port,
				mp->end_port, (ip4_address_t) mp->start_addr,
				(ip4_address_t) mp->end_addr, mp->is_local);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_SET_TS_REPLY);
}

static void
vl_api_ikev2_set_local_key_t_handler (vl_api_ikev2_set_local_key_t * mp)
{
  vl_api_ikev2_profile_set_ts_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  error = ikev2_set_local_key (vm, mp->key_file);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_SET_LOCAL_KEY_REPLY);
}

static void
vl_api_ikev2_set_responder_t_handler (vl_api_ikev2_set_responder_t * mp)
{
  vl_api_ikev2_set_responder_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  u8 *tmp = format (0, "%s", mp->name);
  ip4_address_t ip4;
  clib_memcpy (&ip4, mp->address, sizeof (ip4));

  error = ikev2_set_profile_responder (vm, tmp, mp->sw_if_index, ip4);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_SET_RESPONDER_REPLY);
}

static void
vl_api_ikev2_set_ike_transforms_t_handler (vl_api_ikev2_set_ike_transforms_t *
					   mp)
{
  vl_api_ikev2_set_ike_transforms_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  u8 *tmp = format (0, "%s", mp->name);

  error =
    ikev2_set_profile_ike_transforms (vm, tmp, mp->crypto_alg, mp->integ_alg,
				      mp->dh_group, mp->crypto_key_size);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_SET_IKE_TRANSFORMS_REPLY);
}

static void
vl_api_ikev2_set_esp_transforms_t_handler (vl_api_ikev2_set_esp_transforms_t *
					   mp)
{
  vl_api_ikev2_set_esp_transforms_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  u8 *tmp = format (0, "%s", mp->name);

  error =
    ikev2_set_profile_esp_transforms (vm, tmp, mp->crypto_alg, mp->integ_alg,
				      mp->dh_group, mp->crypto_key_size);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_SET_ESP_TRANSFORMS_REPLY);
}

static void
vl_api_ikev2_set_sa_lifetime_t_handler (vl_api_ikev2_set_sa_lifetime_t * mp)
{
  vl_api_ikev2_set_sa_lifetime_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  u8 *tmp = format (0, "%s", mp->name);

  error =
    ikev2_set_profile_sa_lifetime (vm, tmp, mp->lifetime, mp->lifetime_jitter,
				   mp->handover, mp->lifetime_maxdata);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_SET_SA_LIFETIME_REPLY);
}

static void
vl_api_ikev2_initiate_sa_init_t_handler (vl_api_ikev2_initiate_sa_init_t * mp)
{
  vl_api_ikev2_initiate_sa_init_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  u8 *tmp = format (0, "%s", mp->name);

  error = ikev2_initiate_sa_init (vm, tmp);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_INITIATE_SA_INIT_REPLY);
}

static void
vl_api_ikev2_initiate_del_ike_sa_t_handler (vl_api_ikev2_initiate_del_ike_sa_t
					    * mp)
{
  vl_api_ikev2_initiate_del_ike_sa_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  error = ikev2_initiate_delete_ike_sa (vm, mp->ispi);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_INITIATE_DEL_IKE_SA_REPLY);
}

static void
  vl_api_ikev2_initiate_del_child_sa_t_handler
  (vl_api_ikev2_initiate_del_child_sa_t * mp)
{
  vl_api_ikev2_initiate_del_child_sa_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  error = ikev2_initiate_delete_child_sa (vm, mp->ispi);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_INITIATE_DEL_CHILD_SA_REPLY);
}

static void
  vl_api_ikev2_initiate_rekey_child_sa_t_handler
  (vl_api_ikev2_initiate_rekey_child_sa_t * mp)
{
  vl_api_ikev2_initiate_rekey_child_sa_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  error = ikev2_initiate_rekey_child_sa (vm, mp->ispi);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_INITIATE_REKEY_CHILD_SA_REPLY);
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
