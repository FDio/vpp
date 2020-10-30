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
#include <vnet/api_errno.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip_types_api.h>
#include <ikev2/ikev2.h>
#include <ikev2/ikev2_priv.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <plugins/ikev2/ikev2.api_enum.h>
#include <plugins/ikev2/ikev2.api_types.h>


#define vl_endianfun		/* define message structures */
#include <plugins/ikev2/ikev2.api.h>
#include <plugins/ikev2/ikev2_types.api.h>
#undef vl_endianfun

extern ikev2_main_t ikev2_main;

#define IKEV2_PLUGIN_VERSION_MAJOR 1
#define IKEV2_PLUGIN_VERSION_MINOR 0
#define REPLY_MSG_ID_BASE ikev2_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static u32
ikev2_encode_sa_index (u32 sai, u32 ti)
{
  return (ti << 16) | sai;
}

static void
ikev2_decode_sa_index (u32 api_sai, u32 * sai, u32 * ti)
{
  *sai = api_sai & 0xffff;
  *ti = api_sai >> 16;
}

static void
cp_ike_transforms (vl_api_ikev2_ike_transforms_t * vl_api_ts,
		   ikev2_transforms_set * ts)
{
  vl_api_ts->crypto_alg = ts->crypto_alg;
  vl_api_ts->integ_alg = ts->integ_alg;
  vl_api_ts->dh_group = ts->dh_type;
  vl_api_ts->crypto_key_size = ts->crypto_key_size;
}

static void
cp_esp_transforms (vl_api_ikev2_esp_transforms_t * vl_api_ts,
		   ikev2_transforms_set * ts)
{
  vl_api_ts->crypto_alg = ts->crypto_alg;
  vl_api_ts->integ_alg = ts->integ_alg;
  vl_api_ts->crypto_key_size = ts->crypto_key_size;
}

static void
cp_id (vl_api_ikev2_id_t * vl_api_id, ikev2_id_t * id)
{
  if (!id->data)
    return;

  int size_data = 0;
  vl_api_id->type = id->type;
  size_data = sizeof (vl_api_id->data) - 1;	// size without zero ending character
  if (vec_len (id->data) < size_data)
    size_data = vec_len (id->data);

  vl_api_id->data_len = size_data;
  clib_memcpy (vl_api_id->data, id->data, size_data);
}

static void
cp_ts (vl_api_ikev2_ts_t * vl_api_ts, ikev2_ts_t * ts, u8 is_local)
{
  vl_api_ts->is_local = is_local;
  vl_api_ts->protocol_id = ts->protocol_id;
  vl_api_ts->start_port = ts->start_port;
  vl_api_ts->end_port = ts->end_port;
  ip_address_encode2 (&ts->start_addr, &vl_api_ts->start_addr);
  ip_address_encode2 (&ts->end_addr, &vl_api_ts->end_addr);
}

static void
cp_auth (vl_api_ikev2_auth_t * vl_api_auth, ikev2_auth_t * auth)
{
  vl_api_auth->method = auth->method;
  vl_api_auth->data_len = vec_len (auth->data);
  vl_api_auth->hex = auth->hex;
  clib_memcpy (&vl_api_auth->data, auth->data, vec_len (auth->data));
}

static void
cp_responder (vl_api_ikev2_responder_t * vl_api_responder,
	      ikev2_responder_t * responder)
{
  vl_api_responder->sw_if_index = responder->sw_if_index;
  ip_address_encode2 (&responder->addr, &vl_api_responder->addr);
}

void
cp_sa_transform (vl_api_ikev2_sa_transform_t * vl_tr,
		 ikev2_sa_transform_t * tr)
{
  vl_tr->transform_type = tr->type;
  vl_tr->key_len = tr->key_len;
  vl_tr->key_trunc = tr->key_trunc;
  vl_tr->block_size = tr->block_size;
  vl_tr->dh_group = tr->dh_group;
  vl_tr->transform_id = tr->encr_type;
}

static void
send_profile (ikev2_profile_t * profile, vl_api_registration_t * reg,
	      u32 context)
{
  vl_api_ikev2_profile_details_t *rmp = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp) + vec_len (profile->auth.data));
  clib_memset (rmp, 0, sizeof (*rmp) + vec_len (profile->auth.data));
  ikev2_main_t *im = &ikev2_main;
  rmp->_vl_msg_id = ntohs (VL_API_IKEV2_PROFILE_DETAILS + im->msg_id_base);
  rmp->context = context;

  int size_data = sizeof (rmp->profile.name) - 1;
  if (vec_len (profile->name) < size_data)
    size_data = vec_len (profile->name);
  clib_memcpy (rmp->profile.name, profile->name, size_data);

  cp_ike_transforms (&rmp->profile.ike_ts, &profile->ike_ts);
  cp_esp_transforms (&rmp->profile.esp_ts, &profile->esp_ts);

  cp_id (&rmp->profile.loc_id, &profile->loc_id);
  cp_id (&rmp->profile.rem_id, &profile->rem_id);

  cp_ts (&rmp->profile.rem_ts, &profile->rem_ts, 0 /* is_local */ );
  cp_ts (&rmp->profile.loc_ts, &profile->loc_ts, 1 /* is_local */ );

  cp_auth (&rmp->profile.auth, &profile->auth);

  cp_responder (&rmp->profile.responder, &profile->responder);

  rmp->profile.udp_encap = profile->udp_encap;
  rmp->profile.tun_itf = profile->tun_itf;
  rmp->profile.natt_disabled = profile->natt_disabled;
  rmp->profile.ipsec_over_udp_port = profile->ipsec_over_udp_port;

  rmp->profile.lifetime = profile->lifetime;
  rmp->profile.lifetime_maxdata = profile->lifetime_maxdata;
  rmp->profile.lifetime_jitter = profile->lifetime_jitter;
  rmp->profile.handover = profile->handover;

  vl_api_ikev2_profile_t_endian (&rmp->profile);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_ikev2_profile_dump_t_handler (vl_api_ikev2_profile_dump_t * mp)
{
  ikev2_main_t *im = &ikev2_main;
  ikev2_profile_t *profile;
  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (profile, im->profiles,
  ({
    send_profile (profile, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

static void
send_sa (ikev2_sa_t * sa, vl_api_ikev2_sa_dump_t * mp, u32 api_sa_index)
{
  vl_api_ikev2_sa_details_t *rmp = 0;
  int rv = 0;
  ikev2_sa_transform_t *tr;

  /* *INDENT-OFF* */
  REPLY_MACRO2_ZERO (VL_API_IKEV2_SA_DETAILS,
  {
    vl_api_ikev2_sa_t *rsa = &rmp->sa;
    vl_api_ikev2_keys_t* k = &rsa->keys;
    rsa->profile_index = rsa->profile_index;
    rsa->sa_index = api_sa_index;
    ip_address_encode2 (&sa->iaddr, &rsa->iaddr);
    ip_address_encode2 (&sa->raddr, &rsa->raddr);
    rsa->ispi = sa->ispi;
    rsa->rspi = sa->rspi;
    cp_id(&rsa->i_id, &sa->i_id);
    cp_id(&rsa->r_id, &sa->r_id);

    tr = ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
    if (tr)
      cp_sa_transform (&rsa->encryption, tr);

    tr = ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);
    if (tr)
      cp_sa_transform (&rsa->prf, tr);

    tr = ikev2_sa_get_td_for_type (sa->r_proposals,
                                   IKEV2_TRANSFORM_TYPE_INTEG);
    if (tr)
      cp_sa_transform (&rsa->integrity, tr);

    tr = ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_DH);
    if (tr)
      cp_sa_transform (&rsa->dh, tr);

    k->sk_d_len = vec_len (sa->sk_d);
    clib_memcpy (&k->sk_d, sa->sk_d, k->sk_d_len);

    k->sk_ai_len = vec_len (sa->sk_ai);
    clib_memcpy (&k->sk_ai, sa->sk_ai, k->sk_ai_len);

    k->sk_ar_len = vec_len (sa->sk_ar);
    clib_memcpy (&k->sk_ar, sa->sk_ar, k->sk_ar_len);

    k->sk_ei_len = vec_len (sa->sk_ei);
    clib_memcpy (&k->sk_ei, sa->sk_ei, k->sk_ei_len);

    k->sk_er_len = vec_len (sa->sk_er);
    clib_memcpy (&k->sk_er, sa->sk_er, k->sk_er_len);

    k->sk_pi_len = vec_len (sa->sk_pi);
    clib_memcpy (&k->sk_pi, sa->sk_pi, k->sk_pi_len);

    k->sk_pr_len = vec_len (sa->sk_pr);
    clib_memcpy (&k->sk_pr, sa->sk_pr, k->sk_pr_len);

    vl_api_ikev2_sa_t_endian(rsa);
  });
  /* *INDENT-ON* */
}

static void
vl_api_ikev2_sa_dump_t_handler (vl_api_ikev2_sa_dump_t * mp)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *sa;

  vec_foreach (tkm, km->per_thread_data)
  {
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas,
    ({
      u32 api_sa_index = ikev2_encode_sa_index (sa - tkm->sas,
                                              tkm - km->per_thread_data);
      send_sa (sa, mp, api_sa_index);
    }));
    /* *INDENT-ON* */
  }
}


static void
send_child_sa (ikev2_child_sa_t * child,
	       vl_api_ikev2_child_sa_dump_t * mp, u32 child_sa_index,
	       u32 sa_index)
{
  vl_api_ikev2_child_sa_details_t *rmp = 0;
  int rv = 0;
  ikev2_sa_transform_t *tr;

  /* *INDENT-OFF* */
  REPLY_MACRO2_ZERO (VL_API_IKEV2_CHILD_SA_DETAILS,
  {
    vl_api_ikev2_keys_t *k = &rmp->child_sa.keys;
    rmp->child_sa.child_sa_index = child_sa_index;
    rmp->child_sa.sa_index = sa_index;
    rmp->child_sa.i_spi =
      child->i_proposals ? child->i_proposals[0].spi : 0;
    rmp->child_sa.r_spi =
      child->r_proposals ? child->r_proposals[0].spi : 0;

    tr = ikev2_sa_get_td_for_type (child->r_proposals,
                                   IKEV2_TRANSFORM_TYPE_ENCR);
    if (tr)
      cp_sa_transform (&rmp->child_sa.encryption, tr);

    tr = ikev2_sa_get_td_for_type (child->r_proposals,
                                   IKEV2_TRANSFORM_TYPE_INTEG);
    if (tr)
      cp_sa_transform (&rmp->child_sa.integrity, tr);

    tr = ikev2_sa_get_td_for_type (child->r_proposals,
                                   IKEV2_TRANSFORM_TYPE_ESN);
    if (tr)
      cp_sa_transform (&rmp->child_sa.esn, tr);

    k->sk_ei_len = vec_len (child->sk_ei);
    clib_memcpy (&k->sk_ei, child->sk_ei, k->sk_ei_len);

    k->sk_er_len = vec_len (child->sk_er);
    clib_memcpy (&k->sk_er, child->sk_er, k->sk_er_len);

    if (vec_len (child->sk_ai))
      {
        k->sk_ai_len = vec_len (child->sk_ai);
        clib_memcpy (&k->sk_ai, child->sk_ai,
		     k->sk_ai_len);

        k->sk_ar_len = vec_len (child->sk_ar);
        clib_memcpy (&k->sk_ar, child->sk_ar,
		     k->sk_ar_len);
      }

    vl_api_ikev2_child_sa_t_endian (&rmp->child_sa);
  });
  /* *INDENT-ON* */
}

static void
vl_api_ikev2_child_sa_dump_t_handler (vl_api_ikev2_child_sa_dump_t * mp)
{
  ikev2_main_t *im = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *sa;
  ikev2_child_sa_t *child;
  u32 sai = ~0, ti = ~0;

  ikev2_decode_sa_index (clib_net_to_host_u32 (mp->sa_index), &sai, &ti);

  if (vec_len (im->per_thread_data) <= ti)
    return;

  tkm = vec_elt_at_index (im->per_thread_data, ti);

  if (pool_len (tkm->sas) <= sai || pool_is_free_index (tkm->sas, sai))
    return;

  sa = pool_elt_at_index (tkm->sas, sai);

  vec_foreach (child, sa->childs)
  {
    u32 child_sa_index = child - sa->childs;
    send_child_sa (child, mp, child_sa_index, sai);
  }
}

static void
  vl_api_ikev2_traffic_selector_dump_t_handler
  (vl_api_ikev2_traffic_selector_dump_t * mp)
{
  ikev2_main_t *im = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *sa;
  ikev2_child_sa_t *child;
  ikev2_ts_t *ts;
  u32 sai = ~0, ti = ~0;

  u32 api_sa_index = clib_net_to_host_u32 (mp->sa_index);
  u32 child_sa_index = clib_net_to_host_u32 (mp->child_sa_index);
  ikev2_decode_sa_index (api_sa_index, &sai, &ti);

  if (vec_len (im->per_thread_data) <= ti)
    return;

  tkm = vec_elt_at_index (im->per_thread_data, ti);

  if (pool_len (tkm->sas) <= sai || pool_is_free_index (tkm->sas, sai))
    return;

  sa = pool_elt_at_index (tkm->sas, sai);

  if (vec_len (sa->childs) <= child_sa_index)
    return;

  child = vec_elt_at_index (sa->childs, child_sa_index);

  vec_foreach (ts, mp->is_initiator ? child->tsi : child->tsr)
  {
    vl_api_ikev2_traffic_selector_details_t *rmp = 0;
    int rv = 0;

    /* *INDENT-OFF* */
    REPLY_MACRO2_ZERO (VL_API_IKEV2_TRAFFIC_SELECTOR_DETAILS,
    {
      rmp->ts.sa_index = api_sa_index;
      rmp->ts.child_sa_index = child_sa_index;
      cp_ts (&rmp->ts, ts, mp->is_initiator);
      vl_api_ikev2_ts_t_endian (&rmp->ts);
    });
    /* *INDENT-ON* */
  }
}

static void
vl_api_ikev2_nonce_get_t_handler (vl_api_ikev2_nonce_get_t * mp)
{
  ikev2_main_t *im = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *sa;
  u32 sai = ~0, ti = ~0;

  ikev2_decode_sa_index (clib_net_to_host_u32 (mp->sa_index), &sai, &ti);

  if (vec_len (im->per_thread_data) <= ti)
    return;

  tkm = vec_elt_at_index (im->per_thread_data, ti);

  if (pool_len (tkm->sas) <= sai || pool_is_free_index (tkm->sas, sai))
    return;

  sa = pool_elt_at_index (tkm->sas, sai);

  u8 *nonce = mp->is_initiator ? sa->i_nonce : sa->r_nonce;
  vl_api_ikev2_nonce_get_reply_t *rmp = 0;
  int data_len = vec_len (nonce);
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO3_ZERO (VL_API_IKEV2_NONCE_GET_REPLY, data_len,
  {
    rmp->data_len = clib_host_to_net_u32 (data_len);
    clib_memcpy (rmp->nonce, nonce, data_len);
  });
  /* *INDENT-ON* */
}

static void
vl_api_ikev2_plugin_get_version_t_handler (vl_api_ikev2_plugin_get_version_t *
					   mp)
{
  ikev2_main_t *im = &ikev2_main;
  vl_api_ikev2_plugin_get_version_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_IKEV2_PLUGIN_GET_VERSION_REPLY + im->msg_id_base);
  rmp->context = mp->context;
  rmp->major = htonl (IKEV2_PLUGIN_VERSION_MAJOR);
  rmp->minor = htonl (IKEV2_PLUGIN_VERSION_MINOR);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_ikev2_profile_set_liveness_t_handler
  (vl_api_ikev2_profile_set_liveness_t * mp)
{
  vl_api_ikev2_profile_set_liveness_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  clib_error_t *error;
  error = ikev2_set_liveness_params (clib_net_to_host_u32 (mp->period),
				     clib_net_to_host_u32 (mp->max_retries));
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_SET_LIVENESS_REPLY);
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
  int data_len = ntohl (mp->data_len);
  u8 *tmp = format (0, "%s", mp->name);
  u8 *data = vec_new (u8, data_len);
  clib_memcpy (data, mp->data, data_len);
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
  vl_api_ikev2_profile_set_id_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  int data_len = ntohl (mp->data_len);
  u8 *data = vec_new (u8, data_len);
  clib_memcpy (data, mp->data, data_len);
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
  vl_api_ikev2_profile_set_udp_encap_t_handler
  (vl_api_ikev2_profile_set_udp_encap_t * mp)
{
  vl_api_ikev2_profile_set_udp_encap_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  error = ikev2_set_profile_udp_encap (vm, tmp);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_SET_UDP_ENCAP_REPLY);
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
  ip_address_t start_addr, end_addr;
  ip_address_decode2 (&mp->ts.start_addr, &start_addr);
  ip_address_decode2 (&mp->ts.end_addr, &end_addr);
  error =
    ikev2_set_profile_ts (vm, tmp, mp->ts.protocol_id,
			  clib_net_to_host_u16 (mp->ts.start_port),
			  clib_net_to_host_u16 (mp->ts.end_port),
			  start_addr, end_addr, mp->ts.is_local);
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
  vl_api_ikev2_set_local_key_reply_t *rmp;
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
  ip_address_t ip;
  ip_address_decode2 (&mp->responder.addr, &ip);
  u32 sw_if_index = clib_net_to_host_u32 (mp->responder.sw_if_index);

  error = ikev2_set_profile_responder (vm, tmp, sw_if_index, ip);
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
    ikev2_set_profile_ike_transforms (vm, tmp, mp->tr.crypto_alg,
				      mp->tr.integ_alg,
				      mp->tr.dh_group,
				      ntohl (mp->tr.crypto_key_size));
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
    ikev2_set_profile_esp_transforms (vm, tmp, mp->tr.crypto_alg,
				      mp->tr.integ_alg,
				      ntohl (mp->tr.crypto_key_size));
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
    ikev2_set_profile_sa_lifetime (vm, tmp,
				   clib_net_to_host_u64 (mp->lifetime),
				   ntohl (mp->lifetime_jitter),
				   ntohl (mp->handover),
				   clib_net_to_host_u64
				   (mp->lifetime_maxdata));
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_SET_SA_LIFETIME_REPLY);
}

static void
  vl_api_ikev2_profile_set_ipsec_udp_port_t_handler
  (vl_api_ikev2_profile_set_ipsec_udp_port_t * mp)
{
  vl_api_ikev2_profile_set_ipsec_udp_port_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();

  u8 *tmp = format (0, "%s", mp->name);

  rv =
    ikev2_set_profile_ipsec_udp_port (vm, tmp,
				      clib_net_to_host_u16 (mp->port),
				      mp->is_set);
  vec_free (tmp);
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_SET_IPSEC_UDP_PORT_REPLY);
}

static void
  vl_api_ikev2_set_tunnel_interface_t_handler
  (vl_api_ikev2_set_tunnel_interface_t * mp)
{
  vl_api_ikev2_set_tunnel_interface_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

#if WITH_LIBSSL > 0
  u8 *tmp = format (0, "%s", mp->name);
  clib_error_t *error;

  error = ikev2_set_profile_tunnel_interface (vlib_get_main (), tmp,
					      ntohl (mp->sw_if_index));

  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
  vec_free (tmp);
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_IKEV2_SET_TUNNEL_INTERFACE_REPLY);
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
  vl_api_ikev2_profile_disable_natt_t_handler
  (vl_api_ikev2_profile_disable_natt_t * mp)
{
  vl_api_ikev2_profile_disable_natt_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  clib_error_t *error;

  u8 *tmp = format (0, "%s", mp->name);
  error = ikev2_profile_natt_disable (tmp);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_DISABLE_NATT_REPLY);
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

#include <ikev2/ikev2.api.c>
static clib_error_t *
ikev2_api_init (vlib_main_t * vm)
{
  ikev2_main_t *im = &ikev2_main;

  /* Ask for a correctly-sized block of API message decode slots */
  im->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (ikev2_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
