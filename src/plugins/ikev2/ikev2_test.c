/*
 *------------------------------------------------------------------
 * api_format.c
 *
 * Copyright (c) 2014-2016 Cisco and/or its affiliates.
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <plugins/ikev2/ikev2.h>
#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base ikev2_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <ikev2/ikev2.api_enum.h>
#include <ikev2/ikev2.api_types.h>
#include <vpp/api/vpe.api_types.h>

#define vl_endianfun		/* define message structures */
#include <plugins/ikev2/ikev2.api.h>
#undef vl_endianfun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} ikev2_test_main_t;

static const char *valid_chars = "a-zA-Z0-9_";
ikev2_test_main_t ikev2_test_main;

uword
unformat_ikev2_auth_method (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IKEV2_AUTH_METHOD_##f;
  foreach_ikev2_auth_method
#undef _
    else
    return 0;
  return 1;
}


uword
unformat_ikev2_id_type (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IKEV2_ID_TYPE_##f;
  foreach_ikev2_id_type
#undef _
    else
    return 0;
  return 1;
}

#define MACRO_FORMAT(lc)                                \
u8 * format_ikev2_##lc (u8 * s, va_list * args)         \
{                                                       \
  u32 i = va_arg (*args, u32);                          \
  char * t = 0;                                         \
  switch (i) {                                          \
        foreach_ikev2_##lc                              \
      default:                                          \
        return format (s, "unknown (%u)", i);           \
    }                                                   \
  s = format (s, "%s", t);                              \
  return s;                                             \
}

#define _(v,f,str) case IKEV2_AUTH_METHOD_##f: t = str; break;
MACRO_FORMAT (auth_method)
#undef _
#define _(v,f,str) case IKEV2_ID_TYPE_##f: t = str; break;
  MACRO_FORMAT (id_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_ENCR_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_encr_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_PRF_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_prf_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_INTEG_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_integ_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_DH_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_dh_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_ESN_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_esn_type)
#undef _
     u8 *format_ikev2_id_type_and_data (u8 * s, va_list * args)
{
  vl_api_ikev2_id_t *id = va_arg (*args, vl_api_ikev2_id_t *);

  if (id->type == 0)
    return format (s, "none");

  s = format (s, "%U", format_ikev2_id_type, id->type);

  switch (id->type)
    {
    case 0:
      return format (s, "none");
    case IKEV2_ID_TYPE_ID_FQDN:
      s = format (s, " %s", id->data);
      break;
    case IKEV2_ID_TYPE_ID_RFC822_ADDR:
      s = format (s, " %s", id->data);
      break;
    case IKEV2_ID_TYPE_ID_IPV4_ADDR:
      s = format (s, " %U", format_ip_address, id->data);
      break;
    case IKEV2_ID_TYPE_ID_KEY_ID:
      s = format (s, " 0x%U", format_hex_bytes, id->data, id->data_len);
      break;
    default:
      s = format (s, " %s", id->data);
    }

  return s;
}

u8 *
format_ikev2_sa_transform (u8 * s, va_list * args)
{
  vl_api_ikev2_sa_transform_t *tr =
    va_arg (*args, vl_api_ikev2_sa_transform_t *);

  if (!tr)
    return s;

  if (tr->transform_type >= IKEV2_TRANSFORM_NUM_TYPES)
    return s;

  s = format (s, "%U:", format_ikev2_transform_type, tr->transform_type);

  switch (tr->transform_type)
    {
    case IKEV2_TRANSFORM_TYPE_ENCR:
      s =
	format (s, "%U", format_ikev2_transform_encr_type, tr->transform_id);
      break;
    case IKEV2_TRANSFORM_TYPE_PRF:
      s = format (s, "%U", format_ikev2_transform_prf_type, tr->transform_id);
      break;
    case IKEV2_TRANSFORM_TYPE_INTEG:
      s =
	format (s, "%U", format_ikev2_transform_integ_type, tr->transform_id);
      break;
    case IKEV2_TRANSFORM_TYPE_DH:
      s = format (s, "%U", format_ikev2_transform_dh_type, tr->transform_id);
      break;
    case IKEV2_TRANSFORM_TYPE_ESN:
      s = format (s, "%U", format_ikev2_transform_esn_type, tr->transform_id);
      break;
    default:
      break;
    }

  if (tr->transform_type == IKEV2_TRANSFORM_TYPE_ENCR &&
      tr->transform_id == IKEV2_TRANSFORM_ENCR_TYPE_AES_CBC && tr->key_len)
    s = format (s, "-%u", tr->key_len * 8);

  return s;
}

static int
api_ikev2_profile_disable_natt (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_disable_natt_t *mp;
  u8 *name = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_PROFILE_DISABLE_NATT, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_profile_dump (vat_main_t * vam)
{
  ikev2_test_main_t *ik = &ikev2_test_main;
  vl_api_ikev2_profile_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  /* Construct the API message */
  M (IKEV2_PROFILE_DUMP, mp);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  if (!ik->ping_id)
    ik->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (ik->ping_id);
  mp_ping->client_index = vam->my_client_index;

  vam->result_ready = 0;
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void vl_api_ikev2_profile_details_t_handler
  (vl_api_ikev2_profile_details_t * mp)
{
  vat_main_t *vam = ikev2_test_main.vat_main;
  vl_api_ikev2_profile_t *p = &mp->profile;

  fformat (vam->ofp, "profile %s\n", p->name);

  if (p->auth.method)
    {
      if (p->auth.hex)
	fformat (vam->ofp, "  auth-method %U auth data 0x%U\n",
		 format_ikev2_auth_method, p->auth.method,
		 format_hex_bytes, p->auth.data,
		 clib_net_to_host_u32 (p->auth.data_len));
      else
	fformat (vam->ofp, "  auth-method %U auth data %v\n",
		 format_ikev2_auth_method, p->auth.method, format (0,
								   "%s",
								   p->
								   auth.data));
    }

  if (p->loc_id.type)
    {
      fformat (vam->ofp, "  local id-type data %U\n",
	       format_ikev2_id_type_and_data, &p->loc_id);
    }

  if (p->rem_id.type)
    {
      fformat (vam->ofp, "  remote id-type data %U\n",
	       format_ikev2_id_type_and_data, &p->rem_id);
    }

  fformat (vam->ofp, "  local traffic-selector addr %U - %U port %u - %u"
	   " protocol %u\n",
	   format_ip_address, &p->loc_ts.start_addr,
	   format_ip_address, &p->loc_ts.end_addr,
	   clib_net_to_host_u16 (p->loc_ts.start_port),
	   clib_net_to_host_u16 (p->loc_ts.end_port), p->loc_ts.protocol_id);

  fformat (vam->ofp, "  remote traffic-selector addr %U - %U port %u - %u"
	   " protocol %u\n",
	   format_ip_address, &p->rem_ts.start_addr,
	   format_ip_address, &p->rem_ts.end_addr,
	   clib_net_to_host_u16 (p->rem_ts.start_port),
	   clib_net_to_host_u16 (p->rem_ts.end_port), p->rem_ts.protocol_id);
  u32 tun_itf = clib_net_to_host_u32 (p->tun_itf);
  if (~0 != tun_itf)
    fformat (vam->ofp, "  protected tunnel idx %d\n", tun_itf);

  u32 sw_if_index = clib_net_to_host_u32 (p->responder.sw_if_index);
  if (~0 != sw_if_index)
    fformat (vam->ofp, "  responder idx %d %U\n",
	     sw_if_index, format_ip_address, &p->responder.addr);

  if (p->udp_encap)
    fformat (vam->ofp, "  udp-encap\n");

  if (p->natt_disabled)
    fformat (vam->ofp, "  NAT-T disabled\n");

  u32 ipsec_over_udp_port = clib_net_to_host_u16 (p->ipsec_over_udp_port);
  if (ipsec_over_udp_port != IPSEC_UDP_PORT_NONE)
    fformat (vam->ofp, "  ipsec-over-udp port %d\n", ipsec_over_udp_port);

  u32 crypto_key_size = clib_net_to_host_u32 (p->ike_ts.crypto_key_size);
  if (p->ike_ts.crypto_alg || p->ike_ts.integ_alg || p->ike_ts.dh_group
      || crypto_key_size)
    fformat (vam->ofp, "  ike-crypto-alg %U %u ike-integ-alg %U ike-dh %U\n",
	     format_ikev2_transform_encr_type, p->ike_ts.crypto_alg,
	     crypto_key_size, format_ikev2_transform_integ_type,
	     p->ike_ts.integ_alg, format_ikev2_transform_dh_type,
	     p->ike_ts.dh_group);

  crypto_key_size = clib_net_to_host_u32 (p->esp_ts.crypto_key_size);
  if (p->esp_ts.crypto_alg || p->esp_ts.integ_alg)
    fformat (vam->ofp, "  esp-crypto-alg %U %u esp-integ-alg %U\n",
	     format_ikev2_transform_encr_type, p->esp_ts.crypto_alg,
	     crypto_key_size,
	     format_ikev2_transform_integ_type, p->esp_ts.integ_alg);

  fformat (vam->ofp, "  lifetime %d jitter %d handover %d maxdata %d\n",
	   clib_net_to_host_u64 (p->lifetime),
	   clib_net_to_host_u32 (p->lifetime_jitter),
	   clib_net_to_host_u32 (p->handover),
	   clib_net_to_host_u64 (p->lifetime_maxdata));

  vam->result_ready = 1;
}

static int
api_ikev2_sa_dump (vat_main_t * vam)
{
  ikev2_test_main_t *im = &ikev2_test_main;
  vl_api_ikev2_sa_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  /* Construct the API message */
  M (IKEV2_SA_DUMP, mp);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  if (!im->ping_id)
    im->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (im->ping_id);
  mp_ping->client_index = vam->my_client_index;
  vam->result_ready = 0;

  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_ikev2_sa_details_t_handler (vl_api_ikev2_sa_details_t * mp)
{
  vat_main_t *vam = ikev2_test_main.vat_main;
  vl_api_ikev2_sa_t *sa = &mp->sa;
  ip_address_t iaddr;
  ip_address_t raddr;
  vl_api_ikev2_keys_t *k = &sa->keys;
  vl_api_ikev2_sa_t_endian (sa);

  ip_address_decode2 (&sa->iaddr, &iaddr);
  ip_address_decode2 (&sa->raddr, &raddr);

  fformat (vam->ofp, "profile index %d sa index: %d\n",
	   mp->sa.profile_index, mp->sa.sa_index);
  fformat (vam->ofp, " iip %U ispi %lx rip %U rspi %lx\n", format_ip_address,
	   &iaddr, sa->ispi, format_ip_address, &raddr, sa->rspi);
  fformat (vam->ofp, " %U ", format_ikev2_sa_transform, &sa->encryption);
  fformat (vam->ofp, "%U ", format_ikev2_sa_transform, &sa->prf);
  fformat (vam->ofp, "%U ", format_ikev2_sa_transform, &sa->integrity);
  fformat (vam->ofp, "%U \n", format_ikev2_sa_transform, &sa->dh);

  fformat (vam->ofp, "  SK_d    %U\n",
	   format_hex_bytes, k->sk_d, k->sk_d_len);

  fformat (vam->ofp, "  SK_a  i:%U\n        r:%U\n",
	   format_hex_bytes, k->sk_ai, k->sk_ai_len, format_hex_bytes,
	   k->sk_ar, k->sk_ar_len);

  fformat (vam->ofp, "  SK_e  i:%U\n        r:%U\n", format_hex_bytes,
	   k->sk_ei, k->sk_ei_len, format_hex_bytes, k->sk_er, k->sk_er_len);

  fformat (vam->ofp, "  SK_p  i:%U\n        r:%U\n", format_hex_bytes,
	   k->sk_pi, k->sk_pi_len, format_hex_bytes, k->sk_pr, k->sk_pr_len);

  fformat (vam->ofp, "  identifier (i) %U\n",
	   format_ikev2_id_type_and_data, &sa->i_id);
  fformat (vam->ofp, "  identifier (r) %U\n",
	   format_ikev2_id_type_and_data, &sa->r_id);

  vam->result_ready = 1;
}

static int
api_ikev2_child_sa_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  ikev2_test_main_t *im = &ikev2_test_main;
  vl_api_ikev2_child_sa_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;
  u32 sa_index = ~0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sa_index %d", &sa_index))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sa_index == ~0)
    return -99;

  /* Construct the API message */
  M (IKEV2_CHILD_SA_DUMP, mp);

  mp->sa_index = clib_net_to_host_u32 (sa_index);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  if (!im->ping_id)
    im->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (im->ping_id);
  mp_ping->client_index = vam->my_client_index;
  vam->result_ready = 0;

  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_ikev2_child_sa_details_t_handler (vl_api_ikev2_child_sa_details_t * mp)
{
  vat_main_t *vam = ikev2_test_main.vat_main;
  vl_api_ikev2_child_sa_t *child_sa = &mp->child_sa;
  vl_api_ikev2_keys_t *k = &child_sa->keys;
  vl_api_ikev2_child_sa_t_endian (child_sa);

  fformat (vam->ofp, "  child sa %u:\n", child_sa->child_sa_index);

  fformat (vam->ofp, "    %U ", format_ikev2_sa_transform,
	   &child_sa->encryption);
  fformat (vam->ofp, "%U ", format_ikev2_sa_transform, &child_sa->integrity);
  fformat (vam->ofp, "%U \n", format_ikev2_sa_transform, &child_sa->esn);

  fformat (vam->ofp, "    spi(i) %lx spi(r) %lx\n",
	   child_sa->i_spi, child_sa->r_spi);

  fformat (vam->ofp, "    SK_e  i:%U\n          r:%U\n",
	   format_hex_bytes, k->sk_ei, k->sk_ei_len,
	   format_hex_bytes, k->sk_er, k->sk_er_len);
  if (k->sk_ai_len)
    {
      fformat (vam->ofp, "    SK_a  i:%U\n          r:%U\n",
	       format_hex_bytes, k->sk_ai, k->sk_ai_len,
	       format_hex_bytes, k->sk_ar, k->sk_ar_len);
    }
  vam->result_ready = 1;
}

static int
api_ikev2_traffic_selector_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  ikev2_test_main_t *im = &ikev2_test_main;
  vl_api_ikev2_traffic_selector_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int is_initiator = ~0;
  int sa_index = ~0;
  int child_sa_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "initiator"))
	is_initiator = 1;
      else if (unformat (i, "responder"))
	is_initiator = 0;
      else if (unformat (i, "sa_index %d", &sa_index))
	;
      else if (unformat (i, "child_sa_index %d", &child_sa_index))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (child_sa_index == ~0 || sa_index == ~0 || is_initiator == ~0)
    return -99;

  /* Construct the API message */
  M (IKEV2_TRAFFIC_SELECTOR_DUMP, mp);

  mp->is_initiator = is_initiator;
  mp->sa_index = clib_host_to_net_u32 (sa_index);
  mp->child_sa_index = clib_host_to_net_u32 (child_sa_index);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  if (!im->ping_id)
    im->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (im->ping_id);
  mp_ping->client_index = vam->my_client_index;
  vam->result_ready = 0;

  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
  vl_api_ikev2_traffic_selector_details_t_handler
  (vl_api_ikev2_traffic_selector_details_t * mp)
{
  vat_main_t *vam = ikev2_test_main.vat_main;
  vl_api_ikev2_ts_t *ts = &mp->ts;
  ip_address_t start_addr, end_addr;
  vl_api_ikev2_ts_t_endian (ts);

  ip_address_decode2 (&ts->start_addr, &start_addr);
  ip_address_decode2 (&ts->end_addr, &end_addr);

  fformat (vam->ofp, " %s protocol_id %u addr "
	   "%U - %U port %u - %u\n",
	   ts->is_local, ts->protocol_id,
	   format_ip_address, &start_addr,
	   format_ip_address, &end_addr, ts->start_port, ts->end_port);
  vam->result_ready = 1;
}

static int
api_ikev2_nonce_get (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  ikev2_test_main_t *im = &ikev2_test_main;
  vl_api_ikev2_nonce_get_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 is_initiator = ~0;
  u32 sa_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "initiator"))
	is_initiator = 1;
      else if (unformat (i, "responder"))
	is_initiator = 0;
      else if (unformat (i, "sa_index %d", &sa_index))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sa_index == ~0 || is_initiator == ~0)
    return -99;

  /* Construct the API message */
  M (IKEV2_NONCE_GET, mp);

  mp->is_initiator = is_initiator;
  mp->sa_index = clib_host_to_net_u32 (sa_index);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  if (!im->ping_id)
    im->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (im->ping_id);
  mp_ping->client_index = vam->my_client_index;
  vam->result_ready = 0;

  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_ikev2_nonce_get_reply_t_handler (vl_api_ikev2_nonce_get_reply_t * mp)
{
  vat_main_t *vam = ikev2_test_main.vat_main;
  mp->data_len = clib_net_to_host_u32 (mp->data_len);

  fformat (vam->ofp, "  nonce:%U\n",
	   format_hex_bytes, mp->nonce, mp->data_len);

  vam->result_ready = 1;
}

static int
api_ikev2_plugin_get_version (vat_main_t * vam)
{
  ikev2_test_main_t *sm = &ikev2_test_main;
  vl_api_ikev2_plugin_get_version_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_IKEV2_PLUGIN_GET_VERSION + sm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void vl_api_ikev2_plugin_get_version_reply_t_handler
  (vl_api_ikev2_plugin_get_version_reply_t * mp)
{
  vat_main_t *vam = ikev2_test_main.vat_main;
  clib_warning ("IKEv2 plugin version: %d.%d", ntohl (mp->major),
		ntohl (mp->minor));
  vam->result_ready = 1;
}

static int
api_ikev2_profile_set_ipsec_udp_port (vat_main_t * vam)
{
  return 0;
}

static int
api_ikev2_profile_set_liveness (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_set_liveness_t *mp;
  u32 period = 0, max_retries = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (!unformat (i, "period %d max-retries %d", &period, &max_retries))
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IKEV2_PROFILE_SET_LIVENESS, mp);

  mp->period = clib_host_to_net_u32 (period);
  mp->max_retries = clib_host_to_net_u32 (max_retries);

  S (mp);
  W (ret);

  return ret;
}

static int
api_ikev2_profile_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_add_del_t *mp;
  u8 is_add = 1;
  u8 *name = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "name %U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_PROFILE_ADD_DEL, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  mp->is_add = is_add;
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_profile_set_auth (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_set_auth_t *mp;
  u8 *name = 0;
  u8 *data = 0;
  u32 auth_method = 0;
  u8 is_hex = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else if (unformat (i, "auth_method %U",
			 unformat_ikev2_auth_method, &auth_method))
	;
      else if (unformat (i, "auth_data 0x%U", unformat_hex_string, &data))
	is_hex = 1;
      else if (unformat (i, "auth_data %v", &data))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  if (!vec_len (data))
    {
      errmsg ("auth_data must be specified");
      return -99;
    }

  if (!auth_method)
    {
      errmsg ("auth_method must be specified");
      return -99;
    }

  M (IKEV2_PROFILE_SET_AUTH, mp);

  mp->is_hex = is_hex;
  mp->auth_method = (u8) auth_method;
  mp->data_len = vec_len (data);
  clib_memcpy (mp->name, name, vec_len (name));
  clib_memcpy (mp->data, data, vec_len (data));
  vec_free (name);
  vec_free (data);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_profile_set_id (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_set_id_t *mp;
  u8 *name = 0;
  u8 *data = 0;
  u8 is_local = 0;
  u32 id_type = 0;
  ip_address_t ip;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else if (unformat (i, "id_type %U", unformat_ikev2_id_type, &id_type))
	;
      else if (unformat (i, "id_data %U", unformat_ip_address, &ip))
	{
	  data = vec_new (u8, ip_address_size (&ip));
	  clib_memcpy (data, ip_addr_bytes (&ip), ip_address_size (&ip));
	}
      else if (unformat (i, "id_data 0x%U", unformat_hex_string, &data))
	;
      else if (unformat (i, "id_data %v", &data))
	;
      else if (unformat (i, "local"))
	is_local = 1;
      else if (unformat (i, "remote"))
	is_local = 0;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  if (!vec_len (data))
    {
      errmsg ("id_data must be specified");
      return -99;
    }

  if (!id_type)
    {
      errmsg ("id_type must be specified");
      return -99;
    }

  M (IKEV2_PROFILE_SET_ID, mp);

  mp->is_local = is_local;
  mp->id_type = (u8) id_type;
  mp->data_len = vec_len (data);
  clib_memcpy (mp->name, name, vec_len (name));
  clib_memcpy (mp->data, data, vec_len (data));
  vec_free (name);
  vec_free (data);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_profile_set_ts (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_set_ts_t *mp;
  u8 *name = 0;
  u8 is_local = 0;
  u32 proto = 0, start_port = 0, end_port = (u32) ~ 0;
  ip_address_t start_addr, end_addr;
  u8 start_addr_set = 0, end_addr_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else if (unformat (i, "protocol %d", &proto))
	;
      else if (unformat (i, "start_port %d", &start_port))
	;
      else if (unformat (i, "end_port %d", &end_port))
	;
      else
	if (unformat (i, "start_addr %U", unformat_ip_address, &start_addr))
	start_addr_set = 1;
      else if (unformat (i, "end_addr %U", unformat_ip_address, &end_addr))
	end_addr_set = 1;
      else if (unformat (i, "local"))
	is_local = 1;
      else if (unformat (i, "remote"))
	is_local = 0;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!start_addr_set || !end_addr_set)
    {
      errmsg ("missing start or end address");
      return -99;
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_PROFILE_SET_TS, mp);

  mp->ts.is_local = is_local;
  mp->ts.protocol_id = (u8) proto;
  mp->ts.start_port = clib_host_to_net_u16 ((u16) start_port);
  mp->ts.end_port = clib_host_to_net_u16 ((u16) end_port);
  ip_address_encode2 (&start_addr, &mp->ts.start_addr);
  ip_address_encode2 (&end_addr, &mp->ts.end_addr);
  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_set_local_key (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_local_key_t *mp;
  u8 *file = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "file %v", &file))
	vec_add1 (file, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (file))
    {
      errmsg ("RSA key file must be specified");
      return -99;
    }

  if (vec_len (file) > 256)
    {
      errmsg ("file name too long");
      return -99;
    }

  M (IKEV2_SET_LOCAL_KEY, mp);

  clib_memcpy (mp->key_file, file, vec_len (file));
  vec_free (file);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_profile_set_udp_encap (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_set_udp_encap_t *mp;
  int ret;
  u8 *name = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U udp-encap", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_PROFILE_SET_UDP_ENCAP, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_set_tunnel_interface (vat_main_t * vam)
{
  return (0);
}

static int
api_ikev2_set_responder_hostname (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_responder_hostname_t *mp;
  int ret;
  u8 *name = 0, *hn = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U hostname %v", unformat_token, valid_chars, &name,
		    &hn))
	{
	  vec_add1 (name, 0);
	  vec_add1 (hn, 0);
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_SET_RESPONDER_HOSTNAME, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  clib_memcpy (mp->hostname, hn, vec_len (hn));
  vec_free (name);
  vec_free (hn);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_set_responder (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_responder_t *mp;
  int ret;
  u8 *name = 0;
  u32 sw_if_index = ~0;
  ip_address_t address;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (i, "%U interface %d address %U", unformat_token, valid_chars,
	   &name, &sw_if_index, unformat_ip_address, &address))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_SET_RESPONDER, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  mp->responder.sw_if_index = clib_host_to_net_u32 (sw_if_index);
  ip_address_encode2 (&address, &mp->responder.addr);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_set_ike_transforms (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_ike_transforms_t *mp;
  int ret;
  u8 *name = 0;
  u32 crypto_alg, crypto_key_size, integ_alg, dh_group;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U %d %d %d %d", unformat_token, valid_chars, &name,
		    &crypto_alg, &crypto_key_size, &integ_alg, &dh_group))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_SET_IKE_TRANSFORMS, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);
  mp->tr.crypto_alg = crypto_alg;
  mp->tr.crypto_key_size = clib_host_to_net_u32 (crypto_key_size);
  mp->tr.integ_alg = integ_alg;
  mp->tr.dh_group = dh_group;

  S (mp);
  W (ret);
  return ret;
}


static int
api_ikev2_set_esp_transforms (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_esp_transforms_t *mp;
  int ret;
  u8 *name = 0;
  u32 crypto_alg, crypto_key_size, integ_alg;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U %d %d %d", unformat_token, valid_chars, &name,
		    &crypto_alg, &crypto_key_size, &integ_alg))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_SET_ESP_TRANSFORMS, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);
  mp->tr.crypto_alg = crypto_alg;
  mp->tr.crypto_key_size = clib_host_to_net_u32 (crypto_key_size);
  mp->tr.integ_alg = integ_alg;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_set_sa_lifetime (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_sa_lifetime_t *mp;
  int ret;
  u8 *name = 0;
  u64 lifetime, lifetime_maxdata;
  u32 lifetime_jitter, handover;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U %lu %u %u %lu", unformat_token, valid_chars, &name,
		    &lifetime, &lifetime_jitter, &handover,
		    &lifetime_maxdata))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_SET_SA_LIFETIME, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);
  mp->lifetime = lifetime;
  mp->lifetime_jitter = lifetime_jitter;
  mp->handover = handover;
  mp->lifetime_maxdata = lifetime_maxdata;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_initiate_sa_init (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_initiate_sa_init_t *mp;
  int ret;
  u8 *name = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_INITIATE_SA_INIT, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_initiate_del_ike_sa (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_initiate_del_ike_sa_t *mp;
  int ret;
  u64 ispi;


  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%lx", &ispi))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IKEV2_INITIATE_DEL_IKE_SA, mp);

  mp->ispi = ispi;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_initiate_del_child_sa (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_initiate_del_child_sa_t *mp;
  int ret;
  u32 ispi;


  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%x", &ispi))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IKEV2_INITIATE_DEL_CHILD_SA, mp);

  mp->ispi = ispi;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_initiate_rekey_child_sa (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_initiate_rekey_child_sa_t *mp;
  int ret;
  u32 ispi;


  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%x", &ispi))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IKEV2_INITIATE_REKEY_CHILD_SA, mp);

  mp->ispi = ispi;

  S (mp);
  W (ret);
  return ret;
}

#include <ikev2/ikev2.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
