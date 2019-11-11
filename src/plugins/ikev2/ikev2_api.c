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

#include <ikev2/ikev2.h>
#include <ikev2/ikev2_priv.h>

/* define message IDs */
#include <plugins/ikev2/ikev2.api_enum.h>
#include <plugins/ikev2/ikev2.api_types.h>

extern ikev2_main_t ikev2_main;

#define IKEV2_PLUGIN_VERSION_MAJOR 1
#define IKEV2_PLUGIN_VERSION_MINOR 0
#define REPLY_MSG_ID_BASE ikev2_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

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
  vl_api_ikev2_profile_add_del_reply_t *rmp;
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
vl_api_ikev2_profile_set_ts_t_handler (vl_api_ikev2_profile_set_ts_t * mp)
{
  vl_api_ikev2_profile_set_ts_reply_t *rmp;
  int rv = 0;

#if WITH_LIBSSL > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  error =
    ikev2_set_profile_ts (vm, tmp, mp->proto,
			  clib_net_to_host_u16 (mp->start_port),
			  clib_net_to_host_u16 (mp->end_port),
			  (ip4_address_t) mp->start_addr,
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

  error = ikev2_set_profile_responder (vm, tmp, ntohl (mp->sw_if_index), ip4);
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
    ikev2_set_profile_ike_transforms (vm, tmp, ntohl (mp->crypto_alg),
				      ntohl (mp->integ_alg),
				      ntohl (mp->dh_group),
				      ntohl (mp->crypto_key_size));
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
    ikev2_set_profile_esp_transforms (vm, tmp, ntohl (mp->crypto_alg),
				      ntohl (mp->integ_alg),
				      ntohl (mp->dh_group),
				      ntohl (mp->crypto_key_size));
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
				   clib_net_to_host_f64 (mp->lifetime),
				   ntohl (mp->lifetime_jitter),
				   ntohl (mp->handover),
				   clib_net_to_host_f64
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
