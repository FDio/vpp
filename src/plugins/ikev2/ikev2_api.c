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
#include <plugins/ikev2/ikev2_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <ikev2/ikev2_all_api.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <ikev2/ikev2_all_api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ikev2/ikev2_all_api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ikev2/ikev2_all_api.h>
#undef vl_api_version

extern ikev2_main_t ikev2_main;

#define IKEV2_PLUGIN_VERSION_MAJOR 1
#define IKEV2_PLUGIN_VERSION_MINOR 0
#define REPLY_MSG_ID_BASE ikev2_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#define foreach_ikev2_api_msg                                   \
_(IKEV2_PLUGIN_GET_VERSION, ikev2_plugin_get_version)           \
_(IKEV2_PROFILE_ADD_DEL, ikev2_profile_add_del)                 \
_(IKEV2_PROFILE_SET_AUTH, ikev2_profile_set_auth)               \
_(IKEV2_PROFILE_SET_ID, ikev2_profile_set_id)                   \
_(IKEV2_PROFILE_SET_TS, ikev2_profile_set_ts)                   \
_(IKEV2_SET_LOCAL_KEY, ikev2_set_local_key)                     \
_(IKEV2_SET_RESPONDER, ikev2_set_responder)                     \
_(IKEV2_SET_IKE_TRANSFORMS, ikev2_set_ike_transforms)           \
_(IKEV2_SET_ESP_TRANSFORMS, ikev2_set_esp_transforms)           \
_(IKEV2_SET_SA_LIFETIME, ikev2_set_sa_lifetime)                 \
_(IKEV2_INITIATE_SA_INIT, ikev2_initiate_sa_init)               \
_(IKEV2_INITIATE_DEL_IKE_SA, ikev2_initiate_del_ike_sa)         \
_(IKEV2_INITIATE_DEL_CHILD_SA, ikev2_initiate_del_child_sa)     \
_(IKEV2_INITIATE_REKEY_CHILD_SA, ikev2_initiate_rekey_child_sa)

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
 * ikev2_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <ikev2/ikev2_all_api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (ikev2_main_t * im, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + im->msg_id_base);
  foreach_vl_msg_name_crc_ikev2;
#undef _
}

static clib_error_t *
ikev2_plugin_api_hookup (vlib_main_t * vm)
{
  ikev2_main_t *im = &ikev2_main;
#define _(N,n)                                                  \
  vl_msg_api_set_handlers(VL_API_##N + im->msg_id_base, #n,     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_ikev2_api_msg;
#undef _

  return (NULL);
}

static clib_error_t *
ikev2_api_init (vlib_main_t * vm)
{
  ikev2_main_t *im = &ikev2_main;
  clib_error_t *error = 0;
  u8 *name;

  name = format (0, "ikev2_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  im->msg_id_base = vl_msg_api_get_msg_ids ((char *) name,
					    VL_MSG_FIRST_AVAILABLE);

  error = ikev2_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (im, &api_main);

  vec_free (name);

  return (error);
}

VLIB_INIT_FUNCTION (ikev2_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
