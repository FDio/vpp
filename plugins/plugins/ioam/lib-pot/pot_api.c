/*
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
 */
/*
 *------------------------------------------------------------------
 * pot_api.c - Proof of Transit related APIs to create 
 *             and maintain profiles
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <plugins/ioam/lib-pot/pot_util.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <plugins/ioam/lib-pot/pot_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <plugins/ioam/lib-pot/pot_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <plugins/ioam/lib-pot/pot_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <plugins/ioam/lib-pot/pot_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <plugins/ioam/lib-pot/pot_all_api_h.h>
#undef vl_api_version

/* 
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+sm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO2(t, body)                                   \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t));                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

/* List of message types that this plugin understands */

#define foreach_pot_plugin_api_msg                                      \
_(POT_PROFILE_ADD, pot_profile_add)                                     \
_(POT_PROFILE_ACTIVATE, pot_profile_activate)                           \
_(POT_PROFILE_DEL, pot_profile_del)                                     \

static void vl_api_pot_profile_add_t_handler
(vl_api_pot_profile_add_t *mp)
{
    pot_main_t * sm = &pot_main;
    int rv = 0;
    vl_api_pot_profile_add_reply_t * rmp;
    u8 id;
    pot_profile *profile = NULL;
    u8 *name = 0;

    if (mp->list_name_len)
        name = format(0, "%s", mp->list_name);

    pot_profile_list_init(name);
    id = mp->id;
    profile = pot_profile_find(id);
    if (profile) {
	rv = pot_profile_create(profile,
				clib_net_to_host_u64(mp->prime),
				clib_net_to_host_u64(mp->polynomial_public),
				clib_net_to_host_u64(mp->lpc),
				clib_net_to_host_u64(mp->secret_share));
	if (rv != 0)
            goto ERROROUT;
	if (1 == mp->validator)
	  (void)pot_set_validator(profile, clib_net_to_host_u64(mp->secret_key));
        (void)pot_profile_set_bit_mask(profile, mp->max_bits);
    } else {
        rv = -3;
    }  
 ERROROUT:
    vec_free(name);
    REPLY_MACRO(VL_API_POT_PROFILE_ADD_REPLY);
}

static void vl_api_pot_profile_activate_t_handler
(vl_api_pot_profile_activate_t *mp)
{
    pot_main_t * sm = &pot_main;
    int rv = 0;
    vl_api_pot_profile_add_reply_t * rmp;
    u8 id;
    u8 *name = NULL;

    if (mp->list_name_len)
        name = format(0, "%s", mp->list_name);
    if (!pot_profile_list_is_enabled(name)) {
        rv = -1;
    } else {
        id = mp->id;
	rv = pot_profile_set_active(id);
    }
     
    vec_free(name);
    REPLY_MACRO(VL_API_POT_PROFILE_ACTIVATE_REPLY);
}


static void vl_api_pot_profile_del_t_handler
(vl_api_pot_profile_del_t *mp)
{
    pot_main_t * sm = &pot_main;
    int rv = 0;
    vl_api_pot_profile_del_reply_t * rmp;

    clear_pot_profiles();

    REPLY_MACRO(VL_API_POT_PROFILE_DEL_REPLY);
}


/* 
 * This routine exists to convince the vlib plugin framework that
 * we haven't accidentally copied a random .dll into the plugin directory.
 *
 * Also collects global variable pointers passed from the vpp engine
 */

clib_error_t * 
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
  pot_main_t * sm = &pot_main;
  clib_error_t * error = 0;

  sm->vlib_main = vm;
  sm->vnet_main = h->vnet_main;
  return error;
}

/* Set up the API message handling tables */
static clib_error_t *
pot_plugin_api_hookup (vlib_main_t *vm)
{
  pot_main_t * sm = &pot_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_pot_plugin_api_msg;
#undef _

    return 0;
}

static clib_error_t * pot_init (vlib_main_t * vm)
{
  pot_main_t * sm = &pot_main;
  clib_error_t * error = 0;
  u8 * name;

  bzero(sm, sizeof(pot_main));
  (void)pot_util_init();
  name = format (0, "pot_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = pot_plugin_api_hookup (vm);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (pot_init);
