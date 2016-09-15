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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>
#include <ila/ila.h>


#define vl_msg_id(n,h) n,
typedef enum
{
#include <ila/ila.api.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <ila/ila.api.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <ila/ila.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <ila/ila.api.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ila/ila.api.h>
#undef vl_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} ila_api_test_main_t;


/*
 * Unformat functions are replicate from ila.c
 *
 */

static uword
unformat_ila_direction (unformat_input_t * input, va_list * args)
{
  ila_direction_t *result = va_arg (*args, ila_direction_t *);
#define _(i,n,s) \
  if (unformat(input, s)) \
      { \
        *result = ILA_DIR_##i; \
        return 1;\
      }

  ila_foreach_direction
#undef _
    return 0;
}

static uword
unformat_ila_type (unformat_input_t * input, va_list * args)
{
  ila_type_t *result = va_arg (*args, ila_type_t *);
#define _(i,n,s) \
  if (unformat(input, s)) \
      { \
        *result = ILA_TYPE_##i; \
        return 1;\
      }

  ila_foreach_type
#undef _
    return 0;
}

static uword
unformat_ila_csum_mode (unformat_input_t * input, va_list * args)
{
  ila_csum_mode_t *result = va_arg (*args, ila_csum_mode_t *);
  if (unformat (input, "none") || unformat (input, "no-action"))
    {
      *result = ILA_CSUM_MODE_NO_ACTION;
      return 1;
    }
  if (unformat (input, "neutral-map"))
    {
      *result = ILA_CSUM_MODE_NEUTRAL_MAP;
      return 1;
    }
  if (unformat (input, "adjust-transport"))
    {
      *result = ILA_CSUM_MODE_ADJUST_TRANSPORT;
      return 1;
    }
  return 0;
}

static uword
unformat_half_ip6_address (unformat_input_t * input, va_list * args)
{
  u64 *result = va_arg (*args, u64 *);
  u32 a[4];

  if (!unformat (input, "%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] > 0xFFFF || a[1] > 0xFFFF || a[2] > 0xFFFF || a[3] > 0xFFFF)
    return 0;

  *result = clib_host_to_net_u64 ((((u64) a[0]) << 48) |
				  (((u64) a[1]) << 32) |
				  (((u64) a[2]) << 16) | (((u64) a[3])));

  return 1;
}

ila_api_test_main_t ila_api_test_main;

#define foreach_standard_reply_retval_handler   \
  _(ila_iface_reply)                  \
  _(ila_add_del_entry_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = ila_api_test_main.vat_main;  \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

#define foreach_vpe_api_reply_msg                               \
  _(ILA_IFACE_REPLY, ila_iface_reply)                           \
  _(ILA_ADD_DEL_ENTRY_REPLY, ila_add_del_entry_reply)

/* M: construct, but don't yet send a message */
#define M(T,t)                                                  \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp));                         \
    memcpy (mp, &mps, sizeof (*mp));                            \
    mp->_vl_msg_id =                                            \
      ntohs (VL_API_##T + ila_api_test_main.msg_id_base);       \
    mp->client_index = vam->my_client_index;                    \
} while(0);

/* S: send a message */
#define S (vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp))

/* W: wait for results, with timeout */
#define W                                       \
do {                                            \
    timeout = vat_time_now (vam) + 1.0;         \
                                                \
    while (vat_time_now (vam) < timeout) {      \
        if (vam->result_ready == 1) {           \
            return (vam->retval);               \
        }                                       \
    }                                           \
    return -99;                                 \
} while(0);

static int
api_ila_iface (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  f64 timeout;
  vl_api_ila_iface_t mps, *mp;

  mps.enable = 1;
  if (!unformat (i, "%u", &mps.sw_if_index))
    {
      errmsg ("invalid arguments\n");
      return -99;
    }

  if (unformat (i, "disable"))
    mps.enable = 0;

  M (ILA_IFACE, ila_iface);
  S;
  W;
  /* NOTREACHED */
  return 0;
}

static int
api_ila_add_del_entry (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  f64 timeout;
  vl_api_ila_add_del_entry_t mps, *mp;

  mps.type = ILA_TYPE_IID;
  mps.csum_mode = ILA_CSUM_MODE_NO_ACTION;
  mps.local_adj_index = ~0;
  mps.dir = ILA_DIR_BIDIR;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "type %U", unformat_ila_type, &mps.type))
	;
      else if (unformat
	       (i, "sir-address %U", unformat_ip6_address, &mps.sir_address))
	;
      else if (unformat
	       (i, "locator %U", unformat_half_ip6_address, &mps.locator))
	;
      else if (unformat (i, "adj-index %u", &mps.local_adj_index))
	;
      else if (unformat
	       (i, "csum-mode %U", unformat_ila_csum_mode, &mps.csum_mode))
	;
      else if (unformat (i, "vnid %x", &mps.vnid))
	;
      else if (unformat (i, "direction %U", unformat_ila_direction, &mps.dir))
	;
      else if (unformat (i, "del"))
	mps.is_del = 1;
      else
	{
	  errmsg ("invalid arguments\n");
	  return -99;
	}
    }

  M (ILA_ADD_DEL_ENTRY, ila_add_del_entry);
  S;
  W;
  /* NOTREACHED */
  return 0;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                             \
_(ila_iface, "<sw-if-index> [disable]")                 \
_(ila_add_del_entry, "[type ("ila_type_list")] [sir-address <address>]" \
" [locator <locator>] [vnid <hex-vnid>]" \
" [adj-index <adj-index>] [direction ("ila_direction_list")]" \
" [csum-mode ("ila_csum_list")] [del]")

void
vat_api_hookup (vat_main_t * vam)
{
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                          \
  vl_msg_api_set_handlers((VL_API_##N + ila_api_test_main.msg_id_base), \
                          #n,                                           \
                          vl_api_##n##_t_handler,                       \
                          vl_noop_handler,                              \
                          vl_api_##n##_t_endian,                        \
                          vl_api_##n##_t_print,                         \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  u8 *name;

  ila_api_test_main.vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "ila_%08x%c", api_version, 0);
  ila_api_test_main.msg_id_base =
    vl_client_get_first_plugin_msg_id ((char *) name);

  if (ila_api_test_main.msg_id_base != (u16) ~ 0)
    vat_api_hookup (vam);

  vec_free (name);
  return 0;
}
