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

#include <ila/ila.h>

#include <vppinfra/byte_order.h>
#include <vlibapi/api.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

typedef struct
{
  u16 msg_id_base;
} ila_api_main_t;

ila_api_main_t ila_api_main;

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

/* define generated endian-swappers */
#define vl_endianfun
#include <ila/ila.api.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ila/ila.api.h>
#undef vl_api_version

#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+ila_api_main.msg_id_base);      \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

static void
vl_api_ila_iface_t_handler (vl_api_ila_iface_t * mp)
{
  vl_api_ila_iface_reply_t *rmp;
  int rv = 0;
  rv = ila_interface (mp->sw_if_index, !mp->enable);

  REPLY_MACRO (VL_API_ILA_IFACE_REPLY);
}

static void *
vl_api_ila_iface_t_print (vl_api_ila_iface_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: ila_iface ");
  s = format (s, "%d ", mp->sw_if_index);
  s = format (s, "%s", mp->enable ? "enable" : "disable");
  FINISH;
}

static void
vl_api_ila_add_del_entry_t_handler (vl_api_ila_add_del_entry_t * mp)
{
  vl_api_ila_add_del_entry_reply_t *rmp;
  int rv = 0;
  ila_add_del_entry_args_t args;
  args.type = mp->type;
  memcpy (&args.sir_address, mp->sir_address, sizeof (args.sir_address));
  args.locator = mp->locator;
  args.vnid = mp->vnid;
  args.local_adj_index = mp->local_adj_index;
  args.csum_mode = mp->csum_mode;
  args.dir = mp->dir;
  args.is_del = mp->is_del;

  rv = ila_add_del_entry (&args);
  REPLY_MACRO (VL_API_ILA_ADD_DEL_ENTRY_REPLY);
}

static void *vl_api_ila_add_del_entry_t_print
  (vl_api_ila_add_del_entry_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: ila_add_del_entry ");
  s = format (s, "%U ", format_ila_type, mp->type);
  s = format (s, "%U ", format_ip6_address, mp->sir_address);
  s = format (s, "%U ", format_half_ip6_address, mp->locator);
  s = format (s, "%d ", mp->vnid);
  s = format (s, "%d ", mp->local_adj_index);
  s = format (s, "%U ", format_ila_csum_mode, mp->csum_mode);
  s = format (s, "%U ", format_ila_direction, mp->dir);
  s = format (s, "%s ", mp->is_del ? "del" : "add");
  FINISH;
}

/* List of message types that this plugin understands */
#define foreach_ila_plugin_api_msg            \
_(ILA_IFACE, ila_iface)                       \
_(ILA_ADD_DEL_ENTRY, ila_add_del_entry)

static clib_error_t *
ila_api_init (vlib_main_t * vm)
{
  u8 *name = format (0, "ila_%08x%c", api_version, 0);
  ila_api_main.msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + ila_api_main.msg_id_base), \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_ila_plugin_api_msg;
#undef _

  return 0;
}

VLIB_INIT_FUNCTION (ila_api_init);
