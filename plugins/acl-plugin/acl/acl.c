/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <acl/acl.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <acl/acl_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <acl/acl_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <acl/acl_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <acl/acl_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <acl/acl_all_api_h.h>
#undef vl_api_version

static void
noop_handler (void *notused)
{
}

#define vl_api_acl_add_t_endian noop_handler
#define vl_api_acl_add_t_print noop_handler

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


/* List of message types that this plugin understands */

#define foreach_acl_plugin_api_msg		\
_(ACL_ADD, acl_add)				\
_(ACL_DEL, acl_del)				\
_(ACL_INTERFACE_ADD_DEL, acl_interface_add_del)	\
_(ACL_DUMP, acl_dump)

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
  acl_main_t * am = &acl_main;
  clib_error_t * error = 0;

  am->vlib_main = vm;
  am->vnet_main = h->vnet_main;
  am->ethernet_main = h->ethernet_main;

  return error;
}

/* API message handler */
static void
vl_api_acl_add_t_handler (vl_api_acl_add_t * mp)
{
}
static void
vl_api_acl_del_t_handler (vl_api_acl_del_t * mp)
{
}
static void
vl_api_acl_interface_add_del_t_handler (vl_api_acl_interface_add_del_t * mp)
{
}
static void
vl_api_acl_dump_t_handler (vl_api_acl_dump_t * mp)
{
}

/* Set up the API message handling tables */
static clib_error_t *
acl_plugin_api_hookup (vlib_main_t *vm)
{
  acl_main_t * sm = &acl_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_acl_plugin_api_msg;
#undef _

    return 0;
}

static clib_error_t *
acl_init (vlib_main_t * vm)
{
  acl_main_t * am = &acl_main;
  clib_error_t * error = 0;
  u8 * name;

  name = format (0, "acl_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  am->msg_id_base = vl_msg_api_get_msg_ids ((char *) name,
					    VL_MSG_FIRST_AVAILABLE);

  error = acl_plugin_api_hookup (vm);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (acl_init);
