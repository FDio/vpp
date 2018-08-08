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

#include <vppinfra/byte_order.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include "portmirroring.h"

#define vl_msg_id(n, h) n,
typedef enum {
#include <portmirroring/portmirroring.api.h>
    /* We'll want to know how many messages IDs we need... */
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id


/* define message structures */
#define vl_typedefs
#include <portmirroring/portmirroring.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <portmirroring/portmirroring.api.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output(handle, __VA_ARGS__)

#define vl_msg_name_crc_list
#include <portmirroring/portmirroring.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table(pm_main_t * pmm, api_main_t * am)
{
#define _(id, n, crc) \
    vl_msg_api_add_msg_name_crc(am, # n "_" # crc, id + pmm->msg_id_base);
    foreach_vl_msg_name_crc_portmirroring;
#undef _
}

/* Get the API version number */
#define vl_api_version(n, v) static u32 api_version = (v);
#include <portmirroring/portmirroring.api.h>
#undef vl_api_version

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1(s, 0);                            \
    vl_print(handle, (char *)s);               \
    vec_free(s);                               \
    return handle;

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
            vl_api_client_index_to_input_queue(mp->client_index);      \
        if (!q)                                                     \
            return;                                                 \
                                                                \
        rmp = vl_msg_api_alloc(sizeof(*rmp));                     \
        rmp->_vl_msg_id = ntohs((t)+pmm->msg_id_base);               \
        rmp->context = mp->context;                                 \
        rmp->retval = ntohl(rv);                                    \
                                                                \
        vl_msg_api_send_shmem(q, (u8 *)&rmp);                      \
    } while (0);

static void
vl_api_pm_conf_t_handler(vl_api_pm_conf_t * mp)
{
    pm_main_t * pmm = &pm_main;
    vl_api_pm_conf_reply_t * rmp;
    int rv = 0;

    rv = pm_conf(mp->dst_interface, mp->is_del);

    REPLY_MACRO(VL_API_PM_CONF_REPLY);
}

static void *
vl_api_pm_conf_t_print(vl_api_pm_conf_t * mp, void * handle)
{
    u8 * s;
    s = format(0, "SCRIPT: pm_conf ");
    s = format(s, "%u ", mp->dst_interface);
    s = format(s, "%s ", (mp->is_del ? "DELETE" : "ADD"));
    FINISH;
}

/* List of message types that this plugin understands */
#define foreach_pm_plugin_api_msg            \
    _(PM_CONF, pm_conf)                          \


static clib_error_t *
pm_api_init(vlib_main_t * vm)
{
    pm_main_t * pmm = &pm_main;
    u8 * name = format(0, "portmirroring_%08x%c", api_version, 0);
    pmm->msg_id_base = vl_msg_api_get_msg_ids
            ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N, n)                                                  \
    vl_msg_api_set_handlers((VL_API_ ## N + pmm->msg_id_base),     \
            # n,                  \
            vl_api_ ## n ## _t_handler,              \
            vl_noop_handler,                     \
            vl_api_ ## n ## _t_endian,               \
            vl_api_ ## n ## _t_print,                \
            sizeof(vl_api_ ## n ## _t), 1);
    foreach_pm_plugin_api_msg;
#undef _

    /* Add our API messages to the global name_crc hash table */
    setup_message_id_table(pmm, &api_main);


    return 0;
}

VLIB_INIT_FUNCTION(pm_api_init);
