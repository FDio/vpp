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

#include <flowtable/flowtable.h>

#include <vppinfra/byte_order.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#define vl_msg_id(n, h) n,
typedef enum {
#include <flowtable/flowtable.api.h>
    /* We'll want to know how many messages IDs we need... */
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id


/* define message structures */
#define vl_typedefs
#include <flowtable/flowtable.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <flowtable/flowtable.api.h>
#undef vl_endianfun

#define vl_msg_name_crc_list
#include <flowtable/flowtable.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table(flowtable_main_t * ftm, api_main_t * am)
{
#define _(id, n, crc) \
    vl_msg_api_add_msg_name_crc(am, # n "_" # crc, id + ftm->msg_id_base);
    foreach_vl_msg_name_crc_flowtable;
#undef _
}

#define vl_print(handle, ...) vlib_cli_output(handle, __VA_ARGS__)

/* Get the API version number */
#define vl_api_version(n, v) static u32 api_version = (v);
#include <flowtable/flowtable.api.h>
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
        rmp->_vl_msg_id = ntohs((t)+ftm->msg_id_base);              \
        rmp->context = mp->context;                                 \
        rmp->retval = ntohl(rv);                                    \
                                                                \
        vl_msg_api_send_shmem(q, (u8 *)&rmp);                      \
    } while (0);

static void
vl_api_flowtable_conf_t_handler(vl_api_flowtable_conf_t * mp)
{
    flowtable_main_t * ftm = &flowtable_main;
    vl_api_flowtable_conf_reply_t * rmp;
    int rv = 0;
    u32 flows_max = clib_net_to_host_u32(mp->flows_max);

    if (mp->next_node_index != ~0)
        ftm->next_node_index = clib_net_to_host_u32(mp->next_node_index);

    if (mp->sw_if_index != ~0)
        flowtable_enable_disable(ftm, clib_net_to_host_u32(mp->sw_if_index),
                                      mp->enable_disable);

    if (flows_max != ~0 && flows_max != ftm->flows_max) {
        if (ftm->flows_max < flows_max) {
            pool_alloc_aligned(ftm->flows, flows_max - ftm->flows_max, CLIB_CACHE_LINE_BYTES);
        }
        ftm->flows_max = flows_max;
    }

    REPLY_MACRO(VL_API_FLOWTABLE_CONF_REPLY);
}

static void *
vl_api_flowtable_conf_t_print(vl_api_flowtable_conf_t * mp, void * handle)
{
    u8 * s;
    s = format(0, "SCRIPT: flowtable_conf ");

    s = format(s, "%u ", mp->sw_if_index);
    s = format(s, "%u ", mp->enable_disable);

    FINISH;
}

static void
vl_api_flowtable_update_t_handler(vl_api_flowtable_update_t * mp)
{
    int rv;
    flowtable_main_t * ftm = &flowtable_main;
    vl_api_flowtable_update_reply_t * rmp;

    rv = flowtable_update(mp->is_ip4, mp->ip_src, mp->ip_dst,
            mp->ip_upper_proto, mp->port_src, mp->port_dst,
            mp->lifetime, mp->offloaded, mp->infos);

    REPLY_MACRO(VL_API_FLOWTABLE_UPDATE_REPLY);
}

static void *
vl_api_flowtable_update_t_print(vl_api_flowtable_update_t * mp, void * handle)
{
    u8 * s;
    s = format(0, "SCRIPT: flowtable_update ");

    s = format(s, "%u ", mp->is_ip4);
    s = format(s, "%s ", mp->ip_src);
    s = format(s, "%s ", mp->ip_dst);
    s = format(s, "%u ", mp->ip_upper_proto);
    s = format(s, "%u ", mp->port_src);
    s = format(s, "%u ", mp->port_dst);
    s = format(s, "%u ", mp->lifetime);
    s = format(s, "%u ", mp->offloaded);
    s = format(s, "%s ", mp->infos);

    FINISH;
}

/* List of message types that this plugin understands */
#define foreach_flowtable_plugin_api_msg    \
    _(FLOWTABLE_CONF, flowtable_conf)       \
    _(FLOWTABLE_UPDATE, flowtable_update)   \


static clib_error_t *
flowtable_api_init(vlib_main_t * vm)
{
    flowtable_main_t * ftm = &flowtable_main;
    u8 * name = format(0, "flowtable_%08x%c", api_version, 0);
    ftm->msg_id_base = vl_msg_api_get_msg_ids
            ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N, n)                                                  \
    vl_msg_api_set_handlers((VL_API_ ## N + ftm->msg_id_base),    \
            # n,                                  \
            vl_api_ ## n ## _t_handler,              \
            vl_noop_handler,                     \
            vl_api_ ## n ## _t_endian,               \
            vl_api_ ## n ## _t_print,                \
            sizeof(vl_api_ ## n ## _t), 1);
    foreach_flowtable_plugin_api_msg;
#undef _

    /* Add our API messages to the global name_crc hash table */
    setup_message_id_table(ftm, &api_main);

    return 0;
}

VLIB_INIT_FUNCTION(flowtable_api_init);
