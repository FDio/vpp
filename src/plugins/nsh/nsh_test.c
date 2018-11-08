/*
 * nsh.c - skeleton vpp-api-test plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vppinfra/error.h>
#include <nsh/nsh.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* define message IDs */
#define vl_msg_id(n,h) n,
typedef enum {
#include <nsh/nsh.api.h>
    /* We'll want to know how many messages IDs we need... */
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <nsh/nsh.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <nsh/nsh.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <nsh/nsh.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <nsh/nsh.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <nsh/nsh.api.h>
#undef vl_msg_name_crc_list


typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} nsh_test_main_t;

nsh_test_main_t nsh_test_main;

#define foreach_standard_reply_retval_handler   \
_(nsh_add_del_entry_reply)			\
_(nsh_add_del_map_reply)			\

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = nsh_test_main.vat_main;   \
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

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                                       \
_(NSH_ADD_DEL_ENTRY_REPLY, nsh_add_del_entry_reply)			\
_(NSH_ENTRY_DETAILS, nsh_entry_details)                                 \
_(NSH_ADD_DEL_MAP_REPLY, nsh_add_del_map_reply)                         \
_(NSH_MAP_DETAILS, nsh_map_details)


/* M: construct, but don't yet send a message */

#define M(T,t)                                                  \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp));                         \
    clib_memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + sm->msg_id_base);      \
    mp->client_index = vam->my_client_index;                    \
} while(0);

#define M2(T,t,n)                                               \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp)+(n));                     \
    clib_memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + sm->msg_id_base);      \
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

static int api_nsh_add_del_entry (vat_main_t * vam)
{
    nsh_test_main_t * sm = &nsh_test_main;
    unformat_input_t * line_input = vam->input;
    f64 timeout;
    u8 is_add = 1;
    u8 ver_o_c = 0;
    u8 length = 0;
    u8 md_type = 0;
    u8 next_protocol = 1; /* default: ip4 */
    u32 nsp;
    u8 nsp_set = 0;
    u32 nsi;
    u8 nsi_set = 0;
    u32 nsp_nsi;
    u32 c1 = 0;
    u32 c2 = 0;
    u32 c3 = 0;
    u32 c4 = 0;
    u32 tmp;
    vl_api_nsh_add_del_entry_t * mp;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "version %d", &tmp))
	ver_o_c |= (tmp & 3) << 6;
      else if (unformat (line_input, "o-bit %d", &tmp))
	ver_o_c |= (tmp & 1) << 5;
      else if (unformat (line_input, "c-bit %d", &tmp))
	ver_o_c |= (tmp & 1) << 4;
      else if (unformat (line_input, "md-type %d", &tmp))
	md_type = tmp;
      else if (unformat(line_input, "next-ip4"))
	next_protocol = 1;
      else if (unformat(line_input, "next-ip6"))
	next_protocol = 2;
      else if (unformat(line_input, "next-ethernet"))
	next_protocol = 3;
      else if (unformat (line_input, "c1 %d", &c1))
	;
      else if (unformat (line_input, "c2 %d", &c2))
	;
      else if (unformat (line_input, "c3 %d", &c3))
	;
      else if (unformat (line_input, "c4 %d", &c4))
	;
      else if (unformat (line_input, "nsp %d", &nsp))
	nsp_set = 1;
      else if (unformat (line_input, "nsi %d", &nsi))
	nsi_set = 1;
      else
	return -99; // PARSE ERROR;
    }

    unformat_free (line_input);

    if (nsp_set == 0)
      return -1; //TODO Error type for this cond: clib_error_return (0, "nsp not specified");

    if (nsi_set == 0)
      return -2; //TODO Error type for this cond:clib_error_return (0, "nsi not specified");

    if (md_type == 1)
      length = 6;
    else if (md_type == 2)
      length = 2;  /* base header length */

    nsp_nsi = (nsp<<8) | nsi;

    /* Construct the API message */
    M(NSH_ADD_DEL_ENTRY, nsh_add_del_entry);
    mp->is_add = is_add;

#define _(x) mp->x = x;
    foreach_copy_nsh_base_hdr_field;
#undef _


    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static void vl_api_nsh_entry_details_t_handler
(vl_api_nsh_entry_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp, "%11d%11d%11d%11d%14d%14d%14d%14d%14d\n",
            mp->ver_o_c,
            mp->length,
	    mp->md_type,
	    mp->next_protocol,
            ntohl(mp->nsp_nsi),
	    ntohl(mp->c1),
	    ntohl(mp->c2),
	    ntohl(mp->c3),
            ntohl(mp->c4));
}

static int api_nsh_entry_dump (vat_main_t * vam)
{
    nsh_test_main_t * sm = &nsh_test_main;
    vl_api_nsh_entry_dump_t *mp;
    f64 timeout;

    if (!vam->json_output) {
        fformat(vam->ofp, "%11s%11s%15s%14s%14s%13s%13s%13s%13s\n",
                "ver_o_c", "length", "md_type", "next_protocol",
                "nsp_nsi", "c1", "c2", "c3", "c4");
    }

    /* Get list of nsh entries */
    M(NSH_ENTRY_DUMP, nsh_entry_dump);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_nsh_add_del_map (vat_main_t * vam)
{
    nsh_test_main_t * sm = &nsh_test_main;
    unformat_input_t * line_input = vam->input;
    f64 timeout;
    u8 is_add = 1;
    u32 nsp, nsi, mapped_nsp, mapped_nsi;
    int nsp_set = 0, nsi_set = 0, mapped_nsp_set = 0, mapped_nsi_set = 0;
    u32 next_node = ~0;
    u32 sw_if_index = ~0; // temporary requirement to get this moved over to NSHSFC
    vl_api_nsh_add_del_map_t * mp;


    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "nsp %d", &nsp))
	nsp_set = 1;
      else if (unformat (line_input, "nsi %d", &nsi))
	nsi_set = 1;
      else if (unformat (line_input, "mapped-nsp %d", &mapped_nsp))
	mapped_nsp_set = 1;
      else if (unformat (line_input, "mapped-nsi %d", &mapped_nsi))
	mapped_nsi_set = 1;
      else if (unformat (line_input, "encap-gre4-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_GRE4;
      else if (unformat (line_input, "encap-gre6-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_GRE6;
      else if (unformat (line_input, "encap-vxlan-gpe-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_VXLANGPE;
      else if (unformat (line_input, "encap-none"))
	next_node = NSH_NODE_NEXT_DROP; // Once moved to NSHSFC see nsh.h:foreach_nsh_input_next to handle this case
      else
	return -99; //TODO clib_error_return (0, "parse error: '%U'",
    }

    unformat_free (line_input);

    if (nsp_set == 0 || nsi_set == 0)
      return -1; // TODO create return value: clib_error_return (0, "nsp nsi pair required. Key: for NSH entry");

    if (mapped_nsp_set == 0 || mapped_nsi_set == 0)
      return -2; // TODO create return valuee clib_error_return (0, "mapped-nsp mapped-nsi pair required. Key: for NSH entry");

    if (next_node == ~0)
      return -3; //TODO clib_error_return (0, "must specific action: [encap-gre-intf <nn> | encap-vxlan-gpe-intf <nn> | encap-none]");


    M(NSH_ADD_DEL_MAP, nsh_add_del_map);
    /* set args structure */
    mp->is_add = is_add;
    mp->nsp_nsi = (nsp<< NSH_NSP_SHIFT) | nsi;
    mp->mapped_nsp_nsi = (mapped_nsp<< NSH_NSP_SHIFT) | mapped_nsi;
    mp->sw_if_index = sw_if_index;
    mp->next_node = next_node;

    /* send it... */
    S;

    /* Wait for a reply... */
    W;


}

static void vl_api_nsh_map_details_t_handler
(vl_api_nsh_map_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp, "%14d%14d%14d%14d\n",
            ntohl(mp->nsp_nsi),
	    ntohl(mp->mapped_nsp_nsi),
	    ntohl(mp->sw_if_index),
	    ntohl(mp->next_node));
}

static int api_nsh_map_dump (vat_main_t * vam)
{
    nsh_test_main_t * sm = &nsh_test_main;
    vl_api_nsh_map_dump_t *mp;
    f64 timeout;

    if (!vam->json_output) {
        fformat(vam->ofp, "%16s%16s%13s%13s\n",
                "nsp_nsi", "mapped_nsp_nsi", "sw_if_index", "next_node");
    }

    /* Get list of nsh entries */
    M(NSH_MAP_DUMP, nsh_map_dump);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(nsh_add_del_entry, "{nsp <nn> nsi <nn>} c1 <nn> c2 <nn> c3 <nn> c4 <nn> [md-type <nn>] [tlv <xx>] [del]") \
_(nsh_entry_dump, "")   \
_(nsh_add_del_map, "nsp <nn> nsi <nn> [del] mapped-nsp <nn> mapped-nsi <nn> [encap-gre-intf <nn> | encap-vxlan-gpe-intf <nn> | encap-none]")  \
_(nsh_map_dump, "")

static void
nsh_vat_api_hookup (vat_main_t *vam)
{
    nsh_test_main_t * sm = &nsh_test_main;
    /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
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

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  nsh_test_main_t * sm = &nsh_test_main;
  u8 * name;

  sm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "nsh_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~0)
    nsh_vat_api_hookup (vam);

  vec_free(name);

  return 0;
}
