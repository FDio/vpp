/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vnet/plugin/plugin.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vpp/app/version.h>

#include <l3span/l3_span.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <l3span/l3_span_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <l3span/l3_span_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <l3span/l3_span_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <l3span/l3_span_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <acl/acl_all_api_h.h>
#undef vl_api_version

#include <vlibapi/api_helper_macros.h>
#include <vnet/fib/fib_api.h>
#include <vnet/fib/fib_table.h>

#define foreach_l3_span_api_msg                                 \
  _(L3_SPAN_ADD_DEL, l3_span_add_del)                           \
  _(L3_SPAN_DUMP, l3_span_dump)

/**
 * L2 Emulation Main
 */
typedef struct l3_span_main_t_
{
  u16 msg_id_base;
} l3_span_main_t;

static l3_span_main_t l3_span_main;

#define L3_SPAN_MSG_BASE l3_span_main.msg_id_base

static void
vl_api_l3_span_add_del_t_handler (vl_api_l3_span_add_del_t * mp)
{
  vl_api_l3_span_add_del_reply_t *rmp;
  fib_route_path_t *rpaths, *rpath;
  fib_prefix_t pfx;
  vnet_main_t *vnm;
  u32 fib_index;
  int rv = 0;
  u8 ii;

  rpaths = NULL;
  vnm = vnet_get_main ();
  vnm->api_errno = 0;

  pfx.fp_len = mp->dst_address_length;

  if (mp->is_ip6)
    {
      pfx.fp_proto = FIB_PROTOCOL_IP6;
      clib_memcpy (&pfx.fp_addr.ip6,
		   mp->dst_address, sizeof (pfx.fp_addr.ip6));
    }
  else
    {
      pfx.fp_proto = FIB_PROTOCOL_IP4;
      clib_memcpy (&pfx.fp_addr.ip4,
		   mp->dst_address, sizeof (pfx.fp_addr.ip4));
    }

  fib_index = fib_table_find (pfx.fp_proto, ntohl (mp->table_id));

  if (~0 == fib_index)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto done;
    }

  vec_validate (rpaths, mp->n_paths - 1);

  vec_foreach_index (ii, rpaths)
  {
    rpath = &rpaths[ii];
    rv = fib_path_api_parse (&mp->paths[ii], rpath);
    if (0 != rv)
      {
	goto done;
      }
  }

  if (mp->is_add)
    {
      l3_span_path_add (fib_index, &pfx, rpaths);
    }
  else
    {
      l3_span_path_remove (fib_index, &pfx, rpaths);
    }

done:
  vec_free (rpaths);
  rv = (rv == 0) ? vnm->api_errno : rv;

  REPLY_MACRO (VL_API_L3_SPAN_ADD_DEL_REPLY + L3_SPAN_MSG_BASE);
}

typedef struct l3_span_ctx_t_
{
  vl_api_registration_t * reg;
  u32 context;
} l3_span_ctx_t;

static int
l3_span_send_details (const l3_span_t *l3s,
                      void *arg)
{
    vl_api_l3_span_details_t *mp;
    l3_span_ctx_t *ctx;
    fib_table_t *ft;

    ctx = arg;
    mp = vl_msg_api_alloc(sizeof(*mp));
    if (!mp)
      return (1);
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_L3_SPAN_DETAILS + L3_SPAN_MSG_BASE);
    mp->context = ctx->context;

    mp->context = ctx->context;
    fib_prefix_to_api (&l3s->l3s_pfx,
                       mp->span.dst_address,
                       &mp->span.dst_address_length,
                       &mp->span.is_ip6);
    ft = fib_table_get (l3s->l3s_fib_index, l3s->l3s_pfx.fp_proto);
    mp->span.table_id = htonl (ft->ft_table_id);

    // FIXME - encode paths
    vl_api_send_msg (ctx->reg, (u8 *) mp);

    return (1);
}

static void
vl_api_l3_span_dump_t_handler (vl_api_l3_span_dump_t * mp)
{
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
      return;

    l3_span_ctx_t ctx = {
      .reg = reg,
      .context = mp->context,
    };

    l3_span_walk(l3_span_send_details, &ctx);
}

/*
 * l2_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <l3span/l3_span_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc)                                     \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + L3_SPAN_MSG_BASE);
  foreach_vl_msg_name_crc_l3_span;
#undef _
}

static void
l3_span_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N + L3_SPAN_MSG_BASE,          \
                            #n,                                 \
                            vl_api_##n##_t_handler,             \
                            vl_noop_handler,                    \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_l3_span_api_msg;
#undef _
}

static clib_error_t *
l3_span_api_init (vlib_main_t * vm)
{
  api_main_t *am = &api_main;
  l3_span_main_t *l3_spanm = &l3_span_main;
  u8 *name = format (0, "l3_span_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  l3_spanm->msg_id_base = vl_msg_api_get_msg_ids ((char *) name,
						  VL_MSG_FIRST_AVAILABLE);

  l3_span_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (am);

  vec_free (name);
  return (NULL);
}

VLIB_API_INIT_FUNCTION (l3_span_api_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
