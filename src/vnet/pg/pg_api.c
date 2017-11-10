/*
 *------------------------------------------------------------------
 * pg_api.c - vnet pg api
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

#include <vnet/pg/pg.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>


#define foreach_pg_api_msg                                              \
_(PG_CREATE_INTERFACE, pg_create_interface)                             \
_(PG_CAPTURE, pg_capture)                                               \
_(PG_ENABLE_DISABLE, pg_enable_disable)

extern void stats_dslock_with_hint (int hint, int tag);
extern void stats_dsunlock (void);

static void
vl_api_pg_create_interface_t_handler (vl_api_pg_create_interface_t * mp)
{
  vl_api_pg_create_interface_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 pg_if_id = pg_interface_add_or_get (pg, ntohl (mp->interface_id));
  pg_interface_t *pi = pool_elt_at_index (pg->interfaces, pg_if_id);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PG_CREATE_INTERFACE_REPLY,
  ({
    rmp->sw_if_index = ntohl(pi->sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_pg_capture_t_handler (vl_api_pg_capture_t * mp)
{
  vl_api_pg_capture_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = 0;

  u8 *intf_name = format (0, "pg%d", ntohl (mp->interface_id), 0);
  vec_terminate_c_string (intf_name);
  u32 hw_if_index = ~0;
  uword *p = hash_get_mem (im->hw_interface_by_name, intf_name);
  if (p)
    hw_if_index = *p;
  vec_free (intf_name);

  if (hw_if_index != ~0)
    {
      pg_capture_args_t _a, *a = &_a;

      u32 len = ntohl (mp->pcap_name_length);
      u8 *pcap_file_name = vec_new (u8, len);
      clib_memcpy (pcap_file_name, mp->pcap_file_name, len);

      hi = vnet_get_sup_hw_interface (vnm, hw_if_index);
      a->hw_if_index = hw_if_index;
      a->dev_instance = hi->dev_instance;
      a->is_enabled = mp->is_enabled;
      a->pcap_file_name = pcap_file_name;
      a->count = ntohl (mp->count);

      clib_error_t *e = pg_capture (a);
      if (e)
	{
	  clib_error_report (e);
	  rv = VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE;
	}

      vec_free (pcap_file_name);
    }
  REPLY_MACRO (VL_API_PG_CAPTURE_REPLY);
}

static void
vl_api_pg_enable_disable_t_handler (vl_api_pg_enable_disable_t * mp)
{
  vl_api_pg_enable_disable_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 stream_index = ~0;

  int is_enable = mp->is_enabled != 0;
  u32 len = ntohl (mp->stream_name_length) - 1;

  if (len > 0)
    {
      u8 *stream_name = vec_new (u8, len);
      clib_memcpy (stream_name, mp->stream_name, len);
      uword *p = hash_get_mem (pg->stream_index_by_name, stream_name);
      if (p)
	stream_index = *p;
      vec_free (stream_name);
    }

  pg_enable_disable (stream_index, is_enable);

  REPLY_MACRO (VL_API_PG_ENABLE_DISABLE_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/pg/pg.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_pg;
#undef _
}

static clib_error_t *
pg_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_pg_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (pg_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
