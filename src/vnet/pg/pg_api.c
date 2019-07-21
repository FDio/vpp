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
_(PG_CAPTURE_TIMEOUT, pg_capture_timeout)                               \
_(PG_CAPTURE_DUMP, pg_capture_dump)                                     \
_(PG_ENABLE_DISABLE, pg_enable_disable)

static void
vl_api_pg_create_interface_t_handler (vl_api_pg_create_interface_t * mp)
{
  vl_api_pg_create_interface_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 pg_if_id = pg_interface_add_or_get (pg, ntohl (mp->interface_id));
  pg_interface_t *pi = pool_elt_at_index (pg->interfaces, pg_if_id);
  u8 *interface_name =
    format (0, "%U%c", format_pg_interface_name, pg_if_id, 0);
  u32 size = vec_len (interface_name);

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_PG_CREATE_INTERFACE_REPLY, size,
  ({
	rmp->sw_if_index = ntohl(pi->sw_if_index);
	vl_api_vec_to_api_string(interface_name, &rmp->interface_name);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_pg_capture_t_handler (vl_api_pg_capture_t * mp)
{
  vl_api_pg_capture_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  pg_main_t *pg = &pg_main;
  vnet_hw_interface_t *hi = 0;

  u32 hw_if_index = ~0;
  uword *p = hash_get (pg->if_index_by_if_id, ntohl (mp->interface_id));
  if (p)
    hw_if_index = *p;

  if (hw_if_index != ~0)
    {
      pg_capture_args_t _a, *a = &_a;

      a->pcap_file_name =
	format (0, "%v%c", vl_api_from_api_to_vec (&mp->pcap_file_name), 0);

      hi = vnet_get_sup_hw_interface (vnm, hw_if_index);
      a->hw_if_index = hw_if_index;
      a->dev_instance = hi->dev_instance;
      a->is_enabled = mp->is_enabled;
      a->count = ntohl (mp->count);

      clib_error_t *e = pg_capture (a);
      if (e)
	{
	  clib_error_report (e);
	  rv = VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE;
	}


    }
  REPLY_MACRO (VL_API_PG_CAPTURE_REPLY);
}

static void
vl_api_pg_capture_timeout_t_handler (vl_api_pg_capture_timeout_t * mp)
{
  vl_api_pg_capture_timeout_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  pg_main_t *pg = &pg_main;
  pg_interface_t *pi;
  int rv = 0;
  vnet_hw_interface_t *hi =
    vnet_get_sup_hw_interface (vnm, ntohl (mp->sw_if_index));
  pi = pool_elt_at_index (pg->interfaces, ntohl (hi->dev_instance));
  pi->timeout = clib_net_to_host_f64 (mp->timeout);

  REPLY_MACRO (VL_API_PG_CAPTURE_TIMEOUT_REPLY);

}

static void
send_pg_capture_details (vl_api_registration_t * reg, u32 context,
			 pg_interface_t * pif)
{
  u32 msg_size;

  vl_api_pg_capture_details_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = 0;
  hi = vnet_get_sup_hw_interface (vnm, pif->hw_if_index);
  u8 *pg_interface_name =
    format (0, "%U%c", format_pg_interface_name, hi->dev_instance, 0);

  msg_size =
    sizeof (*rmp) + strlen (pif->pcap_main.file_name) +
    vec_len (pg_interface_name);

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id = ntohs (VL_API_PG_CAPTURE_DETAILS);

  rmp->context = context;
  rmp->sw_if_index = htonl (pif->sw_if_index);
  rmp->hw_if_index = htonl (pif->hw_if_index);
  rmp->n_packets_to_capture = htonl (pif->pcap_main.n_packets_to_capture);
  rmp->packet_type = htonl (pif->pcap_main.packet_type);
  rmp->n_packets_captured = htonl (pif->pcap_main.n_packets_captured);
  rmp->flags = htonl (pif->pcap_main.flags);
  rmp->file_descriptor = htonl (pif->pcap_main.file_descriptor);
  rmp->n_pcap_data_written = htonl (pif->pcap_main.n_pcap_data_written);
  rmp->min_packet_bytes = htonl (pif->pcap_main.min_packet_bytes);
  rmp->max_packet_bytes = htonl (pif->pcap_main.max_packet_bytes);
  rmp->status = pif->state;
  rmp->enable_timestamp = clib_host_to_net_f64 (pif->enable_timestamp);
  rmp->disable_timestamp = clib_host_to_net_f64 (pif->disable_timestamp);
  rmp->timeout = clib_host_to_net_f64 (pif->timeout);

  char *p = (char *) &rmp->interface_name;

  p += vl_api_vec_to_api_string (pg_interface_name, (vl_api_string_t *) p);
  p +=
    vl_api_to_api_string (strlen (pif->pcap_main.file_name),
			  pif->pcap_main.file_name, (vl_api_string_t *) p);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_pg_capture_dump_t_handler (vl_api_pg_capture_dump_t * mp)
{
  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pg_main_t *pg = &pg_main;
  vnet_main_t *vnm = vnet_get_main ();
  pg_interface_t *pi;
  u32 hw_if_index = ~0;

  hw_if_index = ntohl (mp->sw_if_index);

  if (hw_if_index != ~0)
    {
      vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, hw_if_index);
      pi = pool_elt_at_index (pg->interfaces, ntohl (hi->dev_instance));
      send_pg_capture_details (reg, mp->context, pi);
    }
  else
    {

  /* *INDENT-OFF* */
  pool_foreach (pi, pg->interfaces,
  ({
    send_pg_capture_details(reg, mp->context, pi);
  }));
  /* *INDENT-ON* */
    }
}

static void
vl_api_pg_enable_disable_t_handler (vl_api_pg_enable_disable_t * mp)
{
  vl_api_pg_enable_disable_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 stream_index = ~0;

  int is_enable = mp->is_enabled != 0;

  if (vl_api_string_len (&mp->stream_name) > 0)
    {
      u8 *stream_name;
      stream_name = vl_api_from_api_to_vec (&mp->stream_name);
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
