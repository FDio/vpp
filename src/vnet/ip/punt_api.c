/*
 *------------------------------------------------------------------
 * punt_api.c - Punt api
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
#include <vnet/ip/punt.h>

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

#define foreach_punt_api_msg                                            \
_(SET_PUNT, set_punt)                                                   \
_(PUNT_SOCKET_REGISTER, punt_socket_register)                           \
_(PUNT_SOCKET_DEREGISTER, punt_socket_deregister)                       \
_(PUNT_DUMP, punt_dump)                                                 \
_(PUNT_SOCKET_DUMP, punt_socket_dump)

static void
vl_api_set_punt_t_handler (vl_api_set_punt_t * mp)
{
  vl_api_set_punt_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;
  clib_error_t *error;

  error = vnet_punt_add_del (vm, mp->punt.ipv, mp->punt.l4_protocol,
			     ntohs (mp->punt.l4_port), mp->is_add);
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

  REPLY_MACRO (VL_API_SET_PUNT_REPLY);
}

static void
vl_api_punt_dump_t_handler (vl_api_punt_dump_t * mp)
{

}

static void
vl_api_punt_socket_register_t_handler (vl_api_punt_socket_register_t * mp)
{
  vl_api_punt_socket_register_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;
  clib_error_t *error;
  vl_api_registration_t *reg;

  error = vnet_punt_socket_add (vm, ntohl (mp->header_version),
				mp->punt.ipv, mp->punt.l4_protocol,
				ntohs (mp->punt.l4_port),
				(char *) mp->pathname);
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_PUNT_SOCKET_REGISTER_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  char *p = vnet_punt_get_server_pathname ();
  /* Abstract pathnames start with \0 */
  memcpy ((char *) rmp->pathname, p, sizeof (rmp->pathname));
  vl_api_send_msg (reg, (u8 *) rmp);
}

void
send_punt_socket_details (vl_api_registration_t * reg,
			  u32 context, punt_socket_detail_t * p)
{
  vl_api_punt_socket_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return;

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_PUNT_SOCKET_DETAILS);
  mp->context = context;
  mp->punt.ipv = p->ipv;
  mp->punt.l4_protocol = p->l4_protocol;
  mp->punt.l4_port = htons (p->l4_port);
  memcpy (mp->pathname, p->pathname, sizeof (p->pathname));

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_punt_socket_dump_t_handler (vl_api_punt_socket_dump_t * mp)
{
  vl_api_registration_t *reg;
  punt_socket_detail_t *p, *ps;
  int rv __attribute__ ((unused)) = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ps = punt_socket_entries (mp->is_ipv6);
  /* *INDENT-OFF* */
  vec_foreach (p, ps)
  {
    send_punt_socket_details (reg, mp->context, p);
  }
  /* *INDENT-ON* */
  vec_free (ps);
}

static void
vl_api_punt_socket_deregister_t_handler (vl_api_punt_socket_deregister_t * mp)
{
  vl_api_punt_socket_deregister_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;
  clib_error_t *error;
  vl_api_registration_t *reg;

  error = vnet_punt_socket_del (vm, mp->punt.ipv, mp->punt.l4_protocol,
				ntohs (mp->punt.l4_port));
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_PUNT_SOCKET_DEREGISTER_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  vl_api_send_msg (reg, (u8 *) rmp);
}

#define vl_msg_name_crc_list
#include <vnet/ip/punt.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_punt;
#undef _
}

static clib_error_t *
punt_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_punt_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (punt_api_hookup);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
