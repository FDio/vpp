/*
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
 */

#include <snort/snort.h>

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <snort/snort_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <memif/memif_all_api_h.h>
#include <snort/snort_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <memif/memif_all_api_h.h>
#include <snort/snort_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <memif/memif_all_api_h.h>
#include <snort/snort_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <snort/snort_all_api_h.h>
#undef vl_api_version

/* Get CRC codes of memif*/
#define vl_msg_name_crc_list
#include <memif/memif_all_api_h.h>
#undef vl_msg_name_crc_list

#define vl_msg_id(n,h) n,
typedef enum
{
#include <memif/memif_all_api_h.h>
} vl_memif_msg_id_t;
#undef vl_msg_id

#define vl_msg_name_crc_list
#include <snort/snort_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (snort_main_t * mm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + mm->msg_id_base);
  foreach_vl_msg_name_crc_snort;
#undef _
}

#define foreach_snort_plugin_api_msg		\

/* Set up the API message handling tables */
clib_error_t *
snort_plugin_api_hookup (vlib_main_t * vm)
{
  snort_main_t *sm = snort_get_main ();
  api_main_t *am = &api_main;
  u8 *name;

  name = format (0, "snort_%08x%c", api_version, 0);
  sm->msg_id_base = vl_msg_api_get_msg_ids ((char *) name,
	                                    VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_snort_plugin_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (sm, am);
  vec_free (name);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
