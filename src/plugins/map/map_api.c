/*
 *------------------------------------------------------------------
 * map_api.c - vnet map api
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

#include <map/map.h>
#include <map/map_msg_enum.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>
#include <vlibmemory/api.h>

#define vl_typedefs		/* define message structures */
#include <map/map_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <map/map_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <map/map_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <map/map_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE mm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_map_add_domain_t_handler (vl_api_map_add_domain_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_add_domain_reply_t *rmp;
  int rv = 0;
  u32 index;
  u8 flags = 0;

  rv =
    map_create_domain ((ip4_address_t *) & mp->ip4_prefix.prefix,
		       mp->ip4_prefix.len,
		       (ip6_address_t *) & mp->ip6_prefix.prefix,
		       mp->ip6_prefix.len,
		       (ip6_address_t *) & mp->ip6_src.prefix,
		       mp->ip6_src.len, mp->ea_bits_len, mp->psid_offset,
		       mp->psid_length, &index, ntohs (mp->mtu), flags);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MAP_ADD_DOMAIN_REPLY,
  ({
    rmp->index = ntohl(index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_map_del_domain_t_handler (vl_api_map_del_domain_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_del_domain_reply_t *rmp;
  int rv = 0;

  rv = map_delete_domain (ntohl (mp->index));

  REPLY_MACRO (VL_API_MAP_DEL_DOMAIN_REPLY);
}

static void
vl_api_map_add_del_rule_t_handler (vl_api_map_add_del_rule_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_del_domain_reply_t *rmp;
  int rv = 0;

  rv =
    map_add_del_psid (ntohl (mp->index), ntohs (mp->psid),
		      (ip6_address_t *) & mp->ip6_dst, mp->is_add);

  REPLY_MACRO (VL_API_MAP_ADD_DEL_RULE_REPLY);
}

static void
vl_api_map_domain_dump_t_handler (vl_api_map_domain_dump_t * mp)
{
  vl_api_map_domain_details_t *rmp;
  map_main_t *mm = &map_main;
  map_domain_t *d;
  vl_api_registration_t *reg;

  if (pool_elts (mm->domains) == 0)
    return;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach(d, mm->domains,
  ({
    /* Make sure every field is initiated (or don't skip the clib_memset()) */
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = htons(VL_API_MAP_DOMAIN_DETAILS + mm->msg_id_base);
    rmp->context = mp->context;
    rmp->domain_index = htonl(d - mm->domains);
    clib_memcpy(&rmp->ip6_prefix.prefix, &d->ip6_prefix, sizeof(rmp->ip6_prefix));
    clib_memcpy(&rmp->ip4_prefix.prefix, &d->ip4_prefix, sizeof(rmp->ip4_prefix));
    clib_memcpy(&rmp->ip6_src.prefix, &d->ip6_src, sizeof(rmp->ip6_src));
    rmp->ip6_prefix.len = d->ip6_prefix_len;
    rmp->ip4_prefix.len = d->ip4_prefix_len;
    rmp->ip6_src.len = d->ip6_src_len;
    rmp->ea_bits_len = d->ea_bits_len;
    rmp->psid_offset = d->psid_offset;
    rmp->psid_length = d->psid_length;
    rmp->flags = d->flags;
    rmp->mtu = htons(d->mtu);

    vl_api_send_msg (reg, (u8 *) rmp);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_map_rule_dump_t_handler (vl_api_map_rule_dump_t * mp)
{
  vl_api_registration_t *reg;
  u16 i;
  ip6_address_t dst;
  vl_api_map_rule_details_t *rmp;
  map_main_t *mm = &map_main;
  u32 domain_index = ntohl (mp->domain_index);
  map_domain_t *d;

  if (pool_elts (mm->domains) == 0)
    return;

  d = pool_elt_at_index (mm->domains, domain_index);
  if (!d || !d->rules)
    {
      return;
    }

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  for (i = 0; i < (0x1 << d->psid_length); i++)
    {
      dst = d->rules[i];
      if (dst.as_u64[0] == 0 && dst.as_u64[1] == 0)
	{
	  continue;
	}
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id = ntohs (VL_API_MAP_RULE_DETAILS + mm->msg_id_base);
      rmp->psid = htons (i);
      clib_memcpy (&rmp->ip6_dst.address, &dst, sizeof (rmp->ip6_dst));
      rmp->context = mp->context;
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_map_if_enable_disable_t_handler (vl_api_map_if_enable_disable_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_if_enable_disable_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    map_if_enable_disable (mp->is_enable, htonl (mp->sw_if_index),
			   mp->is_translation);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_MAP_IF_ENABLE_DISABLE_REPLY);
}

static void
vl_api_map_params_t_handler (vl_api_map_params_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_params_reply_t *rmp;
  int rv = 0;			/* Used by REPLY_MACRO */

  mm->tcp_mss = ntohs (mp->tcp_mss);
  REPLY_MACRO (VL_API_MAP_PARAMS_REPLY);
}

#define foreach_map_plugin_api_msg		\
_(MAP_ADD_DOMAIN, map_add_domain)		\
_(MAP_DEL_DOMAIN, map_del_domain)		\
_(MAP_ADD_DEL_RULE, map_add_del_rule)		\
_(MAP_DOMAIN_DUMP, map_domain_dump)		\
_(MAP_RULE_DUMP, map_rule_dump)			\
_(MAP_IF_ENABLE_DISABLE, map_if_enable_disable) \
_(MAP_PARAMS, map_params)

#define vl_msg_name_crc_list
#include <map/map_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (map_main_t * mm, api_main_t * am)
{
#define _(id,n,crc)							\
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + mm->msg_id_base);
  foreach_vl_msg_name_crc_map;
#undef _
}

/* Set up the API message handling tables */
clib_error_t *
map_plugin_api_hookup (vlib_main_t * vm)
{
  map_main_t *mm = &map_main;
  u8 *name = format (0, "map_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  mm->msg_id_base =
    vl_msg_api_get_msg_ids ((char *) name, VL_MSG_FIRST_AVAILABLE);
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + mm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_map_plugin_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (mm, &api_main);

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
