/*
 * nsh_api.c - nsh mapping api
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <nsh/nsh.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#define vl_msg_id(n,h) n,
typedef enum
{
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

#define REPLY_MSG_ID_BASE nm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_nsh_plugin_api_msg		\
  _(NSH_ADD_DEL_ENTRY, nsh_add_del_entry)	\
  _(NSH_ENTRY_DUMP, nsh_entry_dump)             \
  _(NSH_ADD_DEL_MAP, nsh_add_del_map)           \
  _(NSH_MAP_DUMP, nsh_map_dump)

/**
 * @brief CLI function for NSH admin up/down
 *
 * @param *vnm
 * @param nsh_hw_if
 * @param flag
 *
 * @return *rc
 *
 */
static clib_error_t *
nsh_interface_admin_up_down (vnet_main_t * vnm, u32 nsh_hw_if, u32 flags)
{
  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, nsh_hw_if,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, nsh_hw_if, 0);

  return 0;
}

/**
 * @brief Naming for NSH tunnel
 *
 * @param *s formatting string
 * @param *args
 *
 * @return *s formatted string
 *
 */
static u8 *
format_nsh_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "nsh_tunnel%d", dev_instance);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (nsh_device_class, static) = {
  .name = "NSH",
  .format_device_name = format_nsh_name,
  .admin_up_down_function = nsh_interface_admin_up_down,
};
/* *INDENT-ON* */

static void send_nsh_entry_details
  (nsh_entry_t * t, vl_api_registration_t * rp, u32 context)
{
  vl_api_nsh_entry_details_t *rmp;
  nsh_main_t *nm = &nsh_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs ((VL_API_NSH_ENTRY_DETAILS) + nm->msg_id_base);
  rmp->ver_o_c = t->nsh_base.ver_o_c;
  rmp->ttl = (t->nsh_base.ver_o_c & NSH_TTL_H4_MASK) << 2 |
    (t->nsh_base.length & NSH_TTL_L2_MASK) >> 6;
  rmp->length = t->nsh_base.length & NSH_LEN_MASK;
  rmp->md_type = t->nsh_base.md_type;
  rmp->next_protocol = t->nsh_base.next_protocol;
  rmp->nsp_nsi = htonl (t->nsh_base.nsp_nsi);

  if (t->nsh_base.md_type == 1)
    {
      rmp->tlv_length = 4;
      rmp->c1 = htonl (t->md.md1_data.c1);
      rmp->c2 = htonl (t->md.md1_data.c2);
      rmp->c3 = htonl (t->md.md1_data.c3);
      rmp->c4 = htonl (t->md.md1_data.c4);
    }
  else if (t->nsh_base.md_type == 2)
    {
      rmp->tlv_length = t->tlvs_len;
      clib_memcpy (rmp->tlv, t->tlvs_data, t->tlvs_len);
    }

  rmp->context = context;

  vl_api_send_msg (rp, (u8 *) rmp);
}

static void send_nsh_map_details
  (nsh_map_t * t, vl_api_registration_t * rp, u32 context)
{
  vl_api_nsh_map_details_t *rmp;
  nsh_main_t *nm = &nsh_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs ((VL_API_NSH_MAP_DETAILS) + nm->msg_id_base);
  rmp->nsp_nsi = htonl (t->nsp_nsi);
  rmp->mapped_nsp_nsi = htonl (t->mapped_nsp_nsi);
  rmp->nsh_action = htonl (t->nsh_action);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->rx_sw_if_index = htonl (t->rx_sw_if_index);
  rmp->next_node = htonl (t->next_node);

  rmp->context = context;

  vl_api_send_msg (rp, (u8 *) rmp);
}

static void
vl_api_nsh_map_dump_t_handler (vl_api_nsh_map_dump_t * mp)
{
  nsh_main_t *nm = &nsh_main;
  nsh_map_t *t;
  u32 map_index;
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  map_index = ntohl (mp->map_index);

  if (~0 == map_index)
    {
      pool_foreach (t, nm->nsh_mappings, (
					   {
					   send_nsh_map_details (t, rp,
								 mp->context);
					   }
		    ));
    }
  else
    {
      if (map_index >= vec_len (nm->nsh_mappings))
	{
	  return;
	}
      t = &nm->nsh_mappings[map_index];
      send_nsh_map_details (t, rp, mp->context);
    }
}

/** API message handler */
static void
vl_api_nsh_add_del_map_t_handler (vl_api_nsh_add_del_map_t * mp)
{
  vl_api_nsh_add_del_map_reply_t *rmp;
  nsh_main_t *nm = &nsh_main;
  int rv;
  nsh_add_del_map_args_t _a, *a = &_a;
  u32 map_index = ~0;

  a->is_add = mp->is_add;
  a->map.nsp_nsi = ntohl (mp->nsp_nsi);
  a->map.mapped_nsp_nsi = ntohl (mp->mapped_nsp_nsi);
  a->map.nsh_action = ntohl (mp->nsh_action);
  a->map.sw_if_index = ntohl (mp->sw_if_index);
  a->map.rx_sw_if_index = ntohl (mp->rx_sw_if_index);
  a->map.next_node = ntohl (mp->next_node);

  rv = nsh_add_del_map (a, &map_index);

  if ((a->map.next_node == NSH_NODE_NEXT_ENCAP_VXLAN4)
      | (a->map.next_node == NSH_NODE_NEXT_ENCAP_VXLAN6))
    {
      rv = nsh_add_del_proxy_session (a);
    }

  REPLY_MACRO2 (VL_API_NSH_ADD_DEL_MAP_REPLY, (
						{
						rmp->map_index =
						htonl (map_index);
						}
		));
}

int
nsh_header_rewrite (nsh_entry_t * nsh_entry)
{
  u8 *rw = 0;
  int len = 0;
  nsh_base_header_t *nsh_base;
  nsh_md1_data_t *nsh_md1;
  nsh_main_t *nm = &nsh_main;
  nsh_md2_data_t *opt0;
  nsh_md2_data_t *limit0;
  nsh_md2_data_t *nsh_md2;
  nsh_option_map_t _nsh_option, *nsh_option = &_nsh_option;
  u8 old_option_size = 0;
  u8 new_option_size = 0;

  vec_free (nsh_entry->rewrite);
  if (nsh_entry->nsh_base.md_type == 1)
    {
      len = sizeof (nsh_base_header_t) + sizeof (nsh_md1_data_t);
    }
  else if (nsh_entry->nsh_base.md_type == 2)
    {
      /* set to maxim, maybe dataplane will add more TLVs */
      len = MAX_NSH_HEADER_LEN;
    }
  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);
  clib_memset (rw, 0, len);

  nsh_base = (nsh_base_header_t *) rw;
  nsh_base->ver_o_c = nsh_entry->nsh_base.ver_o_c;
  nsh_base->length = nsh_entry->nsh_base.length;
  nsh_base->md_type = nsh_entry->nsh_base.md_type;
  nsh_base->next_protocol = nsh_entry->nsh_base.next_protocol;
  nsh_base->nsp_nsi = clib_host_to_net_u32 (nsh_entry->nsh_base.nsp_nsi);

  if (nsh_base->md_type == 1)
    {
      nsh_md1 = (nsh_md1_data_t *) (rw + sizeof (nsh_base_header_t));
      nsh_md1->c1 = clib_host_to_net_u32 (nsh_entry->md.md1_data.c1);
      nsh_md1->c2 = clib_host_to_net_u32 (nsh_entry->md.md1_data.c2);
      nsh_md1->c3 = clib_host_to_net_u32 (nsh_entry->md.md1_data.c3);
      nsh_md1->c4 = clib_host_to_net_u32 (nsh_entry->md.md1_data.c4);
      nsh_entry->rewrite_size = 24;
    }
  else if (nsh_base->md_type == 2)
    {
      opt0 = (nsh_md2_data_t *) (nsh_entry->tlvs_data);
      limit0 = (nsh_md2_data_t *) ((u8 *) opt0 + nsh_entry->tlvs_len);

      nsh_md2 = (nsh_md2_data_t *) (rw + sizeof (nsh_base_header_t));
      nsh_entry->rewrite_size = sizeof (nsh_base_header_t);

      while (opt0 < limit0)
	{
	  old_option_size = sizeof (nsh_md2_data_t) + opt0->length;
	  /* round to 4-byte */
	  old_option_size = ((old_option_size + 3) >> 2) << 2;

	  nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
	  if (nsh_option == NULL)
	    {
	      goto next_tlv_md2;
	    }

	  if (nm->add_options[nsh_option->option_id] != NULL)
	    {
	      if (0 != nm->add_options[nsh_option->option_id] ((u8 *) nsh_md2,
							       &new_option_size))
		{
		  goto next_tlv_md2;
		}

	      /* round to 4-byte */
	      new_option_size = ((new_option_size + 3) >> 2) << 2;

	      nsh_entry->rewrite_size += new_option_size;
	      nsh_md2 =
		(nsh_md2_data_t *) (((u8 *) nsh_md2) + new_option_size);
	      opt0 = (nsh_md2_data_t *) (((u8 *) opt0) + old_option_size);
	    }
	  else
	    {
	    next_tlv_md2:
	      opt0 = (nsh_md2_data_t *) (((u8 *) opt0) + old_option_size);
	    }

	}
    }

  nsh_entry->rewrite = rw;
  nsh_base->length = (nsh_base->length & NSH_TTL_L2_MASK) |
    ((nsh_entry->rewrite_size >> 2) & NSH_LEN_MASK);

  return 0;
}

extern vnet_hw_interface_class_t nsh_hw_class;

/**
 * Action function to add or del an nsh map.
 * Shared by both CLI and binary API
 **/
int
nsh_add_del_map (nsh_add_del_map_args_t * a, u32 * map_indexp)
{
  nsh_main_t *nm = &nsh_main;
  vnet_main_t *vnm = nm->vnet_main;
  nsh_map_t *map = 0;
  u32 key, *key_copy;
  uword *entry;
  hash_pair_t *hp;
  u32 map_index = ~0;
  vnet_hw_interface_t *hi;
  u32 nsh_hw_if = ~0;
  u32 nsh_sw_if = ~0;

  /* net order, so data plane could use nsh header to lookup directly */
  key = clib_host_to_net_u32 (a->map.nsp_nsi);

  entry = hash_get_mem (nm->nsh_mapping_by_key, &key);

  if (a->is_add)
    {
      /* adding an entry, must not already exist */
      if (entry)
	return -1;		//TODO API_ERROR_INVALID_VALUE;

      pool_get_aligned (nm->nsh_mappings, map, CLIB_CACHE_LINE_BYTES);
      clib_memset (map, 0, sizeof (*map));

      /* copy from arg structure */
      map->nsp_nsi = a->map.nsp_nsi;
      map->mapped_nsp_nsi = a->map.mapped_nsp_nsi;
      map->nsh_action = a->map.nsh_action;
      map->sw_if_index = a->map.sw_if_index;
      map->rx_sw_if_index = a->map.rx_sw_if_index;
      map->next_node = a->map.next_node;
      map->adj_index = a->map.adj_index;


      key_copy = clib_mem_alloc (sizeof (*key_copy));
      clib_memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (nm->nsh_mapping_by_key, key_copy, map - nm->nsh_mappings);
      map_index = map - nm->nsh_mappings;

      if (vec_len (nm->free_nsh_tunnel_hw_if_indices) > 0)
	{
	  nsh_hw_if = nm->free_nsh_tunnel_hw_if_indices
	    [vec_len (nm->free_nsh_tunnel_hw_if_indices) - 1];
	  _vec_len (nm->free_nsh_tunnel_hw_if_indices) -= 1;

	  hi = vnet_get_hw_interface (vnm, nsh_hw_if);
	  hi->dev_instance = map_index;
	  hi->hw_instance = hi->dev_instance;
	}
      else
	{
	  nsh_hw_if = vnet_register_interface
	    (vnm, nsh_device_class.index, map_index, nsh_hw_class.index,
	     map_index);
	  hi = vnet_get_hw_interface (vnm, nsh_hw_if);
	  hi->output_node_index = nsh_aware_vnf_proxy_node.index;
	}

      map->nsh_hw_if = nsh_hw_if;
      map->nsh_sw_if = nsh_sw_if = hi->sw_if_index;
      vec_validate_init_empty (nm->tunnel_index_by_sw_if_index, nsh_sw_if,
			       ~0);
      nm->tunnel_index_by_sw_if_index[nsh_sw_if] = key;

      vnet_sw_interface_set_flags (vnm, hi->sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    }
  else
    {
      if (!entry)
	return -2;		//TODO API_ERROR_NO_SUCH_ENTRY;

      map = pool_elt_at_index (nm->nsh_mappings, entry[0]);

      vnet_sw_interface_set_flags (vnm, map->nsh_sw_if,
				   VNET_SW_INTERFACE_FLAG_ADMIN_DOWN);
      vec_add1 (nm->free_nsh_tunnel_hw_if_indices, map->nsh_sw_if);
      nm->tunnel_index_by_sw_if_index[map->nsh_sw_if] = ~0;

      hp = hash_get_pair (nm->nsh_mapping_by_key, &key);
      key_copy = (void *) (hp->key);
      hash_unset_mem (nm->nsh_mapping_by_key, &key);
      clib_mem_free (key_copy);

      pool_put (nm->nsh_mappings, map);
    }

  if (map_indexp)
    *map_indexp = map_index;

  return 0;
}

/**
 * Action function to add or del an nsh-proxy-session.
 * Shared by both CLI and binary API
 **/
int
nsh_add_del_proxy_session (nsh_add_del_map_args_t * a)
{
  nsh_main_t *nm = &nsh_main;
  nsh_proxy_session_t *proxy = 0;
  nsh_proxy_session_by_key_t key, *key_copy;
  uword *entry;
  hash_pair_t *hp;
  u32 nsp = 0, nsi = 0;

  clib_memset (&key, 0, sizeof (key));
  key.transport_type = a->map.next_node;
  key.transport_index = a->map.sw_if_index;

  entry = hash_get_mem (nm->nsh_proxy_session_by_key, &key);

  if (a->is_add)
    {
      /* adding an entry, must not already exist */
      if (entry)
	return -1;		//TODO API_ERROR_INVALID_VALUE;

      pool_get_aligned (nm->nsh_proxy_sessions, proxy, CLIB_CACHE_LINE_BYTES);
      clib_memset (proxy, 0, sizeof (*proxy));

      /* Nsi needs to minus 1 within NSH-Proxy */
      nsp = (a->map.nsp_nsi >> NSH_NSP_SHIFT) & NSH_NSP_MASK;
      nsi = a->map.nsp_nsi & NSH_NSI_MASK;
      if (nsi == 0)
	return -1;

      nsi = nsi - 1;
      /* net order, so could use it to lookup nsh map table directly */
      proxy->nsp_nsi = clib_host_to_net_u32 ((nsp << NSH_NSP_SHIFT) | nsi);

      key_copy = clib_mem_alloc (sizeof (*key_copy));
      clib_memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (nm->nsh_proxy_session_by_key, key_copy,
		    proxy - nm->nsh_proxy_sessions);
    }
  else
    {
      if (!entry)
	return -2;		//TODO API_ERROR_NO_SUCH_ENTRY;

      proxy = pool_elt_at_index (nm->nsh_proxy_sessions, entry[0]);
      hp = hash_get_pair (nm->nsh_proxy_session_by_key, &key);
      key_copy = (void *) (hp->key);
      hash_unset_mem (nm->nsh_proxy_session_by_key, &key);
      clib_mem_free (key_copy);

      pool_put (nm->nsh_proxy_sessions, proxy);
    }

  return 0;
}

/**
 * Action function for adding an NSH entry
 * nsh_add_del_entry_args_t *a: host order
 */
int
nsh_add_del_entry (nsh_add_del_entry_args_t * a, u32 * entry_indexp)
{
  nsh_main_t *nm = &nsh_main;
  nsh_entry_t *nsh_entry = 0;
  u32 key, *key_copy;
  uword *entry_id;
  hash_pair_t *hp;
  u32 entry_index = ~0;
  u8 tlvs_len = 0;
  u8 *data = 0;

  /* host order, because nsh map table stores nsp_nsi in host order */
  key = a->nsh_entry.nsh_base.nsp_nsi;

  entry_id = hash_get_mem (nm->nsh_entry_by_key, &key);

  if (a->is_add)
    {
      /* adding an entry, must not already exist */
      if (entry_id)
	return -1;		// TODO VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned (nm->nsh_entries, nsh_entry, CLIB_CACHE_LINE_BYTES);
      clib_memset (nsh_entry, 0, sizeof (*nsh_entry));

      /* copy from arg structure */
#define _(x) nsh_entry->nsh_base.x = a->nsh_entry.nsh_base.x;
      foreach_copy_nsh_base_hdr_field;
#undef _

      if (a->nsh_entry.nsh_base.md_type == 1)
	{
	  nsh_entry->md.md1_data.c1 = a->nsh_entry.md.md1_data.c1;
	  nsh_entry->md.md1_data.c2 = a->nsh_entry.md.md1_data.c2;
	  nsh_entry->md.md1_data.c3 = a->nsh_entry.md.md1_data.c3;
	  nsh_entry->md.md1_data.c4 = a->nsh_entry.md.md1_data.c4;
	}
      else if (a->nsh_entry.nsh_base.md_type == 2)
	{
	  vec_free (nsh_entry->tlvs_data);
	  tlvs_len = a->nsh_entry.tlvs_len;
	  vec_validate_aligned (data, tlvs_len - 1, CLIB_CACHE_LINE_BYTES);

	  clib_memcpy (data, a->nsh_entry.tlvs_data, tlvs_len);
	  nsh_entry->tlvs_data = data;
	  nsh_entry->tlvs_len = tlvs_len;
	  vec_free (a->nsh_entry.tlvs_data);
	}

      nsh_header_rewrite (nsh_entry);

      key_copy = clib_mem_alloc (sizeof (*key_copy));
      clib_memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (nm->nsh_entry_by_key, key_copy,
		    nsh_entry - nm->nsh_entries);
      entry_index = nsh_entry - nm->nsh_entries;
    }
  else
    {
      if (!entry_id)
	return -2;		//TODO API_ERROR_NO_SUCH_ENTRY;

      nsh_entry = pool_elt_at_index (nm->nsh_entries, entry_id[0]);
      hp = hash_get_pair (nm->nsh_entry_by_key, &key);
      key_copy = (void *) (hp->key);
      hash_unset_mem (nm->nsh_entry_by_key, &key);
      clib_mem_free (key_copy);

      vec_free (nsh_entry->tlvs_data);
      vec_free (nsh_entry->rewrite);
      pool_put (nm->nsh_entries, nsh_entry);
    }

  if (entry_indexp)
    *entry_indexp = entry_index;

  return 0;
}


/** API message handler */
static void vl_api_nsh_add_del_entry_t_handler
  (vl_api_nsh_add_del_entry_t * mp)
{
  vl_api_nsh_add_del_entry_reply_t *rmp;
  nsh_main_t *nm = &nsh_main;
  int rv;
  nsh_add_del_entry_args_t _a, *a = &_a;
  u32 entry_index = ~0;
  u8 tlvs_len = 0;
  u8 *data = 0;

  a->is_add = mp->is_add;
  a->nsh_entry.nsh_base.ver_o_c =
    (mp->ver_o_c & 0xF0) | ((mp->ttl & NSH_LEN_MASK) >> 2);
  a->nsh_entry.nsh_base.length =
    (mp->length & NSH_LEN_MASK) | ((mp->ttl & 0x3) << 6);
  a->nsh_entry.nsh_base.md_type = mp->md_type;
  a->nsh_entry.nsh_base.next_protocol = mp->next_protocol;
  a->nsh_entry.nsh_base.nsp_nsi = ntohl (mp->nsp_nsi);
  if (mp->md_type == 1)
    {
      a->nsh_entry.md.md1_data.c1 = ntohl (mp->c1);
      a->nsh_entry.md.md1_data.c2 = ntohl (mp->c2);
      a->nsh_entry.md.md1_data.c3 = ntohl (mp->c3);
      a->nsh_entry.md.md1_data.c4 = ntohl (mp->c4);
    }
  else if (mp->md_type == 2)
    {
      tlvs_len = mp->tlv_length;
      vec_validate_aligned (data, tlvs_len - 1, CLIB_CACHE_LINE_BYTES);

      clib_memcpy (data, mp->tlv, tlvs_len);
      a->nsh_entry.tlvs_data = data;
      a->nsh_entry.tlvs_len = tlvs_len;
    }

  rv = nsh_add_del_entry (a, &entry_index);

  REPLY_MACRO2 (VL_API_NSH_ADD_DEL_ENTRY_REPLY, (
						  {
						  rmp->entry_index =
						  htonl (entry_index);
						  }
		));
}

static void
vl_api_nsh_entry_dump_t_handler (vl_api_nsh_entry_dump_t * mp)
{
  nsh_main_t *nm = &nsh_main;
  nsh_entry_t *t;
  u32 entry_index;
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  entry_index = ntohl (mp->entry_index);

  if (~0 == entry_index)
    {
      pool_foreach (t, nm->nsh_entries, (
					  {
					  send_nsh_entry_details (t, rp,
								  mp->context);
					  }
		    ));
    }
  else
    {
      if (entry_index >= vec_len (nm->nsh_entries))
	{
	  return;
	}
      t = &nm->nsh_entries[entry_index];
      send_nsh_entry_details (t, rp, mp->context);
    }
}

static void
setup_message_id_table (nsh_main_t * nm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + nm->msg_id_base);
  foreach_vl_msg_name_crc_nsh;
#undef _
}

/* Set up the API message handling tables */
static clib_error_t *
nsh_plugin_api_hookup (vlib_main_t * vm)
{
  nsh_main_t *nm __attribute__ ((unused)) = &nsh_main;
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + nm->msg_id_base),	\
			  #n,					\
			  vl_api_##n##_t_handler,		\
			  vl_noop_handler,			\
			  vl_api_##n##_t_endian,		\
			  vl_api_##n##_t_print,			\
			  sizeof(vl_api_##n##_t), 1);
  foreach_nsh_plugin_api_msg;
#undef _

  return 0;
}

clib_error_t *
nsh_api_init (vlib_main_t * vm, nsh_main_t * nm)
{
  clib_error_t *error;
  u8 *name;

  name = format (0, "nsh_%08x%c", api_version, 0);

  /* Set up the API */
  nm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = nsh_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (nm, &api_main);

  vec_free (name);

  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
