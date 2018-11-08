/*
 * nsh.c - nsh mapping
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
#include <vnet/gre/gre.h>
#include <vnet/vxlan/vxlan.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/l2/l2_classify.h>
#include <vnet/adj/adj.h>

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

/*  Dummy Eth header */
const char dummy_dst_address[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
const char dummy_src_address[6] = { 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc };

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define REPLY_MACRO(t)                                          \
  do {								\
    unix_shared_memory_queue_t * q =                            \
      vl_api_client_index_to_input_queue (mp->client_index);	\
    if (!q)                                                     \
      return;							\
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+nm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
  } while(0);

#define REPLY_MACRO2(t, body)                                   \
  do {                                                          \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+nm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
  } while(0);

#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

/* List of message types that this plugin understands */

#define foreach_nsh_plugin_api_msg		\
  _(NSH_ADD_DEL_ENTRY, nsh_add_del_entry)	\
  _(NSH_ENTRY_DUMP, nsh_entry_dump)             \
  _(NSH_ADD_DEL_MAP, nsh_add_del_map)           \
  _(NSH_MAP_DUMP, nsh_map_dump)

 /* Uses network order's class and type to register */
int
nsh_md2_register_option (u16 class,
			 u8 type,
			 u8 option_size,
			 int add_options (u8 * opt,
					  u8 * opt_size),
			 int options (vlib_buffer_t * b,
				      nsh_tlv_header_t * opt),
			 int swap_options (vlib_buffer_t * b,
					   nsh_tlv_header_t * old_opt,
					   nsh_tlv_header_t * new_opt),
			 int pop_options (vlib_buffer_t * b,
					  nsh_tlv_header_t * opt),
			 u8 * trace (u8 * s, nsh_tlv_header_t * opt))
{
  nsh_main_t *nm = &nsh_main;
  nsh_option_map_by_key_t key, *key_copy;
  uword *p;
  nsh_option_map_t *nsh_option;

  key.class = class;
  key.type = type;
  key.pad = 0;

  p = hash_get_mem (nm->nsh_option_map_by_key, &key);
  /* Already registered */
  if (p != 0)
    {
      return (-1);
    }

  pool_get_aligned (nm->nsh_option_mappings, nsh_option,
		    CLIB_CACHE_LINE_BYTES);
  clib_memset (nsh_option, 0, sizeof (*nsh_option));
  nsh_option->option_id = nsh_option - nm->nsh_option_mappings;

  key_copy = clib_mem_alloc (sizeof (*key_copy));
  clib_memcpy (key_copy, &key, sizeof (*key_copy));
  hash_set_mem (nm->nsh_option_map_by_key, key_copy,
		nsh_option - nm->nsh_option_mappings);

  if (option_size > (MAX_NSH_OPTION_LEN + sizeof (nsh_tlv_header_t)))
    {
      return (-1);
    }
  nm->options_size[nsh_option->option_id] = option_size;
  nm->add_options[nsh_option->option_id] = add_options;
  nm->options[nsh_option->option_id] = options;
  nm->swap_options[nsh_option->option_id] = swap_options;
  nm->pop_options[nsh_option->option_id] = pop_options;
  nm->trace[nsh_option->option_id] = trace;

  return (0);
}

/* Uses network order's class and type to lookup */
nsh_option_map_t *
nsh_md2_lookup_option (u16 class, u8 type)
{
  nsh_main_t *nm = &nsh_main;
  nsh_option_map_by_key_t key;
  uword *p;

  key.class = class;
  key.type = type;
  key.pad = 0;

  p = hash_get_mem (nm->nsh_option_map_by_key, &key);
  /* not registered */
  if (p == 0)
    {
      return NULL;
    }

  return pool_elt_at_index (nm->nsh_option_mappings, p[0]);

}

/* Uses network order's class and type to unregister */
int
nsh_md2_unregister_option (u16 class,
			   u8 type,
			   int options (vlib_buffer_t * b,
					nsh_tlv_header_t * opt),
			   u8 * trace (u8 * s, nsh_tlv_header_t * opt))
{
  nsh_main_t *nm = &nsh_main;
  nsh_option_map_by_key_t key, *key_copy;
  uword *p;
  hash_pair_t *hp;
  nsh_option_map_t *nsh_option;

  key.class = class;
  key.type = type;
  key.pad = 0;

  p = hash_get_mem (nm->nsh_option_map_by_key, &key);
  /* not registered */
  if (p == 0)
    {
      return (-1);
    }

  nsh_option = pool_elt_at_index (nm->nsh_option_mappings, p[0]);
  nm->options[nsh_option->option_id] = NULL;
  nm->add_options[nsh_option->option_id] = NULL;
  nm->pop_options[nsh_option->option_id] = NULL;
  nm->trace[nsh_option->option_id] = NULL;

  hp = hash_get_pair (nm->nsh_option_map_by_key, &key);
  key_copy = (void *) (hp->key);
  hash_unset_mem (nm->nsh_option_map_by_key, &key_copy);
  clib_mem_free (key_copy);

  pool_put (nm->nsh_option_mappings, nsh_option);

  return (0);
}

/* format from network order */
u8 *
format_nsh_header (u8 * s, va_list * args)
{
  nsh_main_t *nm = &nsh_main;
  nsh_md2_data_t *opt0;
  nsh_md2_data_t *limit0;
  nsh_option_map_t *nsh_option;
  u8 option_len = 0;

  u8 *header = va_arg (*args, u8 *);
  nsh_base_header_t *nsh_base = (nsh_base_header_t *) header;
  nsh_md1_data_t *nsh_md1 = (nsh_md1_data_t *) (nsh_base + 1);
  nsh_md2_data_t *nsh_md2 = (nsh_md2_data_t *) (nsh_base + 1);
  opt0 = (nsh_md2_data_t *) nsh_md2;
  limit0 = (nsh_md2_data_t *) ((u8 *) nsh_md2 +
			       ((nsh_base->length & NSH_LEN_MASK) * 4
				- sizeof (nsh_base_header_t)));

  s = format (s, "nsh ver %d ", (nsh_base->ver_o_c >> 6));
  if (nsh_base->ver_o_c & NSH_O_BIT)
    s = format (s, "O-set ");

  if (nsh_base->ver_o_c & NSH_C_BIT)
    s = format (s, "C-set ");

  s = format (s, "ttl %d ", (nsh_base->ver_o_c & NSH_TTL_H4_MASK) << 2 |
	      (nsh_base->length & NSH_TTL_L2_MASK) >> 6);

  s = format (s, "len %d (%d bytes) md_type %d next_protocol %d\n",
	      (nsh_base->length & NSH_LEN_MASK),
	      (nsh_base->length & NSH_LEN_MASK) * 4,
	      nsh_base->md_type, nsh_base->next_protocol);

  s = format (s, "  service path %d service index %d\n",
	      (clib_net_to_host_u32 (nsh_base->nsp_nsi) >> NSH_NSP_SHIFT) &
	      NSH_NSP_MASK,
	      clib_net_to_host_u32 (nsh_base->nsp_nsi) & NSH_NSI_MASK);

  if (nsh_base->md_type == 1)
    {
      s = format (s, "  c1 %d c2 %d c3 %d c4 %d\n",
		  clib_net_to_host_u32 (nsh_md1->c1),
		  clib_net_to_host_u32 (nsh_md1->c2),
		  clib_net_to_host_u32 (nsh_md1->c3),
		  clib_net_to_host_u32 (nsh_md1->c4));
    }
  else if (nsh_base->md_type == 2)
    {
      s = format (s, "  Supported TLVs: \n");

      /* Scan the set of variable metadata, network order */
      while (opt0 < limit0)
	{
	  nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
	  if (nsh_option != NULL)
	    {
	      if (nm->trace[nsh_option->option_id] != NULL)
		{
		  s = (*nm->trace[nsh_option->option_id]) (s, opt0);
		}
	      else
		{
		  s =
		    format (s, "\n    untraced option %d length %d",
			    opt0->type, opt0->length);
		}
	    }
	  else
	    {
	      s =
		format (s, "\n    unrecognized option %d length %d",
			opt0->type, opt0->length);
	    }

	  /* round to 4-byte */
	  option_len = ((opt0->length + 3) >> 2) << 2;
	  opt0 =
	    (nsh_md2_data_t *) (((u8 *) opt0) + sizeof (nsh_md2_data_t) +
				option_len);
	}
    }

  return s;
}

static u8 *
format_nsh_action (u8 * s, va_list * args)
{
  u32 nsh_action = va_arg (*args, u32);

  switch (nsh_action)
    {
    case NSH_ACTION_SWAP:
      return format (s, "swap");
    case NSH_ACTION_PUSH:
      return format (s, "push");
    case NSH_ACTION_POP:
      return format (s, "pop");
    default:
      return format (s, "unknown %d", nsh_action);
    }
  return s;
}

u8 *
format_nsh_map (u8 * s, va_list * args)
{
  nsh_map_t *map = va_arg (*args, nsh_map_t *);

  s = format (s, "nsh entry nsp: %d nsi: %d ",
	      (map->nsp_nsi >> NSH_NSP_SHIFT) & NSH_NSP_MASK,
	      map->nsp_nsi & NSH_NSI_MASK);
  s = format (s, "maps to nsp: %d nsi: %d ",
	      (map->mapped_nsp_nsi >> NSH_NSP_SHIFT) & NSH_NSP_MASK,
	      map->mapped_nsp_nsi & NSH_NSI_MASK);

  s = format (s, " nsh_action %U\n", format_nsh_action, map->nsh_action);

  switch (map->next_node)
    {
    case NSH_NODE_NEXT_ENCAP_GRE4:
      {
	s = format (s, "encapped by GRE4 intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_GRE6:
      {
	s = format (s, "encapped by GRE6 intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_VXLANGPE:
      {
	s = format (s, "encapped by VXLAN GPE intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_VXLAN4:
      {
	s = format (s, "encapped by VXLAN4 intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_VXLAN6:
      {
	s = format (s, "encapped by VXLAN6 intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_DECAP_ETH_INPUT:
      {
	s = format (s, "encap-none");
	break;
      }
    case NSH_NODE_NEXT_ENCAP_LISP_GPE:
      {
	s = format (s, "encapped by LISP GPE intf: %d", map->sw_if_index);
	break;
      }
    case NSH_NODE_NEXT_ENCAP_ETHERNET:
      {
	s = format (s, "encapped by Ethernet intf: %d", map->sw_if_index);
	break;
      }
    default:
      s = format (s, "only GRE and VXLANGPE support in this rev");
    }

  return s;
}

u8 *
format_nsh_node_map_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nsh_input_trace_t *t = va_arg (*args, nsh_input_trace_t *);

  s = format (s, "\n  %U", format_nsh_header, &(t->trace_data));

  return s;
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

static uword
dummy_interface_tx (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

VNET_DEVICE_CLASS (nsh_device_class, static) =
{
.name = "NSH",.format_device_name = format_nsh_name,.tx_function =
    dummy_interface_tx,.admin_up_down_function =
    nsh_interface_admin_up_down,};

/**
 * @brief Formatting function for tracing VXLAN GPE with length
 *
 * @param *s
 * @param *args
 *
 * @return *s
 *
 */
static u8 *
format_nsh_tunnel_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

VNET_HW_INTERFACE_CLASS (nsh_hw_class) =
{
.name = "NSH",.format_header =
    format_nsh_tunnel_with_length,.build_rewrite =
    default_build_rewrite,.flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,};


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
 * CLI command for NSH map
 */

static uword
unformat_nsh_action (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 tmp;

  if (unformat (input, "swap"))
    *result = NSH_ACTION_SWAP;
  else if (unformat (input, "push"))
    *result = NSH_ACTION_PUSH;
  else if (unformat (input, "pop"))
    *result = NSH_ACTION_POP;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;

  return 1;
}

static adj_index_t
nsh_get_adj_by_sw_if_index (u32 sw_if_index)
{
  adj_index_t ai = ~0;

  /* *INDENT-OFF* */
  pool_foreach_index(ai, adj_pool,
  ({
      if (sw_if_index == adj_get_sw_if_index(ai))
      {
        return ai;
      }
  }));
  /* *INDENT-ON* */

  return ~0;
}

static clib_error_t *
nsh_add_del_map_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 nsp, nsi, mapped_nsp, mapped_nsi, nsh_action;
  int nsp_set = 0, nsi_set = 0, mapped_nsp_set = 0, mapped_nsi_set = 0;
  int nsh_action_set = 0;
  u32 next_node = ~0;
  u32 adj_index = ~0;
  u32 sw_if_index = ~0;		// temporary requirement to get this moved over to NSHSFC
  u32 rx_sw_if_index = ~0;	// temporary requirement to get this moved over to NSHSFC
  nsh_add_del_map_args_t _a, *a = &_a;
  u32 map_index;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
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
      else if (unformat (line_input, "nsh_action %U", unformat_nsh_action,
			 &nsh_action))
	nsh_action_set = 1;
      else if (unformat (line_input, "encap-gre4-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_GRE4;
      else if (unformat (line_input, "encap-gre6-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_GRE6;
      else if (unformat (line_input, "encap-vxlan-gpe-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_VXLANGPE;
      else if (unformat (line_input, "encap-lisp-gpe-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_LISP_GPE;
      else if (unformat (line_input, "encap-vxlan4-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_VXLAN4;
      else if (unformat (line_input, "encap-vxlan6-intf %d", &sw_if_index))
	next_node = NSH_NODE_NEXT_ENCAP_VXLAN6;
      else if (unformat (line_input, "encap-eth-intf %d", &sw_if_index))
	{
	  next_node = NSH_NODE_NEXT_ENCAP_ETHERNET;
	  adj_index = nsh_get_adj_by_sw_if_index (sw_if_index);
	}
      else
	if (unformat
	    (line_input, "encap-none %d %d", &sw_if_index, &rx_sw_if_index))
	next_node = NSH_NODE_NEXT_DECAP_ETH_INPUT;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (nsp_set == 0 || nsi_set == 0)
    return clib_error_return (0, "nsp nsi pair required. Key: for NSH entry");

  if (mapped_nsp_set == 0 || mapped_nsi_set == 0)
    return clib_error_return (0,
			      "mapped-nsp mapped-nsi pair required. Key: for NSH entry");

  if (nsh_action_set == 0)
    return clib_error_return (0, "nsh_action required: swap|push|pop.");

  if (next_node == ~0)
    return clib_error_return (0,
			      "must specific action: [encap-gre-intf <nn> | encap-vxlan-gpe-intf <nn> | encap-lisp-gpe-intf <nn> | encap-none <tx_sw_if_index> <rx_sw_if_index>]");

  clib_memset (a, 0, sizeof (*a));

  /* set args structure */
  a->is_add = is_add;
  a->map.nsp_nsi = (nsp << NSH_NSP_SHIFT) | nsi;
  a->map.mapped_nsp_nsi = (mapped_nsp << NSH_NSP_SHIFT) | mapped_nsi;
  a->map.nsh_action = nsh_action;
  a->map.sw_if_index = sw_if_index;
  a->map.rx_sw_if_index = rx_sw_if_index;
  a->map.next_node = next_node;
  a->map.adj_index = adj_index;

  rv = nsh_add_del_map (a, &map_index);

  switch (rv)
    {
    case 0:
      break;
    case -1:			//TODO API_ERROR_INVALID_VALUE:
      return clib_error_return (0,
				"mapping already exists. Remove it first.");

    case -2:			// TODO API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "mapping does not exist.");

    default:
      return clib_error_return (0, "nsh_add_del_map returned %d", rv);
    }

  if ((a->map.next_node == NSH_NODE_NEXT_ENCAP_VXLAN4)
      | (a->map.next_node == NSH_NODE_NEXT_ENCAP_VXLAN6))
    {
      rv = nsh_add_del_proxy_session (a);

      switch (rv)
	{
	case 0:
	  break;
	case -1:		//TODO API_ERROR_INVALID_VALUE:
	  return clib_error_return (0,
				    "nsh-proxy-session already exists. Remove it first.");

	case -2:		// TODO API_ERROR_NO_SUCH_ENTRY:
	  return clib_error_return (0, "nsh-proxy-session does not exist.");

	default:
	  return clib_error_return
	    (0, "nsh_add_del_proxy_session() returned %d", rv);
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (create_nsh_map_command, static) =
{
.path = "create nsh map",.short_help =
    "create nsh map nsp <nn> nsi <nn> [del] mapped-nsp <nn> mapped-nsi <nn> nsh_action [swap|push|pop] "
    "[encap-gre4-intf <nn> | encap-gre4-intf <nn> | encap-vxlan-gpe-intf <nn> | encap-lisp-gpe-intf <nn> "
    " encap-vxlan4-intf <nn> | encap-vxlan6-intf <nn>| encap-eth-intf <nn> | encap-none]\n",.function
    = nsh_add_del_map_command_fn,};

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

/**
 * CLI command for showing the mapping between NSH entries
 */
static clib_error_t *
show_nsh_map_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nsh_main_t *nm = &nsh_main;
  nsh_map_t *map;

  if (pool_elts (nm->nsh_mappings) == 0)
    vlib_cli_output (vm, "No nsh maps configured.");

  pool_foreach (map, nm->nsh_mappings, (
					 {
					 vlib_cli_output (vm, "%U",
							  format_nsh_map,
							  map);
					 }
		));

  return 0;
}

VLIB_CLI_COMMAND (show_nsh_map_command, static) =
{
.path = "show nsh map",.function = show_nsh_map_command_fn,};

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


/**
 * CLI command for adding NSH entry
 */

static clib_error_t *
nsh_add_del_entry_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u8 ver_o_c = 0;
  u8 ttl = 63;
  u8 length = 0;
  u8 md_type = 0;
  u8 next_protocol = 1;		/* default: ip4 */
  u32 nsp;
  u8 nsp_set = 0;
  u32 nsi;
  u8 nsi_set = 0;
  u32 nsp_nsi;
  u32 c1 = 0;
  u32 c2 = 0;
  u32 c3 = 0;
  u32 c4 = 0;
  u8 *data = 0;
  nsh_tlv_header_t tlv_header;
  u8 cur_len = 0, tlvs_len = 0;
  u8 *current;
  nsh_main_t *nm = &nsh_main;
  nsh_option_map_t _nsh_option, *nsh_option = &_nsh_option;
  u8 option_size = 0;
  u32 tmp;
  int rv;
  u32 entry_index;
  nsh_add_del_entry_args_t _a, *a = &_a;
  u8 has_ioam_trace_option = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "version %d", &tmp))
	ver_o_c |= (tmp & 3) << 6;
      else if (unformat (line_input, "o-bit %d", &tmp))
	ver_o_c |= (tmp & 1) << 5;
      else if (unformat (line_input, "c-bit %d", &tmp))
	ver_o_c |= (tmp & 1) << 4;
      else if (unformat (line_input, "ttl %d", &ttl))
	ver_o_c |= (ttl & NSH_LEN_MASK) >> 2;
      else if (unformat (line_input, "md-type %d", &tmp))
	md_type = tmp;
      else if (unformat (line_input, "next-ip4"))
	next_protocol = 1;
      else if (unformat (line_input, "next-ip6"))
	next_protocol = 2;
      else if (unformat (line_input, "next-ethernet"))
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
      else if (unformat (line_input, "tlv-ioam-trace"))
	has_ioam_trace_option = 1;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (nsp_set == 0)
    return clib_error_return (0, "nsp not specified");

  if (nsi_set == 0)
    return clib_error_return (0, "nsi not specified");

  if (md_type == 1 && has_ioam_trace_option == 1)
    return clib_error_return (0, "Invalid MD Type");

  nsp_nsi = (nsp << 8) | nsi;

  clib_memset (a, 0, sizeof (*a));
  a->is_add = is_add;

  if (md_type == 1)
    {
      a->nsh_entry.md.md1_data.c1 = c1;
      a->nsh_entry.md.md1_data.c2 = c2;
      a->nsh_entry.md.md1_data.c3 = c3;
      a->nsh_entry.md.md1_data.c4 = c4;
      length = (sizeof (nsh_base_header_t) + sizeof (nsh_md1_data_t)) >> 2;
    }
  else if (md_type == 2)
    {
      length = sizeof (nsh_base_header_t) >> 2;

      vec_free (a->nsh_entry.tlvs_data);
      tlvs_len = (MAX_METADATA_LEN << 2);
      vec_validate_aligned (data, tlvs_len - 1, CLIB_CACHE_LINE_BYTES);
      a->nsh_entry.tlvs_data = data;
      current = data;

      if (has_ioam_trace_option)
	{
	  tlv_header.class = clib_host_to_net_u16 (NSH_MD2_IOAM_CLASS);
	  tlv_header.type = NSH_MD2_IOAM_OPTION_TYPE_TRACE;
	  /* Uses network order's class and type to lookup */
	  nsh_option =
	    nsh_md2_lookup_option (tlv_header.class, tlv_header.type);
	  if (nsh_option == NULL)
	    return clib_error_return (0, "iOAM Trace not registered");

	  if (nm->add_options[nsh_option->option_id] != NULL)
	    {
	      if (0 != nm->add_options[nsh_option->option_id] ((u8 *) current,
							       &option_size))
		{
		  return clib_error_return (0, "Invalid MD Type");
		}
	    }

	  nm->options_size[nsh_option->option_id] = option_size;
	  /* round to 4-byte */
	  option_size = (((option_size + 3) >> 2) << 2);

	  cur_len += option_size;
	  current = data + option_size;
	}

      /* Add more options' parsing */

      a->nsh_entry.tlvs_len = cur_len;
      length += (cur_len >> 2);
    }
  length = (length & NSH_LEN_MASK) | ((ttl & 0x3) << 6);

#define _(x) a->nsh_entry.nsh_base.x = x;
  foreach_copy_nsh_base_hdr_field;
#undef _

  rv = nsh_add_del_entry (a, &entry_index);

  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "nsh_add_del_entry returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_nsh_entry_command, static) =
{
.path = "create nsh entry",.short_help =
    "create nsh entry {nsp <nn> nsi <nn>} [ttl <nn>] [md-type <nn>]"
    "  [c1 <nn> c2 <nn> c3 <nn> c4 <nn>] [tlv-ioam-trace] [del]\n",.function
    = nsh_add_del_entry_command_fn,};

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

static void send_nsh_entry_details
  (nsh_entry_t * t, unix_shared_memory_queue_t * q, u32 context)
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

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nsh_entry_dump_t_handler (vl_api_nsh_entry_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  nsh_main_t *nm = &nsh_main;
  nsh_entry_t *t;
  u32 entry_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  entry_index = ntohl (mp->entry_index);

  if (~0 == entry_index)
    {
      pool_foreach (t, nm->nsh_entries, (
					  {
					  send_nsh_entry_details (t, q,
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
      send_nsh_entry_details (t, q, mp->context);
    }
}

static void send_nsh_map_details
  (nsh_map_t * t, unix_shared_memory_queue_t * q, u32 context)
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

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nsh_map_dump_t_handler (vl_api_nsh_map_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  nsh_main_t *nm = &nsh_main;
  nsh_map_t *t;
  u32 map_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  map_index = ntohl (mp->map_index);

  if (~0 == map_index)
    {
      pool_foreach (t, nm->nsh_mappings, (
					   {
					   send_nsh_map_details (t, q,
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
      send_nsh_map_details (t, q, mp->context);
    }
}

static clib_error_t *
show_nsh_entry_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nsh_main_t *nm = &nsh_main;
  nsh_entry_t *nsh_entry;

  if (pool_elts (nm->nsh_entries) == 0)
    vlib_cli_output (vm, "No nsh entries configured.");

  pool_foreach (nsh_entry, nm->nsh_entries, (
					      {
					      vlib_cli_output (vm, "%U",
							       format_nsh_header,
							       nsh_entry->rewrite);
					      vlib_cli_output (vm,
							       "  rewrite_size: %d bytes",
							       nsh_entry->rewrite_size);
					      }
		));

  return 0;
}

VLIB_CLI_COMMAND (show_nsh_entry_command, static) =
{
.path = "show nsh entry",.function = show_nsh_entry_command_fn,};


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

static void
setup_message_id_table (nsh_main_t * nm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + nm->msg_id_base);
  foreach_vl_msg_name_crc_nsh;
#undef _
}

always_inline void
nsh_md2_encap (vlib_buffer_t * b, nsh_base_header_t * hdr,
	       nsh_entry_t * nsh_entry)
{
  nsh_main_t *nm = &nsh_main;
  nsh_base_header_t *nsh_base;
  nsh_tlv_header_t *opt0;
  nsh_tlv_header_t *limit0;
  nsh_tlv_header_t *nsh_md2;
  nsh_option_map_t *nsh_option;
  u8 old_option_size = 0;
  u8 new_option_size = 0;

  /* Populate the NSH Header */
  opt0 = (nsh_tlv_header_t *) (nsh_entry->tlvs_data);
  limit0 = (nsh_tlv_header_t *) (nsh_entry->tlvs_data + nsh_entry->tlvs_len);

  nsh_md2 = (nsh_tlv_header_t *) ((u8 *) hdr /*nsh_entry->rewrite */  +
				  sizeof (nsh_base_header_t));
  nsh_entry->rewrite_size = sizeof (nsh_base_header_t);

  /* Scan the set of variable metadata, process ones that we understand */
  while (opt0 < limit0)
    {
      old_option_size = sizeof (nsh_tlv_header_t) + opt0->length;
      /* round to 4-byte */
      old_option_size = ((old_option_size + 3) >> 2) << 2;

      nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
      if (nsh_option == NULL)
	{
	  goto next_tlv_md2;
	}

      if (nm->options[nsh_option->option_id])
	{
	  if ((*nm->options[nsh_option->option_id]) (b, nsh_md2))
	    {
	      goto next_tlv_md2;
	    }

	  /* option length may be varied */
	  new_option_size = sizeof (nsh_tlv_header_t) + nsh_md2->length;
	  /* round to 4-byte */
	  new_option_size = ((new_option_size + 3) >> 2) << 2;
	  nsh_entry->rewrite_size += new_option_size;

	  nsh_md2 = (nsh_tlv_header_t *) (((u8 *) nsh_md2) + new_option_size);
	  opt0 = (nsh_tlv_header_t *) (((u8 *) opt0) + old_option_size);

	}
      else
	{
	next_tlv_md2:
	  opt0 = (nsh_tlv_header_t *) (((u8 *) opt0) + old_option_size);
	}
    }

  /* update nsh header's length */
  nsh_base = (nsh_base_header_t *) nsh_entry->rewrite;
  nsh_base->length = (nsh_base->length & NSH_TTL_L2_MASK) |
    ((nsh_entry->rewrite_size >> 2) & NSH_LEN_MASK);
  return;
}

always_inline void
nsh_md2_swap (vlib_buffer_t * b,
	      nsh_base_header_t * hdr,
	      u32 header_len,
	      nsh_entry_t * nsh_entry, u32 * next, u32 drop_node_val)
{
  nsh_main_t *nm = &nsh_main;
  nsh_base_header_t *nsh_base;
  nsh_tlv_header_t *opt0;
  nsh_tlv_header_t *limit0;
  nsh_tlv_header_t *nsh_md2;
  nsh_option_map_t *nsh_option;
  u8 old_option_size = 0;
  u8 new_option_size = 0;

  /* Populate the NSH Header */
  opt0 = (nsh_md2_data_t *) (hdr + 1);
  limit0 = (nsh_md2_data_t *) ((u8 *) hdr + header_len);

  nsh_md2 =
    (nsh_tlv_header_t *) (nsh_entry->rewrite + sizeof (nsh_base_header_t));
  nsh_entry->rewrite_size = sizeof (nsh_base_header_t);

  /* Scan the set of variable metadata, process ones that we understand */
  while (opt0 < limit0)
    {
      old_option_size = sizeof (nsh_tlv_header_t) + opt0->length;
      /* round to 4-byte */
      old_option_size = ((old_option_size + 3) >> 2) << 2;

      nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
      if (nsh_option == NULL)
	{
	  goto next_tlv_md2;
	}

      if (nm->swap_options[nsh_option->option_id])
	{
	  if ((*nm->swap_options[nsh_option->option_id]) (b, opt0, nsh_md2))
	    {
	      goto next_tlv_md2;
	    }

	  /* option length may be varied */
	  new_option_size = sizeof (nsh_tlv_header_t) + nsh_md2->length;
	  /* round to 4-byte */
	  new_option_size = ((new_option_size + 3) >> 2) << 2;
	  nsh_entry->rewrite_size += new_option_size;
	  nsh_md2 = (nsh_tlv_header_t *) (((u8 *) nsh_md2) + new_option_size);

	  opt0 = (nsh_tlv_header_t *) (((u8 *) opt0) + old_option_size);

	}
      else
	{
	next_tlv_md2:
	  opt0 = (nsh_tlv_header_t *) (((u8 *) opt0) + old_option_size);
	}
    }

  /* update nsh header's length */
  nsh_base = (nsh_base_header_t *) nsh_entry->rewrite;
  nsh_base->length = (nsh_base->length & NSH_TTL_L2_MASK) |
    ((nsh_entry->rewrite_size >> 2) & NSH_LEN_MASK);
  return;
}

always_inline void
nsh_md2_decap (vlib_buffer_t * b,
	       nsh_base_header_t * hdr,
	       u32 * header_len, u32 * next, u32 drop_node_val)
{
  nsh_main_t *nm = &nsh_main;
  nsh_md2_data_t *opt0;
  nsh_md2_data_t *limit0;
  nsh_option_map_t *nsh_option;
  u8 option_len = 0;

  /* Populate the NSH Header */
  opt0 = (nsh_md2_data_t *) (hdr + 1);
  limit0 = (nsh_md2_data_t *) ((u8 *) hdr + *header_len);

  /* Scan the set of variable metadata, process ones that we understand */
  while (opt0 < limit0)
    {
      nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
      if (nsh_option == NULL)
	{
	  *next = drop_node_val;
	  return;
	}

      if (nm->pop_options[nsh_option->option_id])
	{
	  if ((*nm->pop_options[nsh_option->option_id]) (b, opt0))
	    {
	      *next = drop_node_val;
	      return;
	    }
	}
      /* round to 4-byte */
      option_len = ((opt0->length + 3) >> 2) << 2;
      opt0 =
	(nsh_md2_data_t *) (((u8 *) opt0) + sizeof (nsh_md2_data_t) +
			    option_len);
      *next =
	(nm->decap_v4_next_override) ? (nm->decap_v4_next_override) : (*next);
      *header_len = (nm->decap_v4_next_override) ? 0 : (*header_len);
    }

  return;
}

static uword
nsh_input_map (vlib_main_t * vm,
	       vlib_node_runtime_t * node,
	       vlib_frame_t * from_frame, u32 node_type)
{
  u32 n_left_from, next_index, *from, *to_next;
  nsh_main_t *nm = &nsh_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0 = NSH_NODE_NEXT_DROP, next1 = NSH_NODE_NEXT_DROP;
	  uword *entry0, *entry1;
	  nsh_base_header_t *hdr0 = 0, *hdr1 = 0;
	  u32 header_len0 = 0, header_len1 = 0;
	  u32 nsp_nsi0, nsp_nsi1;
	  u32 ttl0, ttl1;
	  u32 error0, error1;
	  nsh_map_t *map0 = 0, *map1 = 0;
	  nsh_entry_t *nsh_entry0 = 0, *nsh_entry1 = 0;
	  nsh_base_header_t *encap_hdr0 = 0, *encap_hdr1 = 0;
	  u32 encap_hdr_len0 = 0, encap_hdr_len1 = 0;
	  nsh_proxy_session_by_key_t key0, key1;
	  uword *p0, *p1;
	  nsh_proxy_session_t *proxy0, *proxy1;
	  u32 sw_if_index0 = 0, sw_if_index1 = 0;
	  ethernet_header_t dummy_eth0, dummy_eth1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  error0 = 0;
	  error1 = 0;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  hdr0 = vlib_buffer_get_current (b0);
	  hdr1 = vlib_buffer_get_current (b1);

	  /* Process packet 0 */
	  if (node_type == NSH_INPUT_TYPE)
	    {
	      nsp_nsi0 = hdr0->nsp_nsi;
	      header_len0 = (hdr0->length & NSH_LEN_MASK) * 4;
	      ttl0 = (hdr0->ver_o_c & NSH_TTL_H4_MASK) << 2 |
		(hdr0->length & NSH_TTL_L2_MASK) >> 6;
	      ttl0 = ttl0 - 1;
	      if (PREDICT_FALSE (ttl0 == 0))
		{
		  error0 = NSH_NODE_ERROR_INVALID_TTL;
		  goto trace0;
		}
	    }
	  else if (node_type == NSH_CLASSIFIER_TYPE)
	    {
	      nsp_nsi0 =
		clib_host_to_net_u32 (vnet_buffer (b0)->
				      l2_classify.opaque_index);
	    }
	  else if (node_type == NSH_AWARE_VNF_PROXY_TYPE)
	    {
	      /* Push dummy Eth header */
	      clib_memcpy (dummy_eth0.dst_address, dummy_dst_address, 6);
	      clib_memcpy (dummy_eth0.src_address, dummy_src_address, 6);
	      dummy_eth0.type = 0x0800;
	      vlib_buffer_advance (b0, -(word) sizeof (ethernet_header_t));
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy (hdr0, &dummy_eth0,
			   (word) sizeof (ethernet_header_t));

	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      nsp_nsi0 = nm->tunnel_index_by_sw_if_index[sw_if_index0];
	    }
	  else
	    {
	      clib_memset (&key0, 0, sizeof (key0));
	      key0.transport_type = NSH_NODE_NEXT_ENCAP_VXLAN4;
	      key0.transport_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	      p0 = hash_get_mem (nm->nsh_proxy_session_by_key, &key0);
	      if (PREDICT_FALSE (p0 == 0))
		{
		  error0 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace0;
		}

	      proxy0 = pool_elt_at_index (nm->nsh_proxy_sessions, p0[0]);
	      if (PREDICT_FALSE (proxy0 == 0))
		{
		  error0 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace0;
		}
	      nsp_nsi0 = proxy0->nsp_nsi;
	    }

	  entry0 = hash_get_mem (nm->nsh_mapping_by_key, &nsp_nsi0);
	  if (PREDICT_FALSE (entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace0;
	    }

	  /* Entry should point to a mapping ... */
	  map0 = pool_elt_at_index (nm->nsh_mappings, entry0[0]);
	  if (PREDICT_FALSE (map0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace0;
	    }

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next0 = map0->next_node;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = map0->sw_if_index;
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = map0->adj_index;

	  if (PREDICT_FALSE (map0->nsh_action == NSH_ACTION_POP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr0->md_type == 2))
		{
		  nsh_md2_decap (b0, hdr0, &header_len0, &next0,
				 NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next0 == NSH_NODE_NEXT_DROP))
		    {
		      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace0;
		    }
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
		    map0->rx_sw_if_index;
		}

	      /* Pop NSH header */
	      vlib_buffer_advance (b0, (word) header_len0);
	      goto trace0;
	    }

	  entry0 = hash_get_mem (nm->nsh_entry_by_key, &map0->mapped_nsp_nsi);
	  if (PREDICT_FALSE (entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_ENTRY;
	      goto trace0;
	    }

	  nsh_entry0 =
	    (nsh_entry_t *) pool_elt_at_index (nm->nsh_entries, entry0[0]);
	  encap_hdr0 = (nsh_base_header_t *) (nsh_entry0->rewrite);
	  /* rewrite_size should equal to (encap_hdr0->length * 4) */
	  encap_hdr_len0 = nsh_entry0->rewrite_size;

	  if (PREDICT_TRUE (map0->nsh_action == NSH_ACTION_SWAP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr0->md_type == 2))
		{
		  nsh_md2_swap (b0, hdr0, header_len0, nsh_entry0,
				&next0, NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next0 == NSH_NODE_NEXT_DROP))
		    {
		      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace0;
		    }
		}

	      /* Pop old NSH header */
	      vlib_buffer_advance (b0, (word) header_len0);

	      /* After processing, md2's length may be varied */
	      encap_hdr_len0 = nsh_entry0->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b0, -(word) encap_hdr_len0);
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy (hdr0, encap_hdr0, (word) encap_hdr_len0);

	      goto trace0;
	    }

	  if (PREDICT_TRUE (map0->nsh_action == NSH_ACTION_PUSH))
	    {
	      /* After processing, md2's length may be varied */
	      encap_hdr_len0 = nsh_entry0->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b0, -(word) encap_hdr_len0);
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy (hdr0, encap_hdr0, (word) encap_hdr_len0);

	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (nsh_entry0->nsh_base.md_type == 2))
		{
		  nsh_md2_encap (b0, hdr0, nsh_entry0);
		}

	    }

	trace0:
	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy (&(tr->trace_data), hdr0,
			   ((hdr0->length & NSH_LEN_MASK) * 4));
	    }

	  /* Process packet 1 */
	  if (node_type == NSH_INPUT_TYPE)
	    {
	      nsp_nsi1 = hdr1->nsp_nsi;
	      header_len1 = (hdr1->length & NSH_LEN_MASK) * 4;
	      ttl1 = (hdr1->ver_o_c & NSH_TTL_H4_MASK) << 2 |
		(hdr1->length & NSH_TTL_L2_MASK) >> 6;
	      ttl1 = ttl1 - 1;
	      if (PREDICT_FALSE (ttl1 == 0))
		{
		  error1 = NSH_NODE_ERROR_INVALID_TTL;
		  goto trace1;
		}
	    }
	  else if (node_type == NSH_CLASSIFIER_TYPE)
	    {
	      nsp_nsi1 =
		clib_host_to_net_u32 (vnet_buffer (b1)->
				      l2_classify.opaque_index);
	    }
	  else if (node_type == NSH_AWARE_VNF_PROXY_TYPE)
	    {
	      /* Push dummy Eth header */
	      clib_memcpy (dummy_eth1.dst_address, dummy_dst_address, 6);
	      clib_memcpy (dummy_eth1.src_address, dummy_src_address, 6);
	      dummy_eth1.type = 0x0800;
	      vlib_buffer_advance (b1, -(word) sizeof (ethernet_header_t));
	      hdr1 = vlib_buffer_get_current (b1);
	      clib_memcpy (hdr1, &dummy_eth1,
			   (word) sizeof (ethernet_header_t));

	      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	      nsp_nsi1 = nm->tunnel_index_by_sw_if_index[sw_if_index1];
	    }
	  else
	    {
	      clib_memset (&key1, 0, sizeof (key1));
	      key1.transport_type = NSH_NODE_NEXT_ENCAP_VXLAN4;
	      key1.transport_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	      p1 = hash_get_mem (nm->nsh_proxy_session_by_key, &key1);
	      if (PREDICT_FALSE (p1 == 0))
		{
		  error1 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace1;
		}

	      proxy1 = pool_elt_at_index (nm->nsh_proxy_sessions, p1[0]);
	      if (PREDICT_FALSE (proxy1 == 0))
		{
		  error1 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace1;
		}
	      nsp_nsi1 = proxy1->nsp_nsi;
	    }

	  entry1 = hash_get_mem (nm->nsh_mapping_by_key, &nsp_nsi1);
	  if (PREDICT_FALSE (entry1 == 0))
	    {
	      error1 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace1;
	    }

	  /* Entry should point to a mapping ... */
	  map1 = pool_elt_at_index (nm->nsh_mappings, entry1[0]);
	  if (PREDICT_FALSE (map1 == 0))
	    {
	      error1 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace1;
	    }

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next1 = map1->next_node;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = map1->sw_if_index;
	  vnet_buffer (b1)->ip.adj_index[VLIB_TX] = map1->adj_index;

	  if (PREDICT_FALSE (map1->nsh_action == NSH_ACTION_POP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr1->md_type == 2))
		{
		  nsh_md2_decap (b1, hdr1, &header_len1, &next1,
				 NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next1 == NSH_NODE_NEXT_DROP))
		    {
		      error1 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace1;
		    }
		  vnet_buffer (b1)->sw_if_index[VLIB_RX] =
		    map1->rx_sw_if_index;
		}

	      /* Pop NSH header */
	      vlib_buffer_advance (b1, (word) header_len1);
	      goto trace1;
	    }

	  entry1 = hash_get_mem (nm->nsh_entry_by_key, &map1->mapped_nsp_nsi);
	  if (PREDICT_FALSE (entry1 == 0))
	    {
	      error1 = NSH_NODE_ERROR_NO_ENTRY;
	      goto trace1;
	    }

	  nsh_entry1 =
	    (nsh_entry_t *) pool_elt_at_index (nm->nsh_entries, entry1[0]);
	  encap_hdr1 = (nsh_base_header_t *) (nsh_entry1->rewrite);
	  /* rewrite_size should equal to (encap_hdr0->length * 4) */
	  encap_hdr_len1 = nsh_entry1->rewrite_size;

	  if (PREDICT_TRUE (map1->nsh_action == NSH_ACTION_SWAP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr1->md_type == 2))
		{
		  nsh_md2_swap (b1, hdr1, header_len1, nsh_entry1,
				&next1, NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next1 == NSH_NODE_NEXT_DROP))
		    {
		      error1 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace1;
		    }
		}

	      /* Pop old NSH header */
	      vlib_buffer_advance (b1, (word) header_len1);

	      /* After processing, md2's length may be varied */
	      encap_hdr_len1 = nsh_entry1->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b1, -(word) encap_hdr_len1);
	      hdr1 = vlib_buffer_get_current (b1);
	      clib_memcpy (hdr1, encap_hdr1, (word) encap_hdr_len1);

	      goto trace1;
	    }

	  if (PREDICT_FALSE (map1->nsh_action == NSH_ACTION_PUSH))
	    {
	      /* After processing, md2's length may be varied */
	      encap_hdr_len1 = nsh_entry1->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b1, -(word) encap_hdr_len1);
	      hdr1 = vlib_buffer_get_current (b1);
	      clib_memcpy (hdr1, encap_hdr1, (word) encap_hdr_len1);

	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (nsh_entry1->nsh_base.md_type == 2))
		{
		  nsh_md2_encap (b1, hdr1, nsh_entry1);
		}

	    }

	trace1:
	  b1->error = error1 ? node->errors[error1] : 0;

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_input_trace_t *tr =
		vlib_add_trace (vm, node, b1, sizeof (*tr));
	      clib_memcpy (&(tr->trace_data), hdr1,
			   ((hdr1->length & NSH_LEN_MASK) * 4));
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);

	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = 0;
	  vlib_buffer_t *b0 = NULL;
	  u32 next0 = NSH_NODE_NEXT_DROP;
	  uword *entry0;
	  nsh_base_header_t *hdr0 = 0;
	  u32 header_len0 = 0;
	  u32 nsp_nsi0;
	  u32 ttl0;
	  u32 error0;
	  nsh_map_t *map0 = 0;
	  nsh_entry_t *nsh_entry0 = 0;
	  nsh_base_header_t *encap_hdr0 = 0;
	  u32 encap_hdr_len0 = 0;
	  nsh_proxy_session_by_key_t key0;
	  uword *p0;
	  nsh_proxy_session_t *proxy0 = 0;
	  u32 sw_if_index0 = 0;
	  ethernet_header_t dummy_eth0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  error0 = 0;

	  b0 = vlib_get_buffer (vm, bi0);
	  hdr0 = vlib_buffer_get_current (b0);

	  if (node_type == NSH_INPUT_TYPE)
	    {
	      nsp_nsi0 = hdr0->nsp_nsi;
	      header_len0 = (hdr0->length & NSH_LEN_MASK) * 4;
	      ttl0 = (hdr0->ver_o_c & NSH_TTL_H4_MASK) << 2 |
		(hdr0->length & NSH_TTL_L2_MASK) >> 6;
	      ttl0 = ttl0 - 1;
	      if (PREDICT_FALSE (ttl0 == 0))
		{
		  error0 = NSH_NODE_ERROR_INVALID_TTL;
		  goto trace00;
		}
	    }
	  else if (node_type == NSH_CLASSIFIER_TYPE)
	    {
	      nsp_nsi0 =
		clib_host_to_net_u32 (vnet_buffer (b0)->
				      l2_classify.opaque_index);
	    }
	  else if (node_type == NSH_AWARE_VNF_PROXY_TYPE)
	    {
	      /* Push dummy Eth header */
	      clib_memcpy (dummy_eth0.dst_address, dummy_dst_address, 6);
	      clib_memcpy (dummy_eth0.src_address, dummy_src_address, 6);
	      dummy_eth0.type = 0x0800;
	      vlib_buffer_advance (b0, -(word) sizeof (ethernet_header_t));
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy (hdr0, &dummy_eth0,
			   (word) sizeof (ethernet_header_t));

	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      nsp_nsi0 = nm->tunnel_index_by_sw_if_index[sw_if_index0];
	    }
	  else
	    {
	      clib_memset (&key0, 0, sizeof (key0));
	      key0.transport_type = NSH_NODE_NEXT_ENCAP_VXLAN4;
	      key0.transport_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	      p0 = hash_get_mem (nm->nsh_proxy_session_by_key, &key0);
	      if (PREDICT_FALSE (p0 == 0))
		{
		  error0 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace00;
		}

	      proxy0 = pool_elt_at_index (nm->nsh_proxy_sessions, p0[0]);
	      if (PREDICT_FALSE (proxy0 == 0))
		{
		  error0 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace00;
		}
	      nsp_nsi0 = proxy0->nsp_nsi;
	    }

	  entry0 = hash_get_mem (nm->nsh_mapping_by_key, &nsp_nsi0);

	  if (PREDICT_FALSE (entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace00;
	    }

	  /* Entry should point to a mapping ... */
	  map0 = pool_elt_at_index (nm->nsh_mappings, entry0[0]);

	  if (PREDICT_FALSE (map0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace00;
	    }

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next0 = map0->next_node;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = map0->sw_if_index;
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = map0->adj_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = map0->nsh_sw_if;

	  if (PREDICT_FALSE (map0->nsh_action == NSH_ACTION_POP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr0->md_type == 2))
		{
		  nsh_md2_decap (b0, hdr0, &header_len0, &next0,
				 NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next0 == NSH_NODE_NEXT_DROP))
		    {
		      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace00;
		    }
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
		    map0->rx_sw_if_index;
		}

	      /* Pop NSH header */
	      vlib_buffer_advance (b0, (word) header_len0);
	      goto trace00;
	    }

	  entry0 = hash_get_mem (nm->nsh_entry_by_key, &map0->mapped_nsp_nsi);
	  if (PREDICT_FALSE (entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_ENTRY;
	      goto trace00;
	    }

	  nsh_entry0 =
	    (nsh_entry_t *) pool_elt_at_index (nm->nsh_entries, entry0[0]);
	  encap_hdr0 = (nsh_base_header_t *) (nsh_entry0->rewrite);
	  /* rewrite_size should equal to (encap_hdr0->length * 4) */
	  encap_hdr_len0 = nsh_entry0->rewrite_size;

	  if (PREDICT_TRUE (map0->nsh_action == NSH_ACTION_SWAP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr0->md_type == 2))
		{
		  nsh_md2_swap (b0, hdr0, header_len0, nsh_entry0,
				&next0, NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next0 == NSH_NODE_NEXT_DROP))
		    {
		      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace00;
		    }
		}

	      /* Pop old NSH header */
	      vlib_buffer_advance (b0, (word) header_len0);

	      /* After processing, md2's length may be varied */
	      encap_hdr_len0 = nsh_entry0->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b0, -(word) encap_hdr_len0);
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy (hdr0, encap_hdr0, (word) encap_hdr_len0);

	      goto trace00;
	    }

	  if (PREDICT_TRUE (map0->nsh_action == NSH_ACTION_PUSH))
	    {
	      /* After processing, md2's length may be varied */
	      encap_hdr_len0 = nsh_entry0->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b0, -(word) encap_hdr_len0);
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy (hdr0, encap_hdr0, (word) encap_hdr_len0);
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (nsh_entry0->nsh_base.md_type == 2))
		{
		  nsh_md2_encap (b0, hdr0, nsh_entry0);
		}

	    }

	trace00:b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy (&(tr->trace_data[0]), hdr0,
			   ((hdr0->length & NSH_LEN_MASK) * 4));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }

  return from_frame->n_vectors;
}

/**
 * @brief Graph processing dispatch function for NSH Input
 *
 * @node nsh_input
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
static uword
nsh_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	   vlib_frame_t * from_frame)
{
  return nsh_input_map (vm, node, from_frame, NSH_INPUT_TYPE);
}

/**
 * @brief Graph processing dispatch function for NSH-Proxy
 *
 * @node nsh_proxy
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
static uword
nsh_proxy (vlib_main_t * vm, vlib_node_runtime_t * node,
	   vlib_frame_t * from_frame)
{
  return nsh_input_map (vm, node, from_frame, NSH_PROXY_TYPE);
}

/**
 * @brief Graph processing dispatch function for NSH Classifier
 *
 * @node nsh_classifier
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
static uword
nsh_classifier (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * from_frame)
{
  return nsh_input_map (vm, node, from_frame, NSH_CLASSIFIER_TYPE);
}

/**
 * @brief Graph processing dispatch function for NSH-AWARE-VNF-PROXY
 *
 * @node nsh_aware_vnf_proxy
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
static uword
nsh_aware_vnf_proxy (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame)
{
  return nsh_input_map (vm, node, from_frame, NSH_AWARE_VNF_PROXY_TYPE);
}

static char *nsh_node_error_strings[] = {
#define _(sym,string) string,
  foreach_nsh_node_error
#undef _
};

/* register nsh-input node */
VLIB_REGISTER_NODE (nsh_input_node) =
{
  .function = nsh_input,.name = "nsh-input",.vector_size =
    sizeof (u32),.format_trace = format_nsh_node_map_trace,.format_buffer =
    format_nsh_header,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (nsh_node_error_strings),.error_strings =
    nsh_node_error_strings,.n_next_nodes = NSH_NODE_N_NEXT,.next_nodes =
  {
#define _(s,n) [NSH_NODE_NEXT_##s] = n,
    foreach_nsh_node_next
#undef _
  }
,};

VLIB_NODE_FUNCTION_MULTIARCH (nsh_input_node, nsh_input);

/* register nsh-proxy node */
VLIB_REGISTER_NODE (nsh_proxy_node) =
{
  .function = nsh_proxy,.name = "nsh-proxy",.vector_size =
    sizeof (u32),.format_trace = format_nsh_node_map_trace,.format_buffer =
    format_nsh_header,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (nsh_node_error_strings),.error_strings =
    nsh_node_error_strings,.n_next_nodes = NSH_NODE_N_NEXT,.next_nodes =
  {
#define _(s,n) [NSH_NODE_NEXT_##s] = n,
    foreach_nsh_node_next
#undef _
  }
,};

VLIB_NODE_FUNCTION_MULTIARCH (nsh_proxy_node, nsh_proxy);

/* register nsh-classifier node */
VLIB_REGISTER_NODE (nsh_classifier_node) =
{
  .function = nsh_classifier,.name = "nsh-classifier",.vector_size =
    sizeof (u32),.format_trace = format_nsh_node_map_trace,.format_buffer =
    format_nsh_header,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (nsh_node_error_strings),.error_strings =
    nsh_node_error_strings,.n_next_nodes = NSH_NODE_N_NEXT,.next_nodes =
  {
#define _(s,n) [NSH_NODE_NEXT_##s] = n,
    foreach_nsh_node_next
#undef _
  }
,};

VLIB_NODE_FUNCTION_MULTIARCH (nsh_classifier_node, nsh_classifier);

/* register nsh-aware-vnf-proxy node */
VLIB_REGISTER_NODE (nsh_aware_vnf_proxy_node) =
{
  .function = nsh_aware_vnf_proxy,.name = "nsh-aware-vnf-proxy",.vector_size =
    sizeof (u32),.format_trace = format_nsh_node_map_trace,.format_buffer =
    format_nsh_header,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (nsh_node_error_strings),.error_strings =
    nsh_node_error_strings,.n_next_nodes = NSH_NODE_N_NEXT,.next_nodes =
  {
#define _(s,n) [NSH_NODE_NEXT_##s] = n,
    foreach_nsh_node_next
#undef _
  }
,};

VLIB_NODE_FUNCTION_MULTIARCH (nsh_aware_vnf_proxy_node, nsh_aware_vnf_proxy);

void
nsh_md2_set_next_ioam_export_override (uword next)
{
  nsh_main_t *hm = &nsh_main;
  hm->decap_v4_next_override = next;
  return;
}


clib_error_t *
nsh_init (vlib_main_t * vm)
{
  nsh_main_t *nm = &nsh_main;
  clib_error_t *error = 0;
  u8 *name;
  uword next_node;

  /* Init the main structures from VPP */
  nm->vlib_main = vm;
  nm->vnet_main = vnet_get_main ();

  /* Various state maintenance mappings */
  nm->nsh_mapping_by_key = hash_create_mem (0, sizeof (u32), sizeof (uword));

  nm->nsh_mapping_by_mapped_key
    = hash_create_mem (0, sizeof (u32), sizeof (uword));

  nm->nsh_entry_by_key = hash_create_mem (0, sizeof (u32), sizeof (uword));

  nm->nsh_proxy_session_by_key
    =
    hash_create_mem (0, sizeof (nsh_proxy_session_by_key_t), sizeof (uword));

  nm->nsh_option_map_by_key
    = hash_create_mem (0, sizeof (nsh_option_map_by_key_t), sizeof (uword));

  name = format (0, "nsh_%08x%c", api_version, 0);

  /* Set up the API */
  nm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = nsh_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (nm, &api_main);

  /* Add dispositions to nodes that feed nsh-input */
  //alagalah - validate we don't really need to use the node value
  next_node =
    vlib_node_add_next (vm, vxlan4_gpe_input_node.index,
			nsh_input_node.index);
  vlib_node_add_next (vm, vxlan4_gpe_input_node.index, nsh_proxy_node.index);
  vlib_node_add_next (vm, vxlan4_gpe_input_node.index,
		      nsh_aware_vnf_proxy_node.index);
  vxlan_gpe_register_decap_protocol (VXLAN_GPE_PROTOCOL_NSH, next_node);

  vlib_node_add_next (vm, vxlan6_gpe_input_node.index, nsh_input_node.index);
  vlib_node_add_next (vm, vxlan6_gpe_input_node.index, nsh_proxy_node.index);
  vlib_node_add_next (vm, vxlan6_gpe_input_node.index,
		      nsh_aware_vnf_proxy_node.index);

  vlib_node_add_next (vm, gre4_input_node.index, nsh_input_node.index);
  vlib_node_add_next (vm, gre4_input_node.index, nsh_proxy_node.index);
  vlib_node_add_next (vm, gre4_input_node.index,
		      nsh_aware_vnf_proxy_node.index);

  vlib_node_add_next (vm, gre6_input_node.index, nsh_input_node.index);
  vlib_node_add_next (vm, gre6_input_node.index, nsh_proxy_node.index);
  vlib_node_add_next (vm, gre6_input_node.index,
		      nsh_aware_vnf_proxy_node.index);

  /* Add NSH-Proxy support */
  vlib_node_add_next (vm, vxlan4_input_node.index, nsh_proxy_node.index);
  vlib_node_add_next (vm, vxlan6_input_node.index, nsh_proxy_node.index);

  /* Add NSH-Classifier support */
  vlib_node_add_next (vm, ip4_classify_node.index, nsh_classifier_node.index);
  vlib_node_add_next (vm, ip6_classify_node.index, nsh_classifier_node.index);
  vlib_node_add_next (vm, l2_input_classify_node.index,
		      nsh_classifier_node.index);

  /* Add Ethernet+NSH support */
  ethernet_register_input_type (vm, ETHERNET_TYPE_NSH, nsh_input_node.index);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (nsh_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Network Service Header",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
