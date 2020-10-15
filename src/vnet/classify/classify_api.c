/*
 *------------------------------------------------------------------
 * classify_api.c - classify api
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

#include <vnet/interface.h>
#include <vnet/api_errno.h>

#include <vnet/classify/vnet_classify.h>
#include <vnet/classify/in_out_acl.h>
#include <vnet/classify/policer_classify.h>
#include <vnet/classify/flow_classify.h>
#include <vnet/l2/l2_classify.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip4.h>

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

#define foreach_vpe_api_msg                                             \
_(CLASSIFY_ADD_DEL_TABLE, classify_add_del_table)                       \
_(CLASSIFY_ADD_DEL_SESSION, classify_add_del_session)                   \
_(CLASSIFY_TABLE_IDS,classify_table_ids)                                \
_(CLASSIFY_TABLE_BY_INTERFACE, classify_table_by_interface)             \
_(CLASSIFY_TABLE_INFO,classify_table_info)                              \
_(CLASSIFY_SESSION_DUMP,classify_session_dump)                          \
_(POLICER_CLASSIFY_SET_INTERFACE, policer_classify_set_interface)       \
_(POLICER_CLASSIFY_DUMP, policer_classify_dump)                         \
_(FLOW_CLASSIFY_SET_INTERFACE, flow_classify_set_interface)             \
_(FLOW_CLASSIFY_DUMP, flow_classify_dump)                               \
_(INPUT_ACL_SET_INTERFACE, input_acl_set_interface)                     \
_(CLASSIFY_SET_INTERFACE_IP_TABLE, classify_set_interface_ip_table)     \
_(CLASSIFY_SET_INTERFACE_L2_TABLES, classify_set_interface_l2_tables)   \
_(OUTPUT_ACL_SET_INTERFACE, output_acl_set_interface)			\
_(CLASSIFY_PCAP_LOOKUP_TABLE, classify_pcap_lookup_table)		\
_(CLASSIFY_PCAP_SET_TABLE, classify_pcap_set_table)			\
_(CLASSIFY_PCAP_GET_TABLES, classify_pcap_get_tables)			\
_(CLASSIFY_TRACE_LOOKUP_TABLE, classify_trace_lookup_table)		\
_(CLASSIFY_TRACE_SET_TABLE, classify_trace_set_table)			\
_(CLASSIFY_TRACE_GET_TABLES, classify_trace_get_tables)			\


#define foreach_classify_add_del_table_field    \
_(table_index)                                  \
_(nbuckets)                                     \
_(memory_size)                                  \
_(skip_n_vectors)                               \
_(match_n_vectors)                              \
_(next_table_index)                             \
_(miss_next_index)                              \
_(mask_len)


static void vl_api_classify_pcap_lookup_table_t_handler
  (vl_api_classify_pcap_lookup_table_t * mp)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vl_api_registration_t *reg;
  vl_api_classify_pcap_lookup_table_reply_t *rmp;
  int rv = 0;
  u32 table_index = ~0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 n_skip = ntohl (mp->skip_n_vectors);
  u32 n_match = ntohl (mp->match_n_vectors);
  u32 mask_len = ntohl (mp->mask_len);
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (n_skip > 5
      || 0 <= n_match || n_match > 5
      || mask_len != n_match * sizeof (u32x4)
      || sw_if_index == ~0
      || sw_if_index >= vec_len (cm->classify_table_index_by_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  u32 table_chain;
  table_chain = classify_get_pcap_chain (cm, sw_if_index);

  u8 *mask_vec = 0;
  vec_validate (mask_vec, mask_len - 1);
  clib_memcpy (mask_vec, mp->mask, mask_len);

  if (table_chain != ~0)
    table_index = classify_lookup_chain (table_chain,
					 mask_vec, n_skip, n_match);

  vec_free (mask_vec);

out:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->table_index = htonl (table_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_classify_pcap_set_table_t_handler
  (vl_api_classify_pcap_set_table_t * mp)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vl_api_classify_pcap_set_table_reply_t *rmp;
  vl_api_registration_t *reg;
  int rv = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 table_index = ntohl (mp->table_index);
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (sw_if_index == ~0
      || sw_if_index >= vec_len (cm->classify_table_index_by_sw_if_index)
      || (table_index != ~0 && pool_is_free_index (cm->tables, table_index)))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  /*
   * Maybe reorder tables such that masks are most-specify to least-specific.
   */
  if (table_index != ~0 && mp->sort_masks)
    table_index = classify_sort_table_chain (cm, table_index);

  classify_set_pcap_chain (cm, sw_if_index, table_index);

out:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_PCAP_SET_TABLE_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->table_index = htonl (table_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_classify_pcap_get_tables_t_handler
  (vl_api_classify_pcap_get_tables_t * mp)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vl_api_classify_pcap_get_tables_reply_t *rmp;
  vl_api_registration_t *reg;
  int rv = 0;
  u32 *tables = 0;
  u32 count;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  if (sw_if_index == ~0
      || sw_if_index >= vec_len (cm->classify_table_index_by_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  u32 table_index = classify_get_pcap_chain (cm, sw_if_index);
  if (table_index == ~0)
    goto out;

  /*
   * Form a vector of all classifier tables in this chain.
   */
  vnet_classify_table_t *t;
  u32 i;

  for (i = table_index; i != ~0; i = t->next_table_index)
    {
      vec_add1 (tables, i);
      t = pool_elt_at_index (cm->tables, i);
    }

out:
  count = vec_len (tables);
  rmp = vl_msg_api_alloc_as_if_client (sizeof (*rmp) + count * sizeof (u32));
  rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_PCAP_GET_TABLES_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->count = htonl (count);

  for (i = 0; i < count; ++i)
    {
      rmp->indices[i] = htonl (tables[i]);
    }

  vec_free (tables);

  vl_api_send_msg (reg, (u8 *) rmp);
}


static void vl_api_classify_trace_lookup_table_t_handler
  (vl_api_classify_trace_lookup_table_t * mp)
{
  vl_api_classify_trace_lookup_table_reply_t *rmp;
  vl_api_registration_t *reg;
  int rv = 0;
  u32 table_index = ~0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 n_skip = ntohl (mp->skip_n_vectors);
  u32 n_match = ntohl (mp->match_n_vectors);
  u32 mask_len = ntohl (mp->mask_len);
  if (n_skip > 5
      || n_match == 0 || n_match > 5 || mask_len != n_match * sizeof (u32x4))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  u32 table_chain;
  table_chain = classify_get_trace_chain ();

  u8 *mask_vec = 0;
  vec_validate (mask_vec, mask_len - 1);
  clib_memcpy (mask_vec, mp->mask, mask_len);

  if (table_chain != ~0)
    table_index = classify_lookup_chain (table_chain,
					 mask_vec, n_skip, n_match);
  vec_free (mask_vec);

out:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs ((VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_REPLY));
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->table_index = htonl (table_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_classify_trace_set_table_t_handler
  (vl_api_classify_trace_set_table_t * mp)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vl_api_classify_trace_set_table_reply_t *rmp;
  vl_api_registration_t *reg;
  int rv = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 table_index = ntohl (mp->table_index);
  if (table_index != ~0 && pool_is_free_index (cm->tables, table_index))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  /*
   * Maybe reorder tables such that masks are most-specific to least-specific.
   */
  if (table_index != ~0 && mp->sort_masks)
    table_index = classify_sort_table_chain (cm, table_index);

  classify_set_trace_chain (cm, table_index);

out:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs ((VL_API_CLASSIFY_TRACE_SET_TABLE_REPLY));
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->table_index = htonl (table_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_classify_trace_get_tables_t_handler
  (vl_api_classify_trace_get_tables_t * mp)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vl_api_classify_trace_get_tables_reply_t *rmp;
  vl_api_registration_t *reg;
  int rv = 0;
  u32 *tables = 0;
  u32 count;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 table_index = classify_get_trace_chain ();
  if (table_index == ~0)
    goto out;

  /*
   * Form a vector of all classifier tables in this chain.
   */
  vnet_classify_table_t *t;
  u32 i;

  for (i = table_index; i != ~0; i = t->next_table_index)
    {
      vec_add1 (tables, i);
      t = pool_elt_at_index (cm->tables, i);
    }

out:
  count = vec_len (tables);
  rmp = vl_msg_api_alloc_as_if_client (sizeof (*rmp) + count * sizeof (u32));
  rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_TRACE_GET_TABLES_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->count = htonl (count);

  for (i = 0; i < count; ++i)
    {
      rmp->indices[i] = htonl (tables[i]);
    }

  vec_free (tables);

  vl_api_send_msg (reg, (u8 *) rmp);
}


static void vl_api_classify_add_del_table_t_handler
  (vl_api_classify_add_del_table_t * mp)
{
  vl_api_classify_add_del_table_reply_t *rmp;
  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *t;
  int rv;

#define _(a) u32 a;
  foreach_classify_add_del_table_field;
#undef _

#define _(a) a = ntohl(mp->a);
  foreach_classify_add_del_table_field;
#undef _

  if (mask_len != match_n_vectors * sizeof (u32x4))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  /* The underlying API fails silently, on purpose, so check here */
  if (mp->is_add == 0)		/* delete */
    {
      if (pool_is_free_index (cm->tables, table_index))
	{
	  rv = VNET_API_ERROR_NO_SUCH_TABLE;
	  goto out;
	}
    }
  else				/* add or update */
    {
      if (table_index != ~0 && pool_is_free_index (cm->tables, table_index))
	table_index = ~0;
    }

  u8 current_data_flag = mp->current_data_flag;
  i16 current_data_offset = clib_net_to_host_i16 (mp->current_data_offset);

  rv = vnet_classify_add_del_table
    (cm, mp->mask, nbuckets, memory_size,
     skip_n_vectors, match_n_vectors,
     next_table_index, miss_next_index, &table_index,
     current_data_flag, current_data_offset, mp->is_add, mp->del_chain);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CLASSIFY_ADD_DEL_TABLE_REPLY,
  ({
    if (rv == 0 && mp->is_add)
      {
        t = pool_elt_at_index (cm->tables, table_index);
        rmp->skip_n_vectors = htonl(t->skip_n_vectors);
        rmp->match_n_vectors = htonl(t->match_n_vectors);
        rmp->new_table_index = htonl(table_index);
      }
    else
      {
        rmp->skip_n_vectors = ~0;
        rmp->match_n_vectors = ~0;
        rmp->new_table_index = ~0;
      }
  }));
  /* *INDENT-ON* */
}

static void vl_api_classify_add_del_session_t_handler
  (vl_api_classify_add_del_session_t * mp)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vl_api_classify_add_del_session_reply_t *rmp;
  int rv;
  u32 table_index, hit_next_index, opaque_index, metadata, match_len;
  i32 advance;
  u8 action;
  vnet_classify_table_t *t;

  table_index = ntohl (mp->table_index);
  hit_next_index = ntohl (mp->hit_next_index);
  opaque_index = ntohl (mp->opaque_index);
  advance = ntohl (mp->advance);
  action = mp->action;
  metadata = ntohl (mp->metadata);
  match_len = ntohl (mp->match_len);

  if (pool_is_free_index (cm->tables, table_index))
    {
      rv = VNET_API_ERROR_NO_SUCH_TABLE;
      goto out;
    }

  t = pool_elt_at_index (cm->tables, table_index);

  if (match_len != (t->skip_n_vectors + t->match_n_vectors) * sizeof (u32x4))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  rv = vnet_classify_add_del_session
    (cm, table_index, mp->match, hit_next_index, opaque_index,
     advance, action, metadata, mp->is_add);

out:
  REPLY_MACRO (VL_API_CLASSIFY_ADD_DEL_SESSION_REPLY);
}

static void
  vl_api_policer_classify_set_interface_t_handler
  (vl_api_policer_classify_set_interface_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_policer_classify_set_interface_reply_t *rmp;
  int rv;
  u32 sw_if_index, ip4_table_index, ip6_table_index, l2_table_index;

  ip4_table_index = ntohl (mp->ip4_table_index);
  ip6_table_index = ntohl (mp->ip6_table_index);
  l2_table_index = ntohl (mp->l2_table_index);
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_set_policer_classify_intfc (vm, sw_if_index, ip4_table_index,
					ip6_table_index, l2_table_index,
					mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_POLICER_CLASSIFY_SET_INTERFACE_REPLY);
}

static void
send_policer_classify_details (u32 sw_if_index,
			       u32 table_index, vl_api_registration_t * reg,
			       u32 context)
{
  vl_api_policer_classify_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_POLICER_CLASSIFY_DETAILS);
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->table_index = htonl (table_index);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_policer_classify_dump_t_handler (vl_api_policer_classify_dump_t * mp)
{
  vl_api_registration_t *reg;
  policer_classify_main_t *pcm = &policer_classify_main;
  u32 *vec_tbl;
  int i;
  u32 filter_sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  filter_sw_if_index = ntohl (mp->sw_if_index);
  if (filter_sw_if_index
      >= vec_len (pcm->classify_table_index_by_sw_if_index[mp->type]))
    return;

  if (filter_sw_if_index != ~0)
    vec_tbl =
      &pcm->classify_table_index_by_sw_if_index[mp->type][filter_sw_if_index];
  else
    vec_tbl = pcm->classify_table_index_by_sw_if_index[mp->type];

  if (vec_len (vec_tbl))
    {
      for (i = 0; i < vec_len (vec_tbl); i++)
	{
	  if (vec_elt (vec_tbl, i) == ~0)
	    continue;

	  send_policer_classify_details (i, vec_elt (vec_tbl, i), reg,
					 mp->context);
	}
    }
}

static void
vl_api_classify_table_ids_t_handler (vl_api_classify_table_ids_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *t;
  u32 *table_ids = 0;
  u32 count;

   /* *INDENT-OFF* */
   pool_foreach (t, cm->tables,
   ({
     vec_add1 (table_ids, ntohl(t - cm->tables));
   }));
   /* *INDENT-ON* */
  count = vec_len (table_ids);

  vl_api_classify_table_ids_reply_t *rmp;
  rmp = vl_msg_api_alloc_as_if_client (sizeof (*rmp) + count * sizeof (u32));
  rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_TABLE_IDS_REPLY);
  rmp->context = mp->context;
  rmp->count = ntohl (count);
  clib_memcpy (rmp->ids, table_ids, count * sizeof (u32));
  rmp->retval = 0;

  vl_api_send_msg (reg, (u8 *) rmp);

  vec_free (table_ids);
}

static void
  vl_api_classify_table_by_interface_t_handler
  (vl_api_classify_table_by_interface_t * mp)
{
  vl_api_classify_table_by_interface_reply_t *rmp;
  int rv = 0;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 *acl = 0;

  vec_validate (acl, IN_OUT_ACL_N_TABLES - 1);
  vec_set (acl, ~0);

  VALIDATE_SW_IF_INDEX (mp);

  in_out_acl_main_t *am = &in_out_acl_main;

  int if_idx;
  u32 type;

  for (type = 0; type < IN_OUT_ACL_N_TABLES; type++)
    {
      u32 *vec_tbl =
	am->classify_table_index_by_sw_if_index[IN_OUT_ACL_INPUT_TABLE_GROUP]
	[type];
      if (vec_len (vec_tbl))
	{
	  for (if_idx = 0; if_idx < vec_len (vec_tbl); if_idx++)
	    {
	      if (vec_elt (vec_tbl, if_idx) == ~0 || sw_if_index != if_idx)
		{
		  continue;
		}
	      acl[type] = vec_elt (vec_tbl, if_idx);
	    }
	}
    }

  BAD_SW_IF_INDEX_LABEL;

   /* *INDENT-OFF* */
   REPLY_MACRO2(VL_API_CLASSIFY_TABLE_BY_INTERFACE_REPLY,
   ({
     rmp->sw_if_index = ntohl(sw_if_index);
     rmp->l2_table_id = ntohl(acl[IN_OUT_ACL_TABLE_L2]);
     rmp->ip4_table_id = ntohl(acl[IN_OUT_ACL_TABLE_IP4]);
     rmp->ip6_table_id = ntohl(acl[IN_OUT_ACL_TABLE_IP6]);
   }));
   /* *INDENT-ON* */
  vec_free (acl);
}

static void
vl_api_classify_table_info_t_handler (vl_api_classify_table_info_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vl_api_classify_table_info_reply_t *rmp = 0;

  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 table_id = ntohl (mp->table_id);
  vnet_classify_table_t *t;

   /* *INDENT-OFF* */
   pool_foreach (t, cm->tables,
   ({
     if (table_id == t - cm->tables)
       {
         rmp = vl_msg_api_alloc_as_if_client
           (sizeof (*rmp) + t->match_n_vectors * sizeof (u32x4));
         rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_TABLE_INFO_REPLY);
         rmp->context = mp->context;
         rmp->table_id = ntohl(table_id);
         rmp->nbuckets = ntohl(t->nbuckets);
         rmp->match_n_vectors = ntohl(t->match_n_vectors);
         rmp->skip_n_vectors = ntohl(t->skip_n_vectors);
         rmp->active_sessions = ntohl(t->active_elements);
         rmp->next_table_index = ntohl(t->next_table_index);
         rmp->miss_next_index = ntohl(t->miss_next_index);
         rmp->mask_length = ntohl(t->match_n_vectors * sizeof (u32x4));
         clib_memcpy(rmp->mask, t->mask, t->match_n_vectors * sizeof(u32x4));
         rmp->retval = 0;
         break;
       }
   }));
   /* *INDENT-ON* */

  if (rmp == 0)
    {
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_TABLE_INFO_REPLY);
      rmp->context = mp->context;
      rmp->retval = ntohl (VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND);
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_classify_session_details (vl_api_registration_t * reg,
			       u32 table_id,
			       u32 match_length,
			       vnet_classify_entry_t * e, u32 context)
{
  vl_api_classify_session_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_SESSION_DETAILS);
  rmp->context = context;
  rmp->table_id = ntohl (table_id);
  rmp->hit_next_index = ntohl (e->next_index);
  rmp->advance = ntohl (e->advance);
  rmp->opaque_index = ntohl (e->opaque_index);
  rmp->match_length = ntohl (match_length);
  clib_memcpy (rmp->match, e->key, match_length);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_classify_session_dump_t_handler (vl_api_classify_session_dump_t * mp)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vl_api_registration_t *reg;

  u32 table_id = ntohl (mp->table_id);
  vnet_classify_table_t *t;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (t, cm->tables,
  ({
    if (table_id == t - cm->tables)
      {
        vnet_classify_bucket_t * b;
        vnet_classify_entry_t * v, * save_v;
        int i, j, k;

        for (i = 0; i < t->nbuckets; i++)
          {
            b = &t->buckets [i];
            if (b->offset == 0)
              continue;

            save_v = vnet_classify_get_entry (t, b->offset);
            for (j = 0; j < (1<<b->log2_pages); j++)
              {
                for (k = 0; k < t->entries_per_page; k++)
                  {
                    v = vnet_classify_entry_at_index
                      (t, save_v, j*t->entries_per_page + k);
                    if (vnet_classify_entry_is_free (v))
                      continue;

                    send_classify_session_details
                      (reg, table_id, t->match_n_vectors * sizeof (u32x4),
                       v, mp->context);
                  }
              }
          }
        break;
      }
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_flow_classify_set_interface_t_handler
  (vl_api_flow_classify_set_interface_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_flow_classify_set_interface_reply_t *rmp;
  int rv;
  u32 sw_if_index, ip4_table_index, ip6_table_index;

  ip4_table_index = ntohl (mp->ip4_table_index);
  ip6_table_index = ntohl (mp->ip6_table_index);
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_set_flow_classify_intfc (vm, sw_if_index, ip4_table_index,
				     ip6_table_index, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_FLOW_CLASSIFY_SET_INTERFACE_REPLY);
}

static void
send_flow_classify_details (u32 sw_if_index,
			    u32 table_index, vl_api_registration_t * reg,
			    u32 context)
{
  vl_api_flow_classify_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_FLOW_CLASSIFY_DETAILS);
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->table_index = htonl (table_index);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_flow_classify_dump_t_handler (vl_api_flow_classify_dump_t * mp)
{
  vl_api_registration_t *reg;
  flow_classify_main_t *pcm = &flow_classify_main;
  u32 *vec_tbl;
  int i;
  u32 filter_sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  filter_sw_if_index = ntohl (mp->sw_if_index);
  if (filter_sw_if_index
      >= vec_len (pcm->classify_table_index_by_sw_if_index[mp->type]))
    return;

  if (filter_sw_if_index != ~0)
    vec_tbl =
      &pcm->classify_table_index_by_sw_if_index[mp->type][filter_sw_if_index];
  else
    vec_tbl = pcm->classify_table_index_by_sw_if_index[mp->type];

  if (vec_len (vec_tbl))
    {
      for (i = 0; i < vec_len (vec_tbl); i++)
	{
	  if (vec_elt (vec_tbl, i) == ~0)
	    continue;

	  send_flow_classify_details (i, vec_elt (vec_tbl, i), reg,
				      mp->context);
	}
    }
}

static void vl_api_classify_set_interface_ip_table_t_handler
  (vl_api_classify_set_interface_ip_table_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_classify_set_interface_ip_table_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  u32 table_index = ntohl (mp->table_index);
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (mp->is_ipv6)
    rv = vnet_set_ip6_classify_intfc (vm, sw_if_index, table_index);
  else
    rv = vnet_set_ip4_classify_intfc (vm, sw_if_index, table_index);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY);
}

static void vl_api_classify_set_interface_l2_tables_t_handler
  (vl_api_classify_set_interface_l2_tables_t * mp)
{
  vl_api_classify_set_interface_l2_tables_reply_t *rmp;
  int rv;
  u32 sw_if_index, ip4_table_index, ip6_table_index, other_table_index;
  int enable;

  ip4_table_index = ntohl (mp->ip4_table_index);
  ip6_table_index = ntohl (mp->ip6_table_index);
  other_table_index = ntohl (mp->other_table_index);
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->is_input)
    rv = vnet_l2_input_classify_set_tables (sw_if_index, ip4_table_index,
					    ip6_table_index,
					    other_table_index);
  else
    rv = vnet_l2_output_classify_set_tables (sw_if_index, ip4_table_index,
					     ip6_table_index,
					     other_table_index);

  if (rv == 0)
    {
      if (ip4_table_index != ~0 || ip6_table_index != ~0
	  || other_table_index != ~0)
	enable = 1;
      else
	enable = 0;

      if (mp->is_input)
	vnet_l2_input_classify_enable_disable (sw_if_index, enable);
      else
	vnet_l2_output_classify_enable_disable (sw_if_index, enable);
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY);
}

static void vl_api_input_acl_set_interface_t_handler
  (vl_api_input_acl_set_interface_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_input_acl_set_interface_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  u32 ip4_table_index = ntohl (mp->ip4_table_index);
  u32 ip6_table_index = ntohl (mp->ip6_table_index);
  u32 l2_table_index = ntohl (mp->l2_table_index);
  u32 sw_if_index = ntohl (mp->sw_if_index);

  rv = vnet_set_input_acl_intfc (vm, sw_if_index, ip4_table_index,
				 ip6_table_index, l2_table_index, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_INPUT_ACL_SET_INTERFACE_REPLY);
}

static void vl_api_output_acl_set_interface_t_handler
  (vl_api_output_acl_set_interface_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_output_acl_set_interface_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  u32 ip4_table_index = ntohl (mp->ip4_table_index);
  u32 ip6_table_index = ntohl (mp->ip6_table_index);
  u32 l2_table_index = ntohl (mp->l2_table_index);
  u32 sw_if_index = ntohl (mp->sw_if_index);

  rv = vnet_set_output_acl_intfc (vm, sw_if_index, ip4_table_index,
				  ip6_table_index, l2_table_index,
				  mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_OUTPUT_ACL_SET_INTERFACE_REPLY);
}

/*
 * classify_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_classify;
#undef _
}

static clib_error_t *
classify_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (classify_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
