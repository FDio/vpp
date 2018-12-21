/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel, Travelping and/or its affiliates.
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

#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/dpo/dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/flow/flow.h>

#include <dpi/dpi.h>

dpi_main_t dpi_main;
dpi_entry_t *dpi_dbs = NULL;

#if CLIB_DEBUG > 0
#define dpi_debug clib_warning
#else
#define dpi_debug(...)              \
  do { } while (0)
#endif


int
dpi_search_host_protocol (dpi_flow_info_t * flow,
			  char *str_to_match,
			  u32 str_to_match_len,
			  u16 master_protocol_id, u32 * host_protocol_id)
{
  dpi_main_t *dm = &dpi_main;
  dpi_adr_t *adr;

  vec_foreach (adr, dm->dpi_adrs)
  {
    if (dpi_db_lookup (adr->db_id, str_to_match, str_to_match_len) == 0)
      {
	flow->app_id = adr->app_id;
	break;
      }
  }


  if (flow->app_id != ~0)
    {
      /* Move the protocol to right position */
      flow->detected_protocol[1] = master_protocol_id,
	flow->detected_protocol[0] = flow->app_id;
      *host_protocol_id = flow->app_id;

      return (flow->detected_protocol[0]);
    }

  return (DPI_PROTOCOL_UNKNOWN);
}

int
dpi_get_db_ref_count (u32 db_index)
{
  if (db_index != ~0)
    {
      dpi_entry_t *entry = pool_elt_at_index (dpi_dbs, db_index);
      return entry->ref_cnt;
    }

  return 0;
}

void
dpi_cleanup_db_entry (dpi_entry_t * entry)
{
  regex_t *regex = NULL;

  vec_foreach (regex, entry->expressions)
  {
    vec_free (*regex);
  }

  hs_free_database (entry->database);
  hs_free_scratch (entry->scratch);
  vec_free (entry->expressions);
  vec_free (entry->flags);

  memset (entry, 0, sizeof (dpi_entry_t));
}

char *
host2hex (const char *str)
{
  int len, i;
  char *hexbuf, *buf;

  len = strlen (str);
  hexbuf = (char *) malloc (len * 4 + 1);
  if (!hexbuf)
    return (NULL);

  for (i = 0, buf = hexbuf; i < len; i++, buf += 4)
    {
      snprintf (buf, 5, "\\x%02x", (const char) str[i]);
    }
  *buf = '\0';

  return hexbuf;
}

int
dpi_create_update_db (dpi_app_t * app)
{
  dpi_main_t *dm = &dpi_main;
  dpi_entry_t *entry = NULL;
  hs_compile_error_t *compile_err = NULL;
  int error = 0;
  u32 index = 0;
  u32 rule_index = 0;
  dpi_rule_t *rule = NULL;
  u8 *expression;

  if (app->db_index != ~0)
    {
      entry = pool_elt_at_index (dpi_dbs, app->db_index);
      if (!entry)
	return -1;

      dpi_cleanup_db_entry (entry);
    }
  else
    {
      pool_get (dpi_dbs, entry);
      if (!entry)
	return -1;

      memset (entry, 0, sizeof (*entry));
      app->db_index = entry - dpi_dbs;
    }

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     regex_t regex = NULL;
     rule = pool_elt_at_index(app->rules, index);

     if(rule->pattern)
       {
         vec_append(regex, rule->pattern);
       }
     else if (rule->host)
       {
         expression = (u8 *)host2hex((const char *)(rule->host));
         vec_append(regex, expression);
       }

     dpi_debug("app id: %u, regex: %s", app - dm->dpi_apps, regex);

     vec_add1(entry->expressions, regex);
     vec_add1(entry->flags, HS_FLAG_SINGLEMATCH);
  }));
  /* *INDENT-ON* */

  if (hs_compile_multi
      ((const char **) entry->expressions, entry->flags, NULL,
       vec_len (entry->expressions), HS_MODE_BLOCK, NULL, &entry->database,
       &compile_err) != HS_SUCCESS)
    {
      error = -1;
      goto done;
    }

  if (hs_alloc_scratch (entry->database, &entry->scratch) != HS_SUCCESS)
    {
      hs_free_database (entry->database);
      entry->database = NULL;
      error = -1;
      goto done;
    }

  entry->name = vec_dup (app->name);

done:
  return error;
}



int
dpi_event_handler (unsigned int id, unsigned long long from,
		   unsigned long long to, unsigned int flags, void *ctx)
{
  (void) from;
  (void) to;
  (void) flags;

  dpi_cb_args_t *args = (dpi_cb_args_t *) ctx;

  args->res = 1;

  return 0;
}

int
dpi_db_lookup (u32 db_index, char *str, u32 length)
{
  dpi_entry_t *entry = NULL;
  int ret = 0;
  dpi_cb_args_t args = { };

  if (db_index == ~0)
    return -1;

  entry = pool_elt_at_index (dpi_dbs, db_index);
  if (!entry)
    return -1;

  ret = hs_scan (entry->database, (const char *) str, length, 0,
		 entry->scratch, dpi_event_handler, (void *) &args);
  if ((ret != HS_SUCCESS) && (ret != HS_SCAN_TERMINATED))
    return -1;

  if (args.res == 0)
    return -1;

  return 0;
}

int
dpi_db_remove (u32 db_index)
{
  dpi_entry_t *entry = NULL;

  entry = pool_elt_at_index (dpi_dbs, db_index);
  if (!entry)
    return -1;

  dpi_cleanup_db_entry (entry);

  pool_put (dpi_dbs, entry);

  return 0;
}

int
dpi_app_add_del (u8 * name, u8 add)
{
  dpi_main_t *dm = &dpi_main;
  dpi_app_t *app = NULL;
  u32 index = 0;
  u32 rule_index = 0;
  uword *p = NULL;

  p = hash_get_mem (dm->dpi_app_by_name, name);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (dm->dpi_apps, app);
      memset (app, 0, sizeof (*app));

      app->name = vec_dup (name);
      app->rules_by_id = hash_create_mem (0, sizeof (u32), sizeof (uword));
      app->db_index = ~0;

      hash_set_mem (dm->dpi_app_by_name, app->name, app - dm->dpi_apps);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      hash_unset_mem (dm->dpi_app_by_name, name);
      app = pool_elt_at_index (dm->dpi_apps, p[0]);

      if (dpi_get_db_ref_count (app->db_index) != 0)
	return VNET_API_ERROR_INSTANCE_IN_USE;

      /* *INDENT-OFF* */
      hash_foreach(rule_index, index, app->rules_by_id,
      ({
         dpi_rule_t *rule = NULL;
         rule = pool_elt_at_index(app->rules, index);
         dpi_rule_add_del(app->name, rule->id, 0, NULL);
      }));
      /* *INDENT-ON* */

      dpi_db_remove (app->db_index);
      vec_free (app->name);
      hash_free (app->rules_by_id);
      pool_free (app->rules);
      pool_put (dm->dpi_apps, app);
    }

  return 0;
}


int
dpi_rule_add_del (u8 * app_name, u32 rule_index, u8 add,
		  dpi_rule_args_t * args)
{
  dpi_main_t *dm = &dpi_main;
  uword *p = NULL;
  dpi_app_t *app = NULL;
  dpi_rule_t *rule = NULL;
  int res = 0;

  p = hash_get_mem (dm->dpi_app_by_name, app_name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  app = pool_elt_at_index (dm->dpi_apps, p[0]);
  if (dpi_get_db_ref_count (app->db_index) != 0)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  p = hash_get_mem (app->rules_by_id, &rule_index);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (app->rules, rule);
      memset (rule, 0, sizeof (*rule));
      rule->id = rule_index;
      if (args->host)
	rule->host = vec_dup (args->host);
      if (args->pattern)
	rule->pattern = vec_dup (args->pattern);

      hash_set_mem (app->rules_by_id, &rule_index, rule - app->rules);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      rule = pool_elt_at_index (app->rules, p[0]);
      if (rule->host)
	vec_free (rule->host);
      if (rule->pattern)
	vec_free (rule->pattern);
      hash_unset_mem (app->rules_by_id, &rule_index);
      pool_put (app->rules, rule);
    }

  res = dpi_create_update_db (app);
  if (res < 0)
    return res;

  return 0;
}

int
dpi_flow_add_del (dpi_add_del_flow_args_t * a, u32 * flow_idp)
{
  dpi_main_t *dm = &dpi_main;
  vnet_main_t *vnm = dm->vnet_main;
  dpi4_flow_key_t key4;
  dpi6_flow_key_t key6;
  dpi_flow_entry_t *p;
  u32 is_ip6 = a->is_ipv6;
  u32 flow_id;
  dpi_flow_entry_t *flow;

  int not_found;
  if (!is_ip6)
    {
      key4.key[0] =
	a->src_ip.ip4.as_u32 | (((u64) a->dst_ip.ip4.as_u32) << 32);
      key4.key[1] =
	(((u64) a->protocol) << 32) | ((u32)
				       clib_host_to_net_u16 (a->src_port) <<
				       16) |
	clib_host_to_net_u16 (a->dst_port);
      key4.key[2] = (u64) a->fib_index;

      not_found =
	clib_bihash_search_inline_24_8 (&dm->dpi4_flow_by_key, &key4);
      p = (void *) &key4.value;
    }
  else
    {
      key6.key[0] = a->src_ip.ip6.as_u64[0];
      key6.key[1] = a->src_ip.ip6.as_u64[1];
      key6.key[2] = a->dst_ip.ip6.as_u64[0];
      key6.key[3] = a->dst_ip.ip6.as_u64[1];
      key6.key[4] = (((u64) a->protocol) << 32)
	| ((u32) clib_host_to_net_u16 (a->src_port) << 16)
	| clib_host_to_net_u16 (a->dst_port);
      key6.key[5] = (u64) a->fib_index;

      not_found =
	clib_bihash_search_inline_48_8 (&dm->dpi6_flow_by_key, &key6);
      p = (void *) &key6.value;
    }

  if (not_found)
    p = 0;

  if (a->is_add)
    {

      /* adding a flow entry: entry must not already exist */
      if (p)
	return VNET_API_ERROR_TUNNEL_EXIST;

      pool_get_aligned (dm->dpi_flows, flow, CLIB_CACHE_LINE_BYTES);
      clib_memset (flow, 0, sizeof (*flow));
      flow_id = flow - dm->dpi_flows;

      /* copy from arg structure */
#define _(x) flow->key.x = a->x;
      foreach_copy_field;
#undef _

      flow->next_index = DPI_INPUT_NEXT_IP4_LOOKUP;
      flow->flow_index = ~0;

      pool_get_aligned (dm->dpi_infos, flow->info, CLIB_CACHE_LINE_BYTES);
      clib_memset (flow->info, 0, sizeof (*flow->info));

      int add_failed;
      if (is_ip6)
	{
	  key6.value = (u64) flow_id;
	  add_failed = clib_bihash_add_del_48_8 (&dm->dpi6_flow_by_key,
						 &key6, 1 /*add */ );
	}
      else
	{
	  key4.value = (u64) flow_id;
	  add_failed = clib_bihash_add_del_24_8 (&dm->dpi4_flow_by_key,
						 &key4, 1 /*add */ );
	}

      if (add_failed)
	{
	  pool_put (dm->dpi_flows, flow);
	  return VNET_API_ERROR_INVALID_REGISTRATION;
	}
    }
  else
    {
      /* deleting a flow: flow must exist */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      flow_id = is_ip6 ? key6.value : key4.value;
      flow_id = (u32) (flow_id & (u32) (~0));
      flow = pool_elt_at_index (dm->dpi_flows, flow_id);

      if (!is_ip6)
	clib_bihash_add_del_24_8 (&dm->dpi4_flow_by_key, &key4, 0 /*del */ );
      else
	clib_bihash_add_del_48_8 (&dm->dpi6_flow_by_key, &key6, 0 /*del */ );

      if (flow->flow_index != ~0)
	vnet_flow_del (vnm, flow->flow_index);

      pool_put (dm->dpi_infos, flow->info);
      pool_put (dm->dpi_flows, flow);
    }

  if (flow_idp)
    *flow_idp = flow_id;

  return 0;
}

int
dpi_reverse_flow_add_del (dpi_add_del_flow_args_t * a, u32 flow_id)
{
  dpi_main_t *dm = &dpi_main;
  vnet_main_t *vnm = dm->vnet_main;
  dpi4_flow_key_t key4;
  dpi6_flow_key_t key6;
  dpi_flow_entry_t *p;
  u32 is_ip6 = a->is_ipv6;
  dpi_flow_entry_t *flow;

  int not_found;
  if (!is_ip6)
    {
      key4.key[0] =
	a->dst_ip.ip4.as_u32 | (((u64) a->src_ip.ip4.as_u32) << 32);
      key4.key[1] =
	(((u64) a->protocol) << 32) | ((u32) a->
				       dst_port << 16) | (a->src_port);
      key4.key[2] = (u64) a->fib_index;

      not_found =
	clib_bihash_search_inline_24_8 (&dm->dpi4_flow_by_key, &key4);
      p = (void *) &key4.value;
    }
  else
    {
      key6.key[0] = a->dst_ip.ip6.as_u64[0];
      key6.key[1] = a->dst_ip.ip6.as_u64[1];
      key6.key[2] = a->dst_ip.ip6.as_u64[0];
      key6.key[3] = a->dst_ip.ip6.as_u64[1];
      key6.key[4] = (((u64) a->protocol) << 32)
	| ((u32) a->dst_port << 16) | (a->src_port);
      key6.key[5] = (u64) a->fib_index;

      not_found =
	clib_bihash_search_inline_48_8 (&dm->dpi6_flow_by_key, &key6);
      p = (void *) &key6.value;
    }

  if (not_found)
    p = 0;

  if (a->is_add)
    {

      /* adding a flow entry: entry must not already exist */
      if (p)
	return VNET_API_ERROR_TUNNEL_EXIST;

      int add_failed;
      if (is_ip6)
	{
	  key6.value = (u64) flow_id | ((u64) 1 << 63);
	  add_failed = clib_bihash_add_del_48_8 (&dm->dpi6_flow_by_key,
						 &key6, 1 /*add */ );
	}
      else
	{
	  key4.value = (u64) flow_id | ((u64) 1 << 63);
	  add_failed = clib_bihash_add_del_24_8 (&dm->dpi4_flow_by_key,
						 &key4, 1 /*add */ );
	}

      if (add_failed)
	{
	  return VNET_API_ERROR_INVALID_REGISTRATION;
	}
    }
  else
    {
      /* deleting a flow: flow must exist */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      flow_id = is_ip6 ? key6.value : key4.value;
      flow = pool_elt_at_index (dm->dpi_flows, flow_id);

      if (!is_ip6)
	clib_bihash_add_del_24_8 (&dm->dpi4_flow_by_key, &key4, 0 /*del */ );
      else
	clib_bihash_add_del_48_8 (&dm->dpi6_flow_by_key, &key6, 0 /*del */ );

      if (flow->flow_index != ~0)
	vnet_flow_del (vnm, flow->flow_index);

      pool_put (dm->dpi_flows, flow);
    }

  return 0;
}

int
dpi_add_del_rx_flow (u32 hw_if_index, u32 flow_id, int is_add, u32 is_ipv6)
{
  dpi_main_t *dm = &dpi_main;
  vnet_main_t *vnm = dm->vnet_main;
  dpi_flow_entry_t *dpi_flow;
  vnet_flow_t *vent_flow;

  ip_port_and_mask_t src_port;
  ip_port_and_mask_t dst_port;


  dpi_flow = pool_elt_at_index (dm->dpi_flows, flow_id);

  src_port.port = dpi_flow->key.dst_port;
  src_port.mask = ~0;
  dst_port.port = dpi_flow->key.dst_port;
  dst_port.mask = ~0;

  if (is_add)
    {
      if (dpi_flow->flow_index == ~0)
	{
	  if (!is_ipv6)
	    {
	      ip4_address_and_mask_t src_addr4;
	      ip4_address_and_mask_t dst_addr4;
	      src_addr4.addr = dpi_flow->key.src_ip.ip4;
	      src_addr4.mask.as_u32 = ~0;
	      dst_addr4.addr = dpi_flow->key.dst_ip.ip4;
	      dst_addr4.mask.as_u32 = ~0;

	      vnet_flow_t flow4 = {
		.actions =
		  VNET_FLOW_ACTION_REDIRECT_TO_NODE | VNET_FLOW_ACTION_MARK,
		.mark_flow_id = flow_id + dm->flow_id_start,
		.redirect_node_index = 0,
		.type = VNET_FLOW_TYPE_IP4_N_TUPLE,
		.ip4_n_tuple = {
				.src_addr = src_addr4,
				.dst_addr = dst_addr4,
				.src_port = src_port,
				.dst_port = dst_port,
				.protocol = dpi_flow->key.protocol,
				}
		,
	      };
	      vent_flow = &flow4;
	    }
	  else
	    {
	      ip6_address_and_mask_t src_addr6;
	      ip6_address_and_mask_t dst_addr6;
	      src_addr6.addr.as_u64[0] = dpi_flow->key.src_ip.ip6.as_u64[0];
	      src_addr6.addr.as_u64[1] = dpi_flow->key.src_ip.ip6.as_u64[1];
	      src_addr6.mask.as_u64[0] = ~0;
	      src_addr6.mask.as_u64[1] = ~0;
	      dst_addr6.addr.as_u64[0] = dpi_flow->key.dst_ip.ip6.as_u64[0];
	      dst_addr6.addr.as_u64[1] = dpi_flow->key.dst_ip.ip6.as_u64[1];
	      dst_addr6.mask.as_u64[0] = ~0;
	      dst_addr6.mask.as_u64[1] = ~0;

	      vnet_flow_t flow6 = {
		.actions =
		  VNET_FLOW_ACTION_REDIRECT_TO_NODE | VNET_FLOW_ACTION_MARK,
		.mark_flow_id = flow_id + dm->flow_id_start,
		.redirect_node_index = 0,
		.type = VNET_FLOW_TYPE_IP6_N_TUPLE,
		.ip6_n_tuple = {
				.src_addr = src_addr6,
				.dst_addr = dst_addr6,
				.src_port = src_port,
				.dst_port = dst_port,
				.protocol = dpi_flow->key.protocol,
				}
		,
	      };
	      vent_flow = &flow6;
	    }
	  vnet_flow_add (vnm, vent_flow, &(dpi_flow->flow_index));
	}
      return vnet_flow_enable (vnm, dpi_flow->flow_index, hw_if_index);
    }

  /* flow index is removed when the flow is deleted */
  return vnet_flow_disable (vnm, dpi_flow->flow_index, hw_if_index);
}

void
dpi_flow_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable)
{
  if (is_ip6)
    vnet_feature_enable_disable ("ip6-unicast", "dpi6-input",
				 sw_if_index, is_enable, 0, 0);
  else
    vnet_feature_enable_disable ("ip4-unicast", "dpi4-input",
				 sw_if_index, is_enable, 0, 0);
}

#define DPI_HASH_NUM_BUCKETS (2 * 1024)
#define DPI_HASH_MEMORY_SIZE (1 << 20)

clib_error_t *
dpi_init (vlib_main_t * vm)
{
  dpi_main_t *dm = &dpi_main;

  dm->vnet_main = vnet_get_main ();
  dm->vlib_main = vm;

  vnet_flow_get_range (dm->vnet_main, "dpi", 1024 * 1024, &dm->flow_id_start);

  /* initialize the flow hash */
  clib_bihash_init_24_8 (&dm->dpi4_flow_by_key, "dpi4",
			 DPI_HASH_NUM_BUCKETS, DPI_HASH_MEMORY_SIZE);
  clib_bihash_init_48_8 (&dm->dpi6_flow_by_key, "dpi6",
			 DPI_HASH_NUM_BUCKETS, DPI_HASH_MEMORY_SIZE);

  dm->dpi_app_by_name = hash_create_vec ( /* initial length */ 32,
					 sizeof (u8), sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (dpi_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Deep Packet Inspection",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
