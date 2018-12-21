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

/* Here rules are extracted from below link with BSD License
 * https://rules.emergingthreats.net/open-nogpl/snort-2.9.0/emerging-all.rules */

dpi_app_match_rule app_match_rules[] = {
  {"www.cisco.com", NULL, "Cisco", DPI_APP_CISCO}
  ,
  {"*.google.com", NULL, "Google", DPI_APP_GOOGLE}
  ,
  {"www.bing.com", NULL, "Bing", DPI_APP_BING}
  ,
  {"www.msn.com", NULL, "MSN", DPI_APP_MSN}
  ,
  {"www.yahoo.com", NULL, "", DPI_APP_YAHOO}
  ,
  {"mail.yahoo.com", NULL, "YahooMail", DPI_APP_YAHOOMAIL}
  ,
  {"www.intel.com", NULL, "Intel", DPI_APP_INTEL}
  ,
  {"*.amazon.com", NULL, "Amazon", DPI_APP_AMAZON}
  ,
  {"*.amd.com", NULL, "AMD", DPI_APP_AMD}
  ,
  {"*.baidu.com", NULL, "Baidu", DPI_APP_BAIDU}
  ,
  {"*.apple.com", NULL, "Apple", DPI_APP_APPLE}
  ,
  {"*.facebook.com", NULL, "Facebook", DPI_APP_FACEBOOK}
  ,
  {"*.ebay.com", NULL, "Ebay", DPI_APP_EBAY}
  ,
  {"*.github.com", NULL, "GitHub", DPI_APP_GITHUB}
  ,
  {"*.gmail.com", NULL, "Gmail", DPI_APP_GMAIL}
  ,
  {"*.qq.com", NULL, "QQ", DPI_APP_QQ}
  ,
  {"weixin.qq.com", NULL, "Wechat", DPI_APP_WECHAT}
  ,
  {"*.pinterest.com", NULL, "", DPI_APP_PINTEREST}
  ,
  {"*.lenovo.com", NULL, "Levono", DPI_APP_LENOVO}
  ,
  {"*.linkedin.com", NULL, "LinkedIn", DPI_APP_LINKEDIN}
  ,
  {"*.skype.com", NULL, "Skype", DPI_APP_SKYPE}
  ,
  {"*.microsoft.com", NULL, "Microsoft", DPI_APP_MICROSOFT}
  ,
  {"*.netflix.com", NULL, "Netflix", DPI_APP_NETFLIX}
  ,
  {"*.nokia.com", NULL, "Nokia", DPI_APP_NOKIA}
  ,
  {"*.nvidia.com", NULL, "nVIDIA", DPI_APP_NVIDIA}
  ,
  {"*.office365.com", NULL, "Office", DPI_APP_OFFICE}
  ,
  {"*.oracle.com", NULL, "Oracle", DPI_APP_ORACLE}
  ,
  {"*.Outlook.com", NULL, "Outlook", DPI_APP_OUTLOOK}
  ,
  {"*.pandora.com", NULL, "Pandora", DPI_APP_PANDORA}
  ,
  {"*.paypal.com", NULL, "Paypal", DPI_APP_PAYPAL}
  ,
  {"*.sina.com", NULL, "Sina", DPI_APP_SINA}
  ,
  {"*.sogou.com", NULL, "Sogou", DPI_APP_SOGOU}
  ,
  {"*.symantec.com", NULL, "Symantec", DPI_APP_SYMANTEC}
  ,
  {"*.taobao.com", NULL, "Taobao", DPI_APP_TAOBAO}
  ,
  {"*.twitter.com", NULL, "Twitter", DPI_APP_TWITTER}
  ,
  {"*.ups.com", NULL, "UPS", DPI_APP_UPS}
  ,
  {"*.visa.com", NULL, "VISA", DPI_APP_VISA}
  ,
  {"*.mcafee.com", NULL, "Mcafee", DPI_APP_MCAFEE}
  ,
  {"*.vmware.com", NULL, "VMWare", DPI_APP_VMWARE}
  ,
  {"*.wordpress.com", NULL, "Wordpress", DPI_APP_WORDPRESS}
  ,
  {"www.adobe.com", NULL, "Adobe", DPI_APP_ADOBE}
  ,
  {"www.akamai.com", NULL, "Akamai", DPI_APP_AKAMAI}
  ,
  {"*.alienvault.com", NULL, "Alienvault", DPI_APP_ALIENVAULT}
  ,
  {"www.bitcomet.com", NULL, "Bitcomet", DPI_APP_BITCOMET}
  ,
  {"www.checkpoint.com", NULL, "Checkpoint", DPI_APP_CHECKPOINT}
  ,
  {"*.bloomberg.com", NULL, "Bloomberg", DPI_APP_BLOOMBERG}
  ,
  {"www.dell.com", NULL, "DELL", DPI_APP_DELL}
  ,
  {"www.f5.com", NULL, "F5", DPI_APP_F5}
  ,
  {"www.fireeye.com", NULL, "Fireeye", DPI_APP_FIREEYE}
  ,
  {"*.dropbox.com", NULL, "", DPI_APP_DROPBOX}
  ,

  {NULL, NULL, NULL, 0}
};

int
dpi_event_handler (unsigned int id, unsigned long long from,
		   unsigned long long to, unsigned int flags, void *ctx)
{
  (void) from;
  (void) to;
  (void) flags;

  dpi_cb_args_t *args = (dpi_cb_args_t *) ctx;

  args->res = 1;
  args->id = id;

  return 0;
}

int
dpi_search_host_protocol (dpi_flow_info_t * flow,
			  char *str_to_match,
			  u32 str_to_match_len,
			  u16 master_protocol_id, u32 * host_protocol_id)
{
  dpi_main_t *dm = &dpi_main;
  dpi_entry_t entry = dm->default_db;
  dpi_cb_args_t args = { };
  int ret;

  /* First search default database */
  ret = hs_scan_stream (flow->stream,
			(const char *) str_to_match, str_to_match_len, 0,
			entry.scratch, dpi_event_handler, (void *) &args);
  if ((ret != HS_SUCCESS) && (ret != HS_SCAN_TERMINATED))
    {
      return DPI_PROTOCOL_UNKNOWN;
    }
  else
    {
      flow->app_id = args.id;
      flow->detect_done = 1;
      goto done;
    }

done:
  if (flow->app_id != ~0)
    {
      /* Move the protocol to right position */
      flow->detected_protocol[1] =
	master_protocol_id, flow->detected_protocol[0] = flow->app_id;
      *host_protocol_id = flow->app_id;

      return (flow->detected_protocol[0]);
    }

  return DPI_PROTOCOL_UNKNOWN;
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
dpi_create_db_entry (dpi_entry_t * entry, u32 num, u32 mode)
{
  hs_compile_error_t *compile_err;

  if (hs_compile_multi
      ((const char **) entry->expressions, entry->flags, entry->ids,
       num, mode, NULL, &entry->database, &compile_err) != HS_SUCCESS)
    {
      return -1;
    }

  if (hs_alloc_scratch (entry->database, &entry->scratch) != HS_SUCCESS)
    {
      hs_free_database (entry->database);
      entry->database = NULL;
      return -1;
    }

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
      key4.key[0] = a->src_ip.ip4.as_u32
	| (((u64) a->dst_ip.ip4.as_u32) << 32);
      key4.key[1] = (((u64) a->protocol) << 32)
	| ((u32) clib_host_to_net_u16 (a->src_port) << 16)
	| clib_host_to_net_u16 (a->dst_port);
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
      flow->info->app_id = ~0;

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
	  pool_put (dm->dpi_infos, flow->info);
	  pool_put (dm->dpi_flows, flow);
	  return VNET_API_ERROR_INVALID_REGISTRATION;
	}

      /* Open a Hyperscan stream for each flow */
      hs_error_t err = hs_open_stream (dm->default_db.database, 0,
				       &(flow->info->stream));
      if (err != HS_SUCCESS)
	{
	  pool_put (dm->dpi_infos, flow->info);
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

      /* Close the Hyperscan stream for each flow */
      hs_error_t err = hs_close_stream (flow->info->stream, NULL,
					NULL, NULL);
      if (err != HS_SUCCESS)
	{
	  return VNET_API_ERROR_INVALID_REGISTRATION;
	}

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
      key4.key[0] = a->dst_ip.ip4.as_u32
	| (((u64) a->src_ip.ip4.as_u32) << 32);
      key4.key[1] = (((u64) a->protocol) << 32)
	| ((u32) clib_host_to_net_u16 (a->dst_port) << 16)
	| clib_host_to_net_u16 (a->src_port);
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
dpi_tcp_reass (tcp_reass_args_t * a)
{
  dpi_main_t *dm = &dpi_main;
  dpi_flow_entry_t *flow;

  flow = pool_elt_at_index (dm->dpi_flows, a->flow_id);
  if (flow == NULL)
    return -1;

  flow->reass_en = a->reass_en;
  flow->reass_dir = a->reass_dir;
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

int
dpi_init_hs_database (dpi_entry_t * entry)
{
  u32 i, j;
  u32 rule_num = 0;
  unsigned char *free_list;
  int rv;

  for (i = 0;
       (app_match_rules[i].host != NULL
	|| app_match_rules[i].pattern != NULL); i++)
    {
      rule_num++;
    }

  entry->expressions = (regex_t *) calloc (sizeof (char *), rule_num + 1);
  if (entry->expressions == NULL)
    return -1;

  entry->ids = (u32 *) calloc (sizeof (u32), rule_num + 1);
  if (entry->ids == NULL)
    {
      free (entry->expressions);
      return -1;
    }

  entry->flags = (u32 *) calloc (sizeof (u32), rule_num + 1);
  if (entry->ids == NULL)
    {
      free (entry->expressions);
      free (entry->ids);
      return -1;
    }

  free_list = (unsigned char *) calloc (sizeof (unsigned char), rule_num + 1);
  if (free_list == NULL)
    {
      free (entry->expressions);
      free (entry->ids);
      free (entry->flags);
      return -1;
    }

  /* first choose pattern, otherwise choose host */
  for (i = 0, j = 0;
       (app_match_rules[i].host != NULL
	|| app_match_rules[i].pattern != NULL); i++)
    {
      if (app_match_rules[i].pattern)
	{
	  entry->expressions[j] = (regex_t) (app_match_rules[i].pattern);
	  entry->ids[j] = app_match_rules[i].app_id;
	  entry->flags[j] = HS_FLAG_SINGLEMATCH;
	  free_list[j] = 0;
	  ++j;
	}
      else
	{
	  /* need to allocate additional buffer for rules */
	  entry->expressions[j] =
	    (regex_t) host2hex (app_match_rules[i].host);
	  if (entry->expressions[j] != NULL)
	    {
	      entry->ids[j] = app_match_rules[i].app_id;
	      entry->flags[j] = HS_FLAG_SINGLEMATCH;
	      free_list[j] = 1;
	      ++j;
	    }
	}
    }

  rv = dpi_create_db_entry (entry, j, HS_MODE_STREAM);

  /* Need to free additional buffers */
  for (i = 0; i < j; ++i)
    {
      if (free_list[i])
	free (entry->expressions[i]);
    }

  free (entry->expressions);
  free (entry->ids);
  free (entry->flags);
  free (free_list);
  return rv;
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

  /* Init default Hyperscan database */
  dpi_init_hs_database (&dm->default_db);

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
