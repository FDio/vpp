/*
 *------------------------------------------------------------------
 * flow_api.c - flow api
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
#include <vnet/ip/ip_types_api.h>
#include <vnet/udp/udp_local.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>

#include <vnet/fib/fib_table.h>
#include <vnet/ipfix-export/flow_report.h>
#include <vnet/ipfix-export/flow_report_classify.h>

#include <vnet/format_fns.h>
#include <vnet/ipfix-export/ipfix_export.api_enum.h>
#include <vnet/ipfix-export/ipfix_export.api_types.h>

#define REPLY_MSG_ID_BASE frm->msg_id_base
#include <vlibapi/api_helper_macros.h>

ipfix_exporter_t *
vnet_ipfix_exporter_lookup (const ip_address_t *ipfix_collector)
{
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp;

  pool_foreach (exp, frm->exporters)
    {
      if (ip_address_cmp (&exp->ipfix_collector, ipfix_collector) == 0)
	return exp;
    }

  return NULL;
}

/*
 * For backwards compatibility reasons index 0 in the set of exporters
 * is alwyas used for the exporter created via the set_ipfix_exporter
 * API.
 */
#define USE_INDEX_0   true
#define USE_ANY_INDEX false

static int
vl_api_set_ipfix_exporter_t_internal (
  u32 client_index, vl_api_address_t *mp_collector_address,
  u16 mp_collector_port, vl_api_address_t *mp_src_address, u32 mp_vrf_id,
  u32 mp_path_mtu, u32 mp_template_interval, bool mp_udp_checksum,
  bool use_index_0, bool is_create)
{
  vlib_main_t *vm = vlib_get_main ();
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp;
  vl_api_registration_t *reg;
  ip_address_t collector, src;
  u16 collector_port = UDP_DST_PORT_ipfix;
  u32 path_mtu;
  u32 template_interval;
  u8 udp_checksum;
  u32 fib_id;
  u32 fib_index = ~0;
  u32 ip_header_size;

  reg = vl_api_client_index_to_registration (client_index);
  if (!reg)
    return VNET_API_ERROR_UNIMPLEMENTED;

  if (use_index_0)
    {
      /*
       * In this case we update the existing exporter. There is no delete
       * for exp[0]
       */
      exp = &frm->exporters[0];

      /* Collector address must be IPv4 for exp[0] */
      collector.version = AF_IP4;
      ip4_address_decode (mp_collector_address->un.ip4, &collector.ip.ip4);
    }
  else
    {
      ip_address_decode2 (mp_collector_address, &collector);
      if (is_create)
	{
	  exp = vnet_ipfix_exporter_lookup (&collector);
	  if (!exp)
	    {
	      /* Create a new exporter instead of updating an existing one */
	      if (pool_elts (frm->exporters) >= IPFIX_EXPORTERS_MAX)
		return VNET_API_ERROR_INVALID_VALUE;
	      pool_get (frm->exporters, exp);
	    }
	}
      else
	{
	  /* Delete the exporter */
	  exp = vnet_ipfix_exporter_lookup (&collector);
	  if (!exp)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;

	  pool_put (frm->exporters, exp);
	  return 0;
	}
    }

  collector_port = ntohs (mp_collector_port);
  if (collector_port == (u16) ~ 0)
    collector_port = UDP_DST_PORT_ipfix;
  ip_address_decode2 (mp_src_address, &src);
  fib_id = ntohl (mp_vrf_id);

  ip4_main_t *im = &ip4_main;
  if (fib_id == ~0)
    {
      fib_index = ~0;
    }
  else
    {
      uword *p = hash_get (im->fib_index_by_table_id, fib_id);
      if (!p)
	return VNET_API_ERROR_NO_SUCH_FIB;
      fib_index = p[0];
    }

  path_mtu = ntohl (mp_path_mtu);
  if (path_mtu == ~0)
    path_mtu = 512;		// RFC 7011 section 10.3.3.
  template_interval = ntohl (mp_template_interval);
  if (template_interval == ~0)
    template_interval = 20;
  udp_checksum = mp_udp_checksum;

  /*
   * If the collector address is set then the src must be too.
   * Collector address can be set to 0 to disable exporter
   */
  if (!ip_address_is_zero (&collector) && ip_address_is_zero (&src))
    return VNET_API_ERROR_INVALID_VALUE;
  if (collector.version != src.version)
    return VNET_API_ERROR_INVALID_VALUE;

  if (path_mtu > 1450 /* vpp does not support fragmentation */ )
    return VNET_API_ERROR_INVALID_VALUE;

  if (path_mtu < 68)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Calculate how much header data we need. */
  if (collector.version == AF_IP4)
    ip_header_size = sizeof (ip4_header_t);
  else
    ip_header_size = sizeof (ip6_header_t);
  exp->all_headers_size = ip_header_size + sizeof (udp_header_t) +
			  sizeof (ipfix_message_header_t) +
			  sizeof (ipfix_set_header_t);

  /* Reset report streams if we are reconfiguring IP addresses */
  if (ip_address_cmp (&exp->ipfix_collector, &collector) ||
      ip_address_cmp (&exp->src_address, &src) ||
      exp->collector_port != collector_port)
    vnet_flow_reports_reset (exp);

  exp->ipfix_collector = collector;
  exp->collector_port = collector_port;
  exp->src_address = src;
  exp->fib_index = fib_index;
  exp->path_mtu = path_mtu;
  exp->template_interval = template_interval;
  exp->udp_checksum = udp_checksum;

  /* Turn on the flow reporting process */
  vlib_process_signal_event (vm, flow_report_process_node.index, 1, 0);

  return 0;
}

static void
vl_api_set_ipfix_exporter_t_handler (vl_api_set_ipfix_exporter_t *mp)
{
  vl_api_set_ipfix_exporter_reply_t *rmp;
  flow_report_main_t *frm = &flow_report_main;
  int rv = vl_api_set_ipfix_exporter_t_internal (
    mp->client_index, &mp->collector_address, mp->collector_port,
    &mp->src_address, mp->vrf_id, mp->path_mtu, mp->template_interval,
    mp->udp_checksum, USE_INDEX_0, 0);

  REPLY_MACRO (VL_API_SET_IPFIX_EXPORTER_REPLY);
}

static void
vl_api_ipfix_exporter_create_delete_t_handler (
  vl_api_ipfix_exporter_create_delete_t *mp)
{
  vl_api_ipfix_exporter_create_delete_reply_t *rmp;
  flow_report_main_t *frm = &flow_report_main;
  int rv = vl_api_set_ipfix_exporter_t_internal (
    mp->client_index, &mp->collector_address, mp->collector_port,
    &mp->src_address, mp->vrf_id, mp->path_mtu, mp->template_interval,
    mp->udp_checksum, USE_ANY_INDEX, mp->is_create);

  REPLY_MACRO (VL_API_IPFIX_EXPORTER_CREATE_DELETE_REPLY);
}

static void
vl_api_ipfix_exporter_dump_t_handler (vl_api_ipfix_exporter_dump_t * mp)
{
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp = pool_elt_at_index (flow_report_main.exporters, 0);
  vl_api_registration_t *reg;
  vl_api_ipfix_exporter_details_t *rmp;
  ip4_main_t *im = &ip4_main;
  u32 vrf_id;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs ((REPLY_MSG_ID_BASE) + VL_API_IPFIX_EXPORTER_DETAILS);
  rmp->context = mp->context;

  ip_address_encode2 (&exp->ipfix_collector, &rmp->collector_address);
  rmp->collector_port = htons (exp->collector_port);
  ip_address_encode2 (&exp->src_address, &rmp->src_address);

  if (exp->fib_index == ~0)
    vrf_id = ~0;
  else
    vrf_id = im->fibs[exp->fib_index].ft_table_id;
  rmp->vrf_id = htonl (vrf_id);
  rmp->path_mtu = htonl (exp->path_mtu);
  rmp->template_interval = htonl (exp->template_interval);
  rmp->udp_checksum = (exp->udp_checksum != 0);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
ipfix_all_fill_details (vl_api_ipfix_all_exporter_details_t *rmp,
			ipfix_exporter_t *exp)
{
  ip4_main_t *im = &ip4_main;
  u32 vrf_id;

  ip_address_encode2 (&exp->ipfix_collector, &rmp->collector_address);
  rmp->collector_port = htons (exp->collector_port);
  ip_address_encode2 (&exp->src_address, &rmp->src_address);

  if (exp->fib_index == ~0)
    vrf_id = ~0;
  else
    vrf_id = im->fibs[exp->fib_index].ft_table_id;
  rmp->vrf_id = htonl (vrf_id);
  rmp->path_mtu = htonl (exp->path_mtu);
  rmp->template_interval = htonl (exp->template_interval);
  rmp->udp_checksum = (exp->udp_checksum != 0);
}

static void
ipfix_all_exporter_details (flow_report_main_t *frm, u32 index,
			    vl_api_registration_t *rp, u32 context)
{
  ipfix_exporter_t *exp = pool_elt_at_index (frm->exporters, index);

  vl_api_ipfix_all_exporter_details_t *rmp;

  REPLY_MACRO_DETAILS4 (VL_API_IPFIX_ALL_EXPORTER_DETAILS, rp, context,
			({ ipfix_all_fill_details (rmp, exp); }));
}

static void
vl_api_ipfix_all_exporter_get_t_handler (vl_api_ipfix_all_exporter_get_t *mp)
{
  flow_report_main_t *frm = &flow_report_main;
  vl_api_ipfix_all_exporter_get_reply_t *rmp;
  int rv = 0;

  REPLY_AND_DETAILS_MACRO (
    VL_API_IPFIX_ALL_EXPORTER_GET_REPLY, frm->exporters,
    ({ ipfix_all_exporter_details (frm, cursor, rp, mp->context); }));
}

static void
  vl_api_set_ipfix_classify_stream_t_handler
  (vl_api_set_ipfix_classify_stream_t * mp)
{
  vl_api_set_ipfix_classify_stream_reply_t *rmp;
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp = &frm->exporters[0];
  u32 domain_id = 0;
  u32 src_port = UDP_DST_PORT_ipfix;
  int rv = 0;

  domain_id = ntohl (mp->domain_id);
  src_port = ntohs (mp->src_port);

  if (fcm->src_port != 0 &&
      (fcm->domain_id != domain_id || fcm->src_port != (u16) src_port))
    {
      int rv = vnet_stream_change (exp, fcm->domain_id, fcm->src_port,
				   domain_id, (u16) src_port);
      ASSERT (rv == 0);
    }

  fcm->domain_id = domain_id;
  fcm->src_port = (u16) src_port;

  REPLY_MACRO (VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY);
}

static void
  vl_api_ipfix_classify_stream_dump_t_handler
  (vl_api_ipfix_classify_stream_dump_t * mp)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  vl_api_registration_t *reg;
  vl_api_ipfix_classify_stream_details_t *rmp;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_IPFIX_CLASSIFY_STREAM_DETAILS);
  rmp->context = mp->context;
  rmp->domain_id = htonl (fcm->domain_id);
  rmp->src_port = htons (fcm->src_port);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_ipfix_classify_table_add_del_t_handler
  (vl_api_ipfix_classify_table_add_del_t * mp)
{
  vl_api_ipfix_classify_table_add_del_reply_t *rmp;
  vl_api_registration_t *reg;
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp = &frm->exporters[0];
  vnet_flow_report_add_del_args_t args;
  ipfix_classify_table_t *table;
  int is_add;
  u32 classify_table_index;
  u8 ip_version;
  u8 transport_protocol;
  int rv = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  classify_table_index = ntohl (mp->table_id);
  ip_version = (mp->ip_version == ADDRESS_IP4) ? 4 : 6;
  transport_protocol = mp->transport_protocol;
  is_add = mp->is_add;

  if (fcm->src_port == 0)
    {
      /* call set_ipfix_classify_stream first */
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto out;
    }

  clib_memset (&args, 0, sizeof (args));

  table = 0;
  int i;
  for (i = 0; i < vec_len (fcm->tables); i++)
    if (ipfix_classify_table_index_valid (i))
      if (fcm->tables[i].classify_table_index == classify_table_index)
	{
	  table = &fcm->tables[i];
	  break;
	}

  if (is_add)
    {
      if (table)
	{
	  rv = VNET_API_ERROR_VALUE_EXIST;
	  goto out;
	}
      table = ipfix_classify_add_table ();
      table->classify_table_index = classify_table_index;
    }
  else
    {
      if (!table)
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	  goto out;
	}
    }

  table->ip_version = ip_version;
  table->transport_protocol = transport_protocol;

  args.opaque.as_uword = table - fcm->tables;
  args.rewrite_callback = ipfix_classify_template_rewrite;
  args.flow_data_callback = ipfix_classify_send_flows;
  args.is_add = is_add;
  args.domain_id = fcm->domain_id;
  args.src_port = fcm->src_port;

  rv = vnet_flow_report_add_del (exp, &args, NULL);

  /* If deleting, or add failed */
  if (is_add == 0 || (rv && is_add))
    ipfix_classify_delete_table (table - fcm->tables);

out:
  REPLY_MACRO (VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY);
}

static void
send_ipfix_classify_table_details (u32 table_index,
				   vl_api_registration_t * reg, u32 context)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  vl_api_ipfix_classify_table_details_t *mp;

  ipfix_classify_table_t *table = &fcm->tables[table_index];

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IPFIX_CLASSIFY_TABLE_DETAILS);
  mp->context = context;
  mp->table_id = htonl (table->classify_table_index);
  mp->ip_version = (table->ip_version == 4) ? ADDRESS_IP4 : ADDRESS_IP6;
  mp->transport_protocol = table->transport_protocol;

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
  vl_api_ipfix_classify_table_dump_t_handler
  (vl_api_ipfix_classify_table_dump_t * mp)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  vl_api_registration_t *reg;
  u32 i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  for (i = 0; i < vec_len (fcm->tables); i++)
    if (ipfix_classify_table_index_valid (i))
      send_ipfix_classify_table_details (i, reg, mp->context);
}

static void
vl_api_ipfix_flush_t_handler (vl_api_ipfix_flush_t * mp)
{
  flow_report_main_t *frm = &flow_report_main;
  vl_api_ipfix_flush_reply_t *rmp;
  vl_api_registration_t *reg;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* poke the flow reporting process */
  vlib_process_signal_event (vm, flow_report_process_node.index,
			     1 /* type_opaque */ , 0 /* data */ );

  REPLY_MACRO (VL_API_IPFIX_FLUSH_REPLY);
}

#include <vnet/ipfix-export/ipfix_export.api.c>
static clib_error_t *
flow_api_hookup (vlib_main_t * vm)
{
  flow_report_main_t *frm = &flow_report_main;
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (flow_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
