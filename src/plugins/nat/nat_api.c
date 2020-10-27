/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 *
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
/**
 * @file
 * @brief NAT plugin API implementation
 */

#include <nat/nat.h>
#include <nat/nat_inlines.h>
#include <nat/nat44/inlines.h>
#include <nat/lib/nat_inlines.h>
#include <nat/nat_ha.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <nat/nat_msg_enum.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <nat/nat44/ed_inlines.h>
#include <nat/lib/ipfix_logging.h>

#define vl_api_nat44_add_del_lb_static_mapping_t_endian vl_noop_handler
#define vl_api_nat44_nat44_lb_static_mapping_details_t_endian vl_noop_handler

/* define message structures */
#define vl_typedefs
#include <nat/nat_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <nat/nat_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <nat/nat_all_api_h.h>
#undef vl_api_version

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

/******************************/
/*** Common NAT plugin APIs ***/
/******************************/

static void
vl_api_nat_control_ping_t_handler (vl_api_nat_control_ping_t * mp)
{
  vl_api_nat_control_ping_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_CONTROL_PING_REPLY,
  ({
    rmp->vpe_pid = ntohl (getpid ());
  }));
  /* *INDENT-ON* */
}

static void *
vl_api_nat_control_ping_t_print (vl_api_nat_control_ping_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_control_ping ");

  FINISH;
}

static void
vl_api_nat_show_config_t_handler (vl_api_nat_show_config_t * mp)
{
  vl_api_nat_show_config_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_SHOW_CONFIG_REPLY,
  ({
    rmp->translation_buckets = htonl (sm->translation_buckets);
    rmp->translation_memory_size = 0;
    rmp->user_buckets = htonl (sm->user_buckets);
    rmp->user_memory_size = 0;
    rmp->max_translations_per_user = htonl (sm->max_translations_per_user);
    rmp->outside_vrf_id = htonl (sm->outside_vrf_id);
    rmp->inside_vrf_id = htonl (sm->inside_vrf_id);
    rmp->static_mapping_only = sm->static_mapping_only;
    rmp->static_mapping_connection_tracking =
      sm->static_mapping_connection_tracking;
    rmp->endpoint_dependent = sm->endpoint_dependent;
    rmp->out2in_dpo = sm->out2in_dpo;
    // these are obsolete
    rmp->dslite_ce = 0;
    rmp->deterministic = 0;
    rmp->nat64_bib_buckets = 0;
    rmp->nat64_bib_memory_size = 0;
    rmp->nat64_st_buckets = 0;
    rmp->nat64_st_memory_size = 0;
  }));
  /* *INDENT-ON* */
}

static void *
vl_api_nat_show_config_t_print (vl_api_nat_show_config_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_show_config ");

  FINISH;
}

static void
vl_api_nat_show_config_2_t_handler (vl_api_nat_show_config_2_t * mp)
{
  vl_api_nat_show_config_2_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_SHOW_CONFIG_2_REPLY,
  ({
    rmp->translation_buckets = htonl (sm->translation_buckets);
    rmp->translation_memory_size = 0;
    rmp->user_buckets = htonl (sm->user_buckets);
    rmp->user_memory_size = 0;
    rmp->max_translations_per_user = htonl (sm->max_translations_per_user);
    rmp->outside_vrf_id = htonl (sm->outside_vrf_id);
    rmp->inside_vrf_id = htonl (sm->inside_vrf_id);
    rmp->static_mapping_only = sm->static_mapping_only;
    rmp->static_mapping_connection_tracking =
      sm->static_mapping_connection_tracking;
    rmp->endpoint_dependent = sm->endpoint_dependent;
    rmp->out2in_dpo = sm->out2in_dpo;
    rmp->max_translations_per_thread = clib_net_to_host_u32(sm->max_translations_per_thread);
    rmp->max_users_per_thread = clib_net_to_host_u32(sm->max_users_per_thread);
    // these are obsolete
    rmp->dslite_ce = 0;
    rmp->deterministic = 0;
    rmp->nat64_bib_buckets = 0;
    rmp->nat64_bib_memory_size = 0;
    rmp->nat64_st_buckets = 0;
    rmp->nat64_st_memory_size = 0;
  }));
  /* *INDENT-ON* */
}

static void *
vl_api_nat_show_config_2_t_print (vl_api_nat_show_config_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_show_config_2 ");

  FINISH;
}

static void
vl_api_nat_set_workers_t_handler (vl_api_nat_set_workers_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_workers_reply_t *rmp;
  int rv = 0;
  uword *bitmap = 0;
  u64 mask;

  mask = clib_net_to_host_u64 (mp->worker_mask);

  if (sm->num_workers < 2)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  bitmap = clib_bitmap_set_multiple (bitmap, 0, mask, BITS (mask));
  rv = snat_set_workers (bitmap);
  clib_bitmap_free (bitmap);

send_reply:
  REPLY_MACRO (VL_API_NAT_SET_WORKERS_REPLY);
}

static void *
vl_api_nat_set_workers_t_print (vl_api_nat_set_workers_t * mp, void *handle)
{
  u8 *s;
  uword *bitmap = 0;
  u8 first = 1;
  int i;
  u64 mask = clib_net_to_host_u64 (mp->worker_mask);

  s = format (0, "SCRIPT: nat_set_workers ");
  bitmap = clib_bitmap_set_multiple (bitmap, 0, mask, BITS (mask));
  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, bitmap,
    ({
      if (first)
        s = format (s, "%d", i);
      else
        s = format (s, ",%d", i);
      first = 0;
    }));
  /* *INDENT-ON* */
  clib_bitmap_free (bitmap);
  FINISH;
}

static void
send_nat_worker_details (u32 worker_index, vl_api_registration_t * reg,
			 u32 context)
{
  vl_api_nat_worker_details_t *rmp;
  snat_main_t *sm = &snat_main;
  vlib_worker_thread_t *w =
    vlib_worker_threads + worker_index + sm->first_worker_index;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_WORKER_DETAILS + sm->msg_id_base);
  rmp->context = context;
  rmp->worker_index = htonl (worker_index);
  rmp->lcore_id = htonl (w->cpu_id);
  strncpy ((char *) rmp->name, (char *) w->name, ARRAY_LEN (rmp->name) - 1);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat_worker_dump_t_handler (vl_api_nat_worker_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  u32 *worker_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach (worker_index, sm->workers)
    send_nat_worker_details(*worker_index, reg, mp->context);
  /* *INDENT-ON* */
}

static void *
vl_api_nat_worker_dump_t_print (vl_api_nat_worker_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_worker_dump ");

  FINISH;
}

static void
vl_api_nat44_set_session_limit_t_handler (vl_api_nat44_set_session_limit_t *
					  mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_set_session_limit_reply_t *rmp;
  int rv = 0;

  rv = nat44_set_session_limit
    (ntohl (mp->session_limit), ntohl (mp->vrf_id));

  REPLY_MACRO (VL_API_NAT_SET_WORKERS_REPLY);
}

static void *
vl_api_nat44_set_session_limit_t_print (vl_api_nat44_set_session_limit_t *
					mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_set_session_limit ");
  s = format (s, "session_limit %d", ntohl (mp->session_limit));
  s = format (s, "vrf_id %d", ntohl (mp->vrf_id));

  FINISH;
}

static void
vl_api_nat_set_log_level_t_handler (vl_api_nat_set_log_level_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_log_level_reply_t *rmp;
  int rv = 0;

  if (sm->log_level > NAT_LOG_DEBUG)
    rv = VNET_API_ERROR_UNSUPPORTED;
  else
    sm->log_level = mp->log_level;

  REPLY_MACRO (VL_API_NAT_SET_WORKERS_REPLY);
}

static void *
vl_api_nat_set_log_level_t_print (vl_api_nat_set_log_level_t *
				  mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_set_log_level ");
  s = format (s, "log_level %d", mp->log_level);

  FINISH;
}

static void
  vl_api_nat44_plugin_enable_disable_t_handler
  (vl_api_nat44_plugin_enable_disable_t * mp)
{
  snat_main_t *sm = &snat_main;
  nat44_config_t c = { 0 };
  vl_api_nat44_plugin_enable_disable_reply_t *rmp;
  int rv = 0;

  if (mp->enable)
    {
      c.endpoint_dependent = mp->flags & NAT44_API_IS_ENDPOINT_DEPENDENT;
      c.static_mapping_only = mp->flags & NAT44_API_IS_STATIC_MAPPING_ONLY;
      c.connection_tracking = mp->flags & NAT44_API_IS_CONNECTION_TRACKING;
      c.out2in_dpo = mp->flags & NAT44_API_IS_OUT2IN_DPO;

      c.inside_vrf = ntohl (mp->inside_vrf);
      c.outside_vrf = ntohl (mp->outside_vrf);

      c.users = ntohl (mp->users);

      c.sessions = ntohl (mp->sessions);

      c.user_sessions = ntohl (mp->user_sessions);

      rv = nat44_plugin_enable (c);
    }
  else
    rv = nat44_plugin_disable ();

  REPLY_MACRO (VL_API_NAT44_PLUGIN_ENABLE_DISABLE_REPLY);
}

static void *vl_api_nat44_plugin_enable_disable_t_print
  (vl_api_nat44_plugin_enable_disable_t * mp, void *handle)
{
  u8 *s;
  u32 val;

  s = format (0, "SCRIPT: nat44_plugin_enable_disable ");
  if (mp->enable)
    {
      s = format (s, "enable ");
      if (mp->flags & NAT44_API_IS_ENDPOINT_DEPENDENT)
	s = format (s, "endpoint-dependent ");
      else
	s = format (s, "endpoint-indepenednet ");
      if (mp->flags & NAT44_API_IS_STATIC_MAPPING_ONLY)
	s = format (s, "static_mapping_only ");
      if (mp->flags & NAT44_API_IS_CONNECTION_TRACKING)
	s = format (s, "connection_tracking ");
      if (mp->flags & NAT44_API_IS_OUT2IN_DPO)
	s = format (s, "out2in_dpo ");
      val = ntohl (mp->inside_vrf);
      if (val)
	s = format (s, "inside_vrf %u ", val);
      val = ntohl (mp->outside_vrf);
      if (val)
	s = format (s, "outside_vrf %u ", val);
      val = ntohl (mp->users);
      if (val)
	s = format (s, "users %u ", val);
      val = ntohl (mp->user_memory);
      if (val)
	s = format (s, "user_memory %u ", val);
      val = ntohl (mp->sessions);
      if (val)
	s = format (s, "sessions %u ", val);
      val = ntohl (mp->session_memory);
      if (val)
	s = format (s, "session_memory %u ", val);
      val = ntohl (mp->user_sessions);
      if (val)
	s = format (s, "user_sessions %u ", val);
    }
  else
    s = format (s, "disable ");

  FINISH;
}

static void
vl_api_nat_ipfix_enable_disable_t_handler (vl_api_nat_ipfix_enable_disable_t *
					   mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ipfix_enable_disable_reply_t *rmp;
  int rv = 0;

  rv = nat_ipfix_logging_enable_disable (mp->enable,
					 clib_host_to_net_u32
					 (mp->domain_id),
					 clib_host_to_net_u16 (mp->src_port));

  REPLY_MACRO (VL_API_NAT_IPFIX_ENABLE_DISABLE_REPLY);
}

static void *
vl_api_nat_ipfix_enable_disable_t_print (vl_api_nat_ipfix_enable_disable_t *
					 mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_ipfix_enable_disable ");
  if (mp->domain_id)
    s = format (s, "domain %d ", clib_net_to_host_u32 (mp->domain_id));
  if (mp->src_port)
    s = format (s, "src_port %d ", clib_net_to_host_u16 (mp->src_port));
  if (!mp->enable)
    s = format (s, "disable ");

  FINISH;
}

static void
vl_api_nat_set_timeouts_t_handler (vl_api_nat_set_timeouts_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_timeouts_reply_t *rmp;
  int rv = 0;

  sm->udp_timeout = ntohl (mp->udp);
  sm->tcp_established_timeout = ntohl (mp->tcp_established);
  sm->tcp_transitory_timeout = ntohl (mp->tcp_transitory);
  sm->icmp_timeout = ntohl (mp->icmp);

  REPLY_MACRO (VL_API_NAT_SET_TIMEOUTS_REPLY);
}

static void *
vl_api_nat_set_timeouts_t_print (vl_api_nat_set_timeouts_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_set_timeouts ");
  s = format (s, "udp %d tcp_established %d tcp_transitory %d icmp %d\n",
	      ntohl (mp->udp),
	      ntohl (mp->tcp_established),
	      ntohl (mp->tcp_transitory), ntohl (mp->icmp));

  FINISH;
}

static void
vl_api_nat_get_timeouts_t_handler (vl_api_nat_get_timeouts_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_get_timeouts_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_GET_TIMEOUTS_REPLY,
  ({
    rmp->udp = htonl (sm->udp_timeout);
    rmp->tcp_established = htonl (sm->tcp_established_timeout);
    rmp->tcp_transitory = htonl (sm->tcp_transitory_timeout);
    rmp->icmp = htonl (sm->icmp_timeout);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_nat_get_timeouts_t_print (vl_api_nat_get_timeouts_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_get_timeouts");

  FINISH;
}

static void
  vl_api_nat_set_addr_and_port_alloc_alg_t_handler
  (vl_api_nat_set_addr_and_port_alloc_alg_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_addr_and_port_alloc_alg_reply_t *rmp;
  int rv = 0;
  u16 port_start, port_end;

  switch (mp->alg)
    {
    case NAT_ADDR_AND_PORT_ALLOC_ALG_DEFAULT:
      nat_set_alloc_addr_and_port_default ();
      break;
    case NAT_ADDR_AND_PORT_ALLOC_ALG_MAPE:
      nat_set_alloc_addr_and_port_mape (ntohs (mp->psid), mp->psid_offset,
					mp->psid_length);
      break;
    case NAT_ADDR_AND_PORT_ALLOC_ALG_RANGE:
      port_start = ntohs (mp->start_port);
      port_end = ntohs (mp->end_port);
      if (port_end <= port_start)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto send_reply;
	}
      nat_set_alloc_addr_and_port_range (port_start, port_end);
      break;
    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      break;
    }

send_reply:
  REPLY_MACRO (VL_API_NAT_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY);
}

static void *vl_api_nat_set_addr_and_port_alloc_alg_t_print
  (vl_api_nat_set_addr_and_port_alloc_alg_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_set_addr_and_port_alloc_alg ");
  s = format (s, "alg %d psid_offset %d psid_length %d psid %d start_port %d "
	      "end_port %d\n",
	      ntohl (mp->alg), ntohl (mp->psid_offset),
	      ntohl (mp->psid_length), ntohs (mp->psid),
	      ntohs (mp->start_port), ntohs (mp->end_port));

  FINISH;
}

static void
  vl_api_nat_get_addr_and_port_alloc_alg_t_handler
  (vl_api_nat_get_addr_and_port_alloc_alg_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_get_addr_and_port_alloc_alg_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY,
  ({
    rmp->alg = sm->addr_and_port_alloc_alg;
    rmp->psid_offset = sm->psid_offset;
    rmp->psid_length = sm->psid_length;
    rmp->psid = htons (sm->psid);
    rmp->start_port = htons (sm->start_port);
    rmp->end_port = htons (sm->end_port);
  }))
  /* *INDENT-ON* */
}

static void *vl_api_nat_get_addr_and_port_alloc_alg_t_print
  (vl_api_nat_get_addr_and_port_alloc_alg_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_get_addr_and_port_alloc_alg");

  FINISH;
}

static void
vl_api_nat_set_mss_clamping_t_handler (vl_api_nat_set_mss_clamping_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_mss_clamping_reply_t *rmp;
  int rv = 0;

  if (mp->enable)
    sm->mss_clamping = ntohs (mp->mss_value);
  else
    sm->mss_clamping = 0;

  REPLY_MACRO (VL_API_NAT_SET_MSS_CLAMPING_REPLY);
}

static void *
vl_api_nat_set_mss_clamping_t_print (vl_api_nat_set_mss_clamping_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_set_mss_clamping enable %d mss_value %d\n",
	      mp->enable, ntohs (mp->mss_value));

  FINISH;
}

static void
vl_api_nat_get_mss_clamping_t_handler (vl_api_nat_get_mss_clamping_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_get_mss_clamping_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_GET_MSS_CLAMPING_REPLY,
  ({
    rmp->enable = sm->mss_clamping ? 1 : 0;
    rmp->mss_value = htons (sm->mss_clamping);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_nat_get_mss_clamping_t_print (vl_api_nat_get_mss_clamping_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_get_mss_clamping");

  FINISH;
}

static void
vl_api_nat_ha_set_listener_t_handler (vl_api_nat_ha_set_listener_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_set_listener_reply_t *rmp;
  ip4_address_t addr;
  int rv;

  memcpy (&addr, &mp->ip_address, sizeof (addr));
  rv =
    nat_ha_set_listener (&addr, clib_net_to_host_u16 (mp->port),
			 clib_net_to_host_u32 (mp->path_mtu));

  REPLY_MACRO (VL_API_NAT_HA_SET_LISTENER_REPLY);
}

static void *
vl_api_nat_ha_set_listener_t_print (vl_api_nat_ha_set_listener_t * mp,
				    void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_ha_set_listener ");
  s = format (s, "ip_address %U ", format_ip4_address, mp->ip_address);
  s = format (s, "port %d ", clib_net_to_host_u16 (mp->port));
  s = format (s, "path_mtu %d", clib_net_to_host_u32 (mp->path_mtu));

  FINISH;
}

static void
vl_api_nat_ha_get_listener_t_handler (vl_api_nat_ha_get_listener_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_get_listener_reply_t *rmp;
  int rv = 0;
  ip4_address_t addr;
  u16 port;
  u32 path_mtu;

  nat_ha_get_listener (&addr, &port, &path_mtu);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_HA_GET_LISTENER_REPLY,
  ({
    clib_memcpy (rmp->ip_address, &addr, sizeof (ip4_address_t));
    rmp->port = clib_host_to_net_u16 (port);
    rmp->path_mtu = clib_host_to_net_u32 (path_mtu);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_nat_ha_get_listener_t_print (vl_api_nat_ha_get_listener_t * mp,
				    void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_ha_get_listener");

  FINISH;
}

static void
vl_api_nat_ha_set_failover_t_handler (vl_api_nat_ha_set_failover_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_set_failover_reply_t *rmp;
  ip4_address_t addr;
  int rv;

  memcpy (&addr, &mp->ip_address, sizeof (addr));
  rv =
    nat_ha_set_failover (&addr, clib_net_to_host_u16 (mp->port),
			 clib_net_to_host_u32 (mp->session_refresh_interval));

  REPLY_MACRO (VL_API_NAT_HA_SET_FAILOVER_REPLY);
}

static void *
vl_api_nat_ha_set_failover_t_print (vl_api_nat_ha_set_failover_t * mp,
				    void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_ha_set_failover ");
  s = format (s, "ip_address %U ", format_ip4_address, mp->ip_address);
  s = format (s, "port %d ", clib_net_to_host_u16 (mp->port));

  FINISH;
}

static void
vl_api_nat_ha_get_failover_t_handler (vl_api_nat_ha_get_failover_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_get_failover_reply_t *rmp;
  int rv = 0;
  ip4_address_t addr;
  u16 port;
  u32 session_refresh_interval;

  nat_ha_get_failover (&addr, &port, &session_refresh_interval);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_HA_GET_FAILOVER_REPLY,
  ({
    clib_memcpy (rmp->ip_address, &addr, sizeof (ip4_address_t));
    rmp->port = clib_host_to_net_u16 (port);
    rmp->session_refresh_interval = clib_host_to_net_u32 (session_refresh_interval);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_nat_ha_get_failover_t_print (vl_api_nat_ha_get_failover_t * mp,
				    void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_ha_get_failover");

  FINISH;
}

static void
vl_api_nat_ha_flush_t_handler (vl_api_nat_ha_flush_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_flush_reply_t *rmp;
  int rv = 0;

  nat_ha_flush (0);

  REPLY_MACRO (VL_API_NAT_HA_FLUSH_REPLY);
}

static void *
vl_api_nat_ha_flush_t_print (vl_api_nat_ha_flush_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_ha_flush ");

  FINISH;
}

static void
nat_ha_resync_completed_event_cb (u32 client_index, u32 pid, u32 missed_count)
{
  snat_main_t *sm = &snat_main;
  vl_api_registration_t *reg;
  vl_api_nat_ha_resync_completed_event_t *mp;

  reg = vl_api_client_index_to_registration (client_index);
  if (!reg)
    return;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->client_index = client_index;
  mp->pid = pid;
  mp->missed_count = clib_host_to_net_u32 (missed_count);
  mp->_vl_msg_id =
    ntohs (VL_API_NAT_HA_RESYNC_COMPLETED_EVENT + sm->msg_id_base);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_nat_ha_resync_t_handler (vl_api_nat_ha_resync_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_resync_reply_t *rmp;
  int rv;

  rv =
    nat_ha_resync (mp->client_index, mp->pid,
		   mp->want_resync_event ? nat_ha_resync_completed_event_cb :
		   NULL);

  REPLY_MACRO (VL_API_NAT_HA_RESYNC_REPLY);
}

static void *
vl_api_nat_ha_resync_t_print (vl_api_nat_ha_resync_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_ha_resync ");
  s =
    format (s, "want_resync_event %d pid %d", mp->want_resync_event,
	    clib_host_to_net_u32 (mp->pid));

  FINISH;
}

/*************/
/*** NAT44 ***/
/*************/
static void
vl_api_nat44_del_user_t_handler (vl_api_nat44_del_user_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_del_user_reply_t *rmp;
  ip4_address_t addr;
  int rv;
  memcpy (&addr.as_u8, mp->ip_address, 4);
  rv = nat44_user_del (&addr, ntohl (mp->fib_index));
  REPLY_MACRO (VL_API_NAT44_DEL_USER_REPLY);
}

static void *vl_api_nat44_del_user_t_print
  (vl_api_nat44_del_user_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: nat44_del_user ");
  s = format (s, "ip_address %U fib_index %U ",
	      format_ip4_address, mp->ip_address, ntohl (mp->fib_index));
  FINISH;
}

static void
  vl_api_nat44_add_del_address_range_t_handler
  (vl_api_nat44_add_del_address_range_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_address_range_reply_t *rmp;
  ip4_address_t this_addr;
  u8 is_add, twice_nat;
  u32 start_host_order, end_host_order;
  u32 vrf_id;
  int i, count;
  int rv = 0;
  u32 *tmp;

  if (sm->static_mapping_only)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  is_add = mp->is_add;
  twice_nat = mp->flags & NAT_API_IS_TWICE_NAT;

  tmp = (u32 *) mp->first_ip_address;
  start_host_order = clib_host_to_net_u32 (tmp[0]);
  tmp = (u32 *) mp->last_ip_address;
  end_host_order = clib_host_to_net_u32 (tmp[0]);

  count = (end_host_order - start_host_order) + 1;

  vrf_id = clib_host_to_net_u32 (mp->vrf_id);

  if (count > 1024)
    nat_log_info ("%U - %U, %d addresses...",
		  format_ip4_address, mp->first_ip_address,
		  format_ip4_address, mp->last_ip_address, count);

  memcpy (&this_addr.as_u8, mp->first_ip_address, 4);

  for (i = 0; i < count; i++)
    {
      if (is_add)
	rv = snat_add_address (sm, &this_addr, vrf_id, twice_nat);
      else
	rv = snat_del_address (sm, this_addr, 0, twice_nat);

      if (rv)
	goto send_reply;

      if (sm->out2in_dpo)
	nat44_add_del_address_dpo (this_addr, is_add);

      increment_v4_address (&this_addr);
    }

send_reply:
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_REPLY);
}

static void *vl_api_nat44_add_del_address_range_t_print
  (vl_api_nat44_add_del_address_range_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_address_range ");
  s = format (s, "%U ", format_ip4_address, mp->first_ip_address);
  if (memcmp (mp->first_ip_address, mp->last_ip_address, 4))
    {
      s = format (s, " - %U ", format_ip4_address, mp->last_ip_address);
    }
  s = format (s, "twice_nat %d ", mp->flags & NAT_API_IS_TWICE_NAT);
  FINISH;
}

static void
send_nat44_address_details (snat_address_t * a,
			    vl_api_registration_t * reg, u32 context,
			    u8 twice_nat)
{
  vl_api_nat44_address_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_ADDRESS_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->ip_address, &(a->addr), 4);
  if (a->fib_index != ~0)
    {
      fib_table_t *fib = fib_table_get (a->fib_index, FIB_PROTOCOL_IP4);
      rmp->vrf_id = ntohl (fib->ft_table_id);
    }
  else
    rmp->vrf_id = ~0;
  if (twice_nat)
    rmp->flags |= NAT_API_IS_TWICE_NAT;
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_address_dump_t_handler (vl_api_nat44_address_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_address_t *a;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach (a, sm->addresses)
    send_nat44_address_details (a, reg, mp->context, 0);
  vec_foreach (a, sm->twice_nat_addresses)
    send_nat44_address_details (a, reg, mp->context, 1);
  /* *INDENT-ON* */
}

static void *
vl_api_nat44_address_dump_t_print (vl_api_nat44_address_dump_t * mp,
				   void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_address_dump ");

  FINISH;
}

static void
  vl_api_nat44_interface_add_del_feature_t_handler
  (vl_api_nat44_interface_add_del_feature_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_interface_add_del_feature_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u8 is_del;
  int rv = 0;

  is_del = !mp->is_add;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    snat_interface_add_del (sw_if_index, mp->flags & NAT_API_IS_INSIDE,
			    is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_REPLY);
}

static void *vl_api_nat44_interface_add_del_feature_t_print
  (vl_api_nat44_interface_add_del_feature_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_interface_add_del_feature ");
  s = format (s, "sw_if_index %d %s %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->flags & NAT_API_IS_INSIDE ? "in" : "out",
	      mp->is_add ? "" : "del");

  FINISH;
}

static void
send_nat44_interface_details (snat_interface_t * i,
			      vl_api_registration_t * reg, u32 context)
{
  vl_api_nat44_interface_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_INTERFACE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);

  if (nat_interface_is_inside (i))
    rmp->flags |= NAT_API_IS_INSIDE;
  if (nat_interface_is_outside (i))
    rmp->flags |= NAT_API_IS_OUTSIDE;

  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_interface_dump_t_handler (vl_api_nat44_interface_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
  ({
    send_nat44_interface_details(i, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

static void *
vl_api_nat44_interface_dump_t_print (vl_api_nat44_interface_dump_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_interface_dump ");

  FINISH;
}

static void
  vl_api_nat44_interface_add_del_output_feature_t_handler
  (vl_api_nat44_interface_add_del_output_feature_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_interface_add_del_output_feature_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_interface_add_del_output_feature (sw_if_index,
					      mp->flags & NAT_API_IS_INSIDE,
					      !mp->is_add);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_NAT44_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY);
}

static void *vl_api_nat44_interface_add_del_output_feature_t_print
  (vl_api_nat44_interface_add_del_output_feature_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_interface_add_del_output_feature ");
  s = format (s, "sw_if_index %d %s %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->flags & NAT_API_IS_INSIDE ? "in" : "out",
	      mp->is_add ? "" : "del");

  FINISH;
}

static void
send_nat44_interface_output_feature_details (snat_interface_t * i,
					     vl_api_registration_t * reg,
					     u32 context)
{
  vl_api_nat44_interface_output_feature_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_INTERFACE_OUTPUT_FEATURE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->context = context;

  if (nat_interface_is_inside (i))
    rmp->flags |= NAT_API_IS_INSIDE;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_nat44_interface_output_feature_dump_t_handler
  (vl_api_nat44_interface_output_feature_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (i, sm->output_feature_interfaces,
  ({
    send_nat44_interface_output_feature_details(i, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

static void *vl_api_nat44_interface_output_feature_dump_t_print
  (vl_api_nat44_interface_output_feature_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_interface_output_feature_dump ");

  FINISH;
}

static void
  vl_api_nat44_add_del_static_mapping_t_handler
  (vl_api_nat44_add_del_static_mapping_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_static_mapping_reply_t *rmp;
  ip4_address_t local_addr, external_addr, pool_addr = { 0 };
  u16 local_port = 0, external_port = 0;
  u32 vrf_id, external_sw_if_index;
  twice_nat_type_t twice_nat = TWICE_NAT_DISABLED;
  int rv = 0;
  nat_protocol_t proto;
  u8 *tag = 0;

  memcpy (&local_addr.as_u8, mp->local_ip_address, 4);
  memcpy (&external_addr.as_u8, mp->external_ip_address, 4);

  if (!(mp->flags & NAT_API_IS_ADDR_ONLY))
    {
      local_port = mp->local_port;
      external_port = mp->external_port;
    }

  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  external_sw_if_index = clib_net_to_host_u32 (mp->external_sw_if_index);
  proto = ip_proto_to_nat_proto (mp->protocol);

  if (mp->flags & NAT_API_IS_TWICE_NAT)
    twice_nat = TWICE_NAT;
  else if (mp->flags & NAT_API_IS_SELF_TWICE_NAT)
    twice_nat = TWICE_NAT_SELF;
  mp->tag[sizeof (mp->tag) - 1] = 0;
  tag = format (0, "%s", mp->tag);
  vec_terminate_c_string (tag);

  rv = snat_add_static_mapping (local_addr, external_addr, local_port,
				external_port, vrf_id,
				mp->flags & NAT_API_IS_ADDR_ONLY,
				external_sw_if_index, proto,
				mp->is_add, twice_nat,
				mp->flags & NAT_API_IS_OUT2IN_ONLY, tag, 0,
				pool_addr, 0);
  vec_free (tag);

  REPLY_MACRO (VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY);
}

static void
  vl_api_nat44_add_del_static_mapping_v2_t_handler
  (vl_api_nat44_add_del_static_mapping_v2_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_static_mapping_v2_reply_t *rmp;
  ip4_address_t local_addr, external_addr, pool_addr;
  u16 local_port = 0, external_port = 0;
  u32 vrf_id, external_sw_if_index;
  twice_nat_type_t twice_nat = TWICE_NAT_DISABLED;
  int rv = 0;
  nat_protocol_t proto;
  u8 *tag = 0;

  memcpy (&pool_addr.as_u8, mp->pool_ip_address, 4);
  memcpy (&local_addr.as_u8, mp->local_ip_address, 4);
  memcpy (&external_addr.as_u8, mp->external_ip_address, 4);

  if (!(mp->flags & NAT_API_IS_ADDR_ONLY))
    {
      local_port = mp->local_port;
      external_port = mp->external_port;
    }

  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  external_sw_if_index = clib_net_to_host_u32 (mp->external_sw_if_index);
  proto = ip_proto_to_nat_proto (mp->protocol);

  if (mp->flags & NAT_API_IS_TWICE_NAT)
    twice_nat = TWICE_NAT;
  else if (mp->flags & NAT_API_IS_SELF_TWICE_NAT)
    twice_nat = TWICE_NAT_SELF;
  mp->tag[sizeof (mp->tag) - 1] = 0;
  tag = format (0, "%s", mp->tag);
  vec_terminate_c_string (tag);

  rv = snat_add_static_mapping (local_addr, external_addr, local_port,
				external_port, vrf_id,
				mp->flags & NAT_API_IS_ADDR_ONLY,
				external_sw_if_index, proto,
				mp->is_add, twice_nat,
				mp->flags & NAT_API_IS_OUT2IN_ONLY, tag, 0,
				pool_addr, mp->match_pool);
  vec_free (tag);

  REPLY_MACRO (VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_REPLY);
}

static void *vl_api_nat44_add_del_static_mapping_t_print
  (vl_api_nat44_add_del_static_mapping_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_static_mapping ");
  s = format (s, "protocol %d local_addr %U external_addr %U ",
	      mp->protocol,
	      format_ip4_address, mp->local_ip_address,
	      format_ip4_address, mp->external_ip_address);

  if (!(mp->flags & NAT_API_IS_ADDR_ONLY))
    s = format (s, "local_port %d external_port %d ",
		clib_net_to_host_u16 (mp->local_port),
		clib_net_to_host_u16 (mp->external_port));

  s = format (s, "twice_nat %d out2in_only %d ",
	      mp->flags & NAT_API_IS_TWICE_NAT,
	      mp->flags & NAT_API_IS_OUT2IN_ONLY);

  if (mp->vrf_id != ~0)
    s = format (s, "vrf %d", clib_net_to_host_u32 (mp->vrf_id));

  if (mp->external_sw_if_index != ~0)
    s = format (s, "external_sw_if_index %d",
		clib_net_to_host_u32 (mp->external_sw_if_index));
  FINISH;
}

static void *vl_api_nat44_add_del_static_mapping_v2_t_print
  (vl_api_nat44_add_del_static_mapping_v2_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_static_mapping_v2 ");
  s = format (s, "protocol %d local_addr %U external_addr %U ",
	      mp->protocol,
	      format_ip4_address, mp->local_ip_address,
	      format_ip4_address, mp->external_ip_address);

  if (!(mp->flags & NAT_API_IS_ADDR_ONLY))
    s = format (s, "local_port %d external_port %d ",
		clib_net_to_host_u16 (mp->local_port),
		clib_net_to_host_u16 (mp->external_port));

  s = format (s, "twice_nat %d out2in_only %d ",
	      mp->flags & NAT_API_IS_TWICE_NAT,
	      mp->flags & NAT_API_IS_OUT2IN_ONLY);

  if (mp->vrf_id != ~0)
    s = format (s, "vrf %d", clib_net_to_host_u32 (mp->vrf_id));

  if (mp->external_sw_if_index != ~0)
    s = format (s, "external_sw_if_index %d",
		clib_net_to_host_u32 (mp->external_sw_if_index));
  if (mp->match_pool)
    s = format (s, "match pool address %U",
		format_ip4_address, mp->pool_ip_address);

  FINISH;
}

static void
send_nat44_static_mapping_details (snat_static_mapping_t * m,
				   vl_api_registration_t * reg, u32 context)
{
  vl_api_nat44_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;
  u32 len = sizeof (*rmp);

  rmp = vl_msg_api_alloc (len);
  clib_memset (rmp, 0, len);
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_STATIC_MAPPING_DETAILS + sm->msg_id_base);

  clib_memcpy (rmp->local_ip_address, &(m->local_addr), 4);
  clib_memcpy (rmp->external_ip_address, &(m->external_addr), 4);
  rmp->external_sw_if_index = ~0;
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->context = context;

  if (m->twice_nat == TWICE_NAT)
    rmp->flags |= NAT_API_IS_TWICE_NAT;
  else if (m->twice_nat == TWICE_NAT_SELF)
    rmp->flags |= NAT_API_IS_SELF_TWICE_NAT;

  if (is_out2in_only_static_mapping (m))
    rmp->flags |= NAT_API_IS_OUT2IN_ONLY;

  if (is_addr_only_static_mapping (m))
    {
      rmp->flags |= NAT_API_IS_ADDR_ONLY;
    }
  else
    {
      rmp->protocol = nat_proto_to_ip_proto (m->proto);
      rmp->external_port = m->external_port;
      rmp->local_port = m->local_port;
    }

  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_nat44_static_map_resolve_details (snat_static_map_resolve_t * m,
				       vl_api_registration_t * reg,
				       u32 context)
{
  vl_api_nat44_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_STATIC_MAPPING_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->local_ip_address, &(m->l_addr), 4);
  rmp->external_sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->context = context;

  if (m->twice_nat)
    rmp->flags |= NAT_API_IS_TWICE_NAT;

  if (m->addr_only)
    {
      rmp->flags |= NAT_API_IS_ADDR_ONLY;
    }
  else
    {
      rmp->protocol = nat_proto_to_ip_proto (m->proto);
      rmp->external_port = m->e_port;
      rmp->local_port = m->l_port;
    }
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_static_mapping_dump_t_handler (vl_api_nat44_static_mapping_dump_t
					    * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_static_map_resolve_t *rp;
  int j;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (m, sm->static_mappings,
  ({
      if (!is_identity_static_mapping(m) && !is_lb_static_mapping (m))
        send_nat44_static_mapping_details (m, reg, mp->context);
  }));
  /* *INDENT-ON* */

  for (j = 0; j < vec_len (sm->to_resolve); j++)
    {
      rp = sm->to_resolve + j;
      if (!rp->identity_nat)
	send_nat44_static_map_resolve_details (rp, reg, mp->context);
    }
}

static void *
vl_api_nat44_static_mapping_dump_t_print (vl_api_nat44_static_mapping_dump_t *
					  mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_static_mapping_dump ");

  FINISH;
}

static void
  vl_api_nat44_add_del_identity_mapping_t_handler
  (vl_api_nat44_add_del_identity_mapping_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_identity_mapping_reply_t *rmp;
  ip4_address_t addr, pool_addr = { 0 };
  u16 port = 0;
  u32 vrf_id, sw_if_index;
  int rv = 0;
  nat_protocol_t proto = NAT_PROTOCOL_OTHER;
  u8 *tag = 0;

  if (!(mp->flags & NAT_API_IS_ADDR_ONLY))
    {
      port = mp->port;
      proto = ip_proto_to_nat_proto (mp->protocol);
    }
  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  if (sw_if_index != ~0)
    addr.as_u32 = 0;
  else
    memcpy (&addr.as_u8, mp->ip_address, 4);
  mp->tag[sizeof (mp->tag) - 1] = 0;
  tag = format (0, "%s", mp->tag);
  vec_terminate_c_string (tag);

  rv =
    snat_add_static_mapping (addr, addr, port, port, vrf_id,
			     mp->flags & NAT_API_IS_ADDR_ONLY, sw_if_index,
			     proto, mp->is_add, 0, 0, tag, 1, pool_addr, 0);
  vec_free (tag);

  REPLY_MACRO (VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_REPLY);
}

static void *vl_api_nat44_add_del_identity_mapping_t_print
  (vl_api_nat44_add_del_identity_mapping_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_identity_mapping ");
  if (mp->sw_if_index != ~0)
    s = format (s, "sw_if_index %d", clib_net_to_host_u32 (mp->sw_if_index));
  else
    s = format (s, "addr %U", format_ip4_address, mp->ip_address);

  if (!(mp->flags & NAT_API_IS_ADDR_ONLY))
    s =
      format (s, " protocol %d port %d", mp->protocol,
	      clib_net_to_host_u16 (mp->port));

  if (mp->vrf_id != ~0)
    s = format (s, " vrf %d", clib_net_to_host_u32 (mp->vrf_id));

  FINISH;
}

static void
send_nat44_identity_mapping_details (snat_static_mapping_t * m, int index,
				     vl_api_registration_t * reg, u32 context)
{
  vl_api_nat44_identity_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat44_lb_addr_port_t *local = pool_elt_at_index (m->locals, index);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_IDENTITY_MAPPING_DETAILS + sm->msg_id_base);

  if (is_addr_only_static_mapping (m))
    rmp->flags |= NAT_API_IS_ADDR_ONLY;

  clib_memcpy (rmp->ip_address, &(m->local_addr), 4);
  rmp->port = m->local_port;
  rmp->sw_if_index = ~0;
  rmp->vrf_id = htonl (local->vrf_id);
  rmp->protocol = nat_proto_to_ip_proto (m->proto);
  rmp->context = context;
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_nat44_identity_map_resolve_details (snat_static_map_resolve_t * m,
					 vl_api_registration_t * reg,
					 u32 context)
{
  vl_api_nat44_identity_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_IDENTITY_MAPPING_DETAILS + sm->msg_id_base);

  if (m->addr_only)
    rmp->flags = (vl_api_nat_config_flags_t) NAT_API_IS_ADDR_ONLY;

  rmp->port = m->l_port;
  rmp->sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->protocol = nat_proto_to_ip_proto (m->proto);
  rmp->context = context;
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_nat44_identity_mapping_dump_t_handler
  (vl_api_nat44_identity_mapping_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_static_map_resolve_t *rp;
  int j;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (m, sm->static_mappings,
  ({
      if (is_identity_static_mapping(m) && !is_lb_static_mapping (m))
        {
          pool_foreach_index (j, m->locals,
          ({
            send_nat44_identity_mapping_details (m, j, reg, mp->context);
          }));
        }
  }));
  /* *INDENT-ON* */

  for (j = 0; j < vec_len (sm->to_resolve); j++)
    {
      rp = sm->to_resolve + j;
      if (rp->identity_nat)
	send_nat44_identity_map_resolve_details (rp, reg, mp->context);
    }
}

static void *vl_api_nat44_identity_mapping_dump_t_print
  (vl_api_nat44_identity_mapping_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_identity_mapping_dump ");

  FINISH;
}

static void
  vl_api_nat44_add_del_interface_addr_t_handler
  (vl_api_nat44_add_del_interface_addr_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_interface_addr_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;
  u8 is_del;

  is_del = !mp->is_add;

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_add_interface_address (sm, sw_if_index, is_del,
				   mp->flags & NAT_API_IS_TWICE_NAT);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY);
}

static void *vl_api_nat44_add_del_interface_addr_t_print
  (vl_api_nat44_add_del_interface_addr_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_interface_addr ");
  s = format (s, "sw_if_index %d twice_nat %d %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->flags & NAT_API_IS_TWICE_NAT, mp->is_add ? "" : "del");

  FINISH;
}

static void
send_nat44_interface_addr_details (u32 sw_if_index,
				   vl_api_registration_t * reg, u32 context,
				   u8 twice_nat)
{
  vl_api_nat44_interface_addr_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_INTERFACE_ADDR_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (sw_if_index);

  if (twice_nat)
    rmp->flags = (vl_api_nat_config_flags_t) NAT_API_IS_TWICE_NAT;
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_interface_addr_dump_t_handler (vl_api_nat44_interface_addr_dump_t
					    * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  u32 *i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach (i, sm->auto_add_sw_if_indices)
    send_nat44_interface_addr_details(*i, reg, mp->context, 0);
  vec_foreach (i, sm->auto_add_sw_if_indices_twice_nat)
    send_nat44_interface_addr_details(*i, reg, mp->context, 1);
  /* *INDENT-ON* */
}

static void *
vl_api_nat44_interface_addr_dump_t_print (vl_api_nat44_interface_addr_dump_t *
					  mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_interface_addr_dump ");

  FINISH;
}

static void
send_nat44_user_details (snat_user_t * u, vl_api_registration_t * reg,
			 u32 context)
{
  vl_api_nat44_user_details_t *rmp;
  snat_main_t *sm = &snat_main;
  ip4_main_t *im = &ip4_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_USER_DETAILS + sm->msg_id_base);

  if (!pool_is_free_index (im->fibs, u->fib_index))
    {
      fib_table_t *fib = fib_table_get (u->fib_index, FIB_PROTOCOL_IP4);
      rmp->vrf_id = ntohl (fib->ft_table_id);
    }

  clib_memcpy (rmp->ip_address, &(u->addr), 4);
  rmp->nsessions = ntohl (u->nsessions);
  rmp->nstaticsessions = ntohl (u->nstaticsessions);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
nat_ed_user_create_helper (snat_main_per_thread_data_t * tsm,
			   snat_session_t * s)
{
  snat_user_key_t k;
  k.addr = s->in2out.addr;
  k.fib_index = s->in2out.fib_index;
  clib_bihash_kv_8_8_t key, value;
  key.key = k.as_u64;
  snat_user_t *u;
  if (clib_bihash_search_8_8 (&tsm->user_hash, &key, &value))
    {
      pool_get (tsm->users, u);
      u->addr = k.addr;
      u->fib_index = k.fib_index;
      u->nsessions = 0;
      u->nstaticsessions = 0;
      key.value = u - tsm->users;
      clib_bihash_add_del_8_8 (&tsm->user_hash, &key, 1);
    }
  else
    {
      u = pool_elt_at_index (tsm->users, value.value);
    }
  if (snat_is_session_static (s))
    {
      ++u->nstaticsessions;
    }
  else
    {
      ++u->nsessions;
    }
}

static void
nat_ed_users_create (snat_main_per_thread_data_t * tsm)
{
  snat_session_t *s;
  /* *INDENT-OFF* */
  pool_foreach (s, tsm->sessions, { nat_ed_user_create_helper (tsm, s); });
  /* *INDENT-ON* */
}

static void
nat_ed_users_destroy (snat_main_per_thread_data_t * tsm)
{
  snat_user_t *u;
  /* *INDENT-OFF* */
  pool_flush (u, tsm->users, { });
  /* *INDENT-ON* */
  clib_bihash_free_8_8 (&tsm->user_hash);
  clib_bihash_init_8_8 (&tsm->user_hash, "users", snat_main.user_buckets, 0);
  clib_bihash_set_kvp_format_fn_8_8 (&tsm->user_hash, format_user_kvp);
}

static void
vl_api_nat44_user_dump_t_handler (vl_api_nat44_user_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  snat_user_t *u;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach (tsm, sm->per_thread_data)
    {
      if (sm->endpoint_dependent)
	{
	  nat_ed_users_create (tsm);
	}
      pool_foreach (u, tsm->users,
      ({
        send_nat44_user_details (u, reg, mp->context);
      }));
      if (sm->endpoint_dependent)
	{
	  nat_ed_users_destroy (tsm);
	}
    }
  /* *INDENT-ON* */
}

static void *
vl_api_nat44_user_dump_t_print (vl_api_nat44_user_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_user_dump ");

  FINISH;
}

static void
send_nat44_user_session_details (snat_session_t * s,
				 vl_api_registration_t * reg, u32 context)
{
  vl_api_nat44_user_session_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_USER_SESSION_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->outside_ip_address, (&s->out2in.addr), 4);
  clib_memcpy (rmp->inside_ip_address, (&s->in2out.addr), 4);

  if (snat_is_session_static (s))
    rmp->flags |= NAT_API_IS_STATIC;

  if (is_twice_nat_session (s))
    rmp->flags |= NAT_API_IS_TWICE_NAT;

  if (is_ed_session (s) || is_fwd_bypass_session (s))
    rmp->flags |= NAT_API_IS_EXT_HOST_VALID;

  rmp->last_heard = clib_host_to_net_u64 ((u64) s->last_heard);
  rmp->total_bytes = clib_host_to_net_u64 (s->total_bytes);
  rmp->total_pkts = ntohl (s->total_pkts);
  rmp->context = context;
  if (snat_is_unk_proto_session (s))
    {
      rmp->outside_port = 0;
      rmp->inside_port = 0;
      rmp->protocol = ntohs (s->in2out.port);
    }
  else
    {
      rmp->outside_port = s->out2in.port;
      rmp->inside_port = s->in2out.port;
      rmp->protocol = ntohs (nat_proto_to_ip_proto (s->nat_proto));
    }
  if (is_ed_session (s) || is_fwd_bypass_session (s))
    {
      clib_memcpy (rmp->ext_host_address, &s->ext_host_addr, 4);
      rmp->ext_host_port = s->ext_host_port;
      if (is_twice_nat_session (s))
	{
	  clib_memcpy (rmp->ext_host_nat_address, &s->ext_host_nat_addr, 4);
	  rmp->ext_host_nat_port = s->ext_host_nat_port;
	}
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_user_session_dump_t_handler (vl_api_nat44_user_session_dump_t *
					  mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  snat_session_t *s;
  clib_bihash_kv_8_8_t key, value;
  snat_user_key_t ukey;
  snat_user_t *u;
  u32 session_index, head_index, elt_index;
  dlist_elt_t *head, *elt;
  ip4_header_t ip;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  clib_memcpy (&ukey.addr, mp->ip_address, 4);
  ip.src_address.as_u32 = ukey.addr.as_u32;
  ukey.fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->vrf_id));
  key.key = ukey.as_u64;
  if (sm->num_workers > 1)
    tsm =
      vec_elt_at_index (sm->per_thread_data,
			sm->worker_in2out_cb (&ip, ukey.fib_index, 0));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);
  if (!sm->endpoint_dependent)
    {
      if (clib_bihash_search_8_8 (&tsm->user_hash, &key, &value))
	return;
      u = pool_elt_at_index (tsm->users, value.value);
      if (!u->nsessions && !u->nstaticsessions)
	return;

      head_index = u->sessions_per_user_list_head_index;
      head = pool_elt_at_index (tsm->list_pool, head_index);
      elt_index = head->next;
      elt = pool_elt_at_index (tsm->list_pool, elt_index);
      session_index = elt->value;
      while (session_index != ~0)
	{
	  s = pool_elt_at_index (tsm->sessions, session_index);

	  send_nat44_user_session_details (s, reg, mp->context);

	  elt_index = elt->next;
	  elt = pool_elt_at_index (tsm->list_pool, elt_index);
	  session_index = elt->value;
	}
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (s, tsm->sessions, {
        if (s->in2out.addr.as_u32 == ukey.addr.as_u32)
          {
            send_nat44_user_session_details (s, reg, mp->context);
          }
      });
      /* *INDENT-ON* */
    }
}

static void *
vl_api_nat44_user_session_dump_t_print (vl_api_nat44_user_session_dump_t * mp,
					void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_user_session_dump ");
  s = format (s, "ip_address %U vrf_id %d\n",
	      format_ip4_address, mp->ip_address,
	      clib_net_to_host_u32 (mp->vrf_id));

  FINISH;
}

static nat44_lb_addr_port_t *
unformat_nat44_lb_addr_port (vl_api_nat44_lb_addr_port_t * addr_port_pairs,
			     u32 addr_port_pair_num)
{
  u8 i;
  nat44_lb_addr_port_t *lb_addr_port_pairs = 0, lb_addr_port;
  vl_api_nat44_lb_addr_port_t *ap;

  for (i = 0; i < addr_port_pair_num; i++)
    {
      ap = &addr_port_pairs[i];
      clib_memset (&lb_addr_port, 0, sizeof (lb_addr_port));
      clib_memcpy (&lb_addr_port.addr, ap->addr, 4);
      lb_addr_port.port = ap->port;
      lb_addr_port.probability = ap->probability;
      lb_addr_port.vrf_id = clib_net_to_host_u32 (ap->vrf_id);
      vec_add1 (lb_addr_port_pairs, lb_addr_port);
    }

  return lb_addr_port_pairs;
}

static void
  vl_api_nat44_add_del_lb_static_mapping_t_handler
  (vl_api_nat44_add_del_lb_static_mapping_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_lb_static_mapping_reply_t *rmp;
  twice_nat_type_t twice_nat = TWICE_NAT_DISABLED;
  int rv = 0;
  nat44_lb_addr_port_t *locals = 0;
  ip4_address_t e_addr;
  nat_protocol_t proto;
  u8 *tag = 0;

  if (!sm->endpoint_dependent)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  locals =
    unformat_nat44_lb_addr_port (mp->locals,
				 clib_net_to_host_u32 (mp->local_num));
  clib_memcpy (&e_addr, mp->external_addr, 4);
  proto = ip_proto_to_nat_proto (mp->protocol);

  if (mp->flags & NAT_API_IS_TWICE_NAT)
    twice_nat = TWICE_NAT;
  else if (mp->flags & NAT_API_IS_SELF_TWICE_NAT)
    twice_nat = TWICE_NAT_SELF;
  mp->tag[sizeof (mp->tag) - 1] = 0;
  tag = format (0, "%s", mp->tag);
  vec_terminate_c_string (tag);

  rv =
    nat44_add_del_lb_static_mapping (e_addr,
				     mp->external_port,
				     proto, locals, mp->is_add,
				     twice_nat,
				     mp->flags & NAT_API_IS_OUT2IN_ONLY, tag,
				     clib_net_to_host_u32 (mp->affinity));

  vec_free (locals);
  vec_free (tag);

send_reply:
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY);
}

static void *vl_api_nat44_add_del_lb_static_mapping_t_print
  (vl_api_nat44_add_del_lb_static_mapping_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_lb_static_mapping ");
  s = format (s, "is_add %d twice_nat %d out2in_only %d ",
	      mp->is_add,
	      mp->flags & NAT_API_IS_TWICE_NAT,
	      mp->flags & NAT_API_IS_OUT2IN_ONLY);

  FINISH;
}

static void
  vl_api_nat44_lb_static_mapping_add_del_local_t_handler
  (vl_api_nat44_lb_static_mapping_add_del_local_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_lb_static_mapping_add_del_local_reply_t *rmp;
  int rv = 0;
  ip4_address_t e_addr, l_addr;
  nat_protocol_t proto;

  if (!sm->endpoint_dependent)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  clib_memcpy (&e_addr, mp->external_addr, 4);
  clib_memcpy (&l_addr, mp->local.addr, 4);
  proto = ip_proto_to_nat_proto (mp->protocol);

  rv =
    nat44_lb_static_mapping_add_del_local (e_addr,
					   clib_net_to_host_u16
					   (mp->external_port), l_addr,
					   clib_net_to_host_u16 (mp->
								 local.port),
					   proto,
					   clib_net_to_host_u32 (mp->
								 local.vrf_id),
					   mp->local.probability, mp->is_add);

send_reply:
  REPLY_MACRO (VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_REPLY);
}

static void *vl_api_nat44_lb_static_mapping_add_del_local_t_print
  (vl_api_nat44_lb_static_mapping_add_del_local_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_lb_static_mapping_add_del_local ");
  s = format (s, "is_add %d", mp->is_add);

  FINISH;
}

static void
send_nat44_lb_static_mapping_details (snat_static_mapping_t * m,
				      vl_api_registration_t * reg,
				      u32 context)
{
  vl_api_nat44_lb_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat44_lb_addr_port_t *ap;
  vl_api_nat44_lb_addr_port_t *locals;
  u32 local_num = 0;

  rmp =
    vl_msg_api_alloc (sizeof (*rmp) +
		      (pool_elts (m->locals) *
		       sizeof (nat44_lb_addr_port_t)));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_LB_STATIC_MAPPING_DETAILS + sm->msg_id_base);

  clib_memcpy (rmp->external_addr, &(m->external_addr), 4);
  rmp->external_port = m->external_port;
  rmp->protocol = nat_proto_to_ip_proto (m->proto);
  rmp->context = context;

  if (m->twice_nat == TWICE_NAT)
    rmp->flags |= NAT_API_IS_TWICE_NAT;
  else if (m->twice_nat == TWICE_NAT_SELF)
    rmp->flags |= NAT_API_IS_SELF_TWICE_NAT;
  if (is_out2in_only_static_mapping (m))
    rmp->flags |= NAT_API_IS_OUT2IN_ONLY;
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  locals = (vl_api_nat44_lb_addr_port_t *) rmp->locals;
  /* *INDENT-OFF* */
  pool_foreach (ap, m->locals,
  ({
    clib_memcpy (locals->addr, &(ap->addr), 4);
    locals->port = ap->port;
    locals->probability = ap->probability;
    locals->vrf_id = ntohl (ap->vrf_id);
    locals++;
    local_num++;
  }));
  /* *INDENT-ON* */
  rmp->local_num = ntohl (local_num);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_nat44_lb_static_mapping_dump_t_handler
  (vl_api_nat44_lb_static_mapping_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;

  if (!sm->endpoint_dependent)
    return;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (m, sm->static_mappings,
  ({
      if (is_lb_static_mapping(m))
        send_nat44_lb_static_mapping_details (m, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

static void *vl_api_nat44_lb_static_mapping_dump_t_print
  (vl_api_nat44_lb_static_mapping_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_lb_static_mapping_dump ");

  FINISH;
}

static void
vl_api_nat44_del_session_t_handler (vl_api_nat44_del_session_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_del_session_reply_t *rmp;
  ip4_address_t addr, eh_addr;
  u16 port, eh_port;
  u32 vrf_id;
  int rv = 0;
  u8 is_in;
  nat_protocol_t proto;

  memcpy (&addr.as_u8, mp->address, 4);
  port = mp->port;
  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  proto = ip_proto_to_nat_proto (mp->protocol);
  memcpy (&eh_addr.as_u8, mp->ext_host_address, 4);
  eh_port = mp->ext_host_port;

  is_in = mp->flags & NAT_API_IS_INSIDE;

  if (mp->flags & NAT_API_IS_EXT_HOST_VALID)
    rv =
      nat44_del_ed_session (sm, &addr, port, &eh_addr, eh_port, mp->protocol,
			    vrf_id, is_in);
  else
    rv = nat44_del_session (sm, &addr, port, proto, vrf_id, is_in);

  REPLY_MACRO (VL_API_NAT44_DEL_SESSION_REPLY);
}

static void *
vl_api_nat44_del_session_t_print (vl_api_nat44_del_session_t * mp,
				  void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_session ");
  s = format (s, "addr %U port %d protocol %d vrf_id %d is_in %d",
	      format_ip4_address, mp->address,
	      clib_net_to_host_u16 (mp->port),
	      mp->protocol, clib_net_to_host_u32 (mp->vrf_id),
	      mp->flags & NAT_API_IS_INSIDE);
  if (mp->flags & NAT_API_IS_EXT_HOST_VALID)
    s = format (s, "ext_host_address %U ext_host_port %d",
		format_ip4_address, mp->ext_host_address,
		clib_net_to_host_u16 (mp->ext_host_port));

  FINISH;
}

static void
  vl_api_nat44_forwarding_enable_disable_t_handler
  (vl_api_nat44_forwarding_enable_disable_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_forwarding_enable_disable_reply_t *rmp;
  int rv = 0;
  u32 *ses_to_be_removed = 0, *ses_index;
  snat_main_per_thread_data_t *tsm;
  snat_session_t *s;

  sm->forwarding_enabled = mp->enable != 0;

  if (mp->enable == 0)
    {
      /* *INDENT-OFF* */
      vec_foreach (tsm, sm->per_thread_data)
      {
        pool_foreach (s, tsm->sessions,
        ({
          if (is_fwd_bypass_session(s))
            {
              vec_add1 (ses_to_be_removed, s - tsm->sessions);
            }
        }));
	if(sm->endpoint_dependent){
	    vec_foreach (ses_index, ses_to_be_removed)
	      {
		s = pool_elt_at_index(tsm->sessions, ses_index[0]);
		nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
		nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
	      }
	}else{
	    vec_foreach (ses_index, ses_to_be_removed)
	      {
		s = pool_elt_at_index(tsm->sessions, ses_index[0]);
		nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
		nat44_delete_session (sm, s, tsm - sm->per_thread_data);
	      }
	}
        vec_free (ses_to_be_removed);
      }
      /* *INDENT-ON* */
    }

  REPLY_MACRO (VL_API_NAT44_FORWARDING_ENABLE_DISABLE_REPLY);
}

static void *vl_api_nat44_forwarding_enable_disable_t_print
  (vl_api_nat44_forwarding_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_forwarding_enable_disable ");
  s = format (s, "enable %d", mp->enable != 0);

  FINISH;
}

static void
  vl_api_nat44_forwarding_is_enabled_t_handler
  (vl_api_nat44_forwarding_is_enabled_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  vl_api_nat44_forwarding_is_enabled_reply_t *rmp;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_FORWARDING_IS_ENABLED_REPLY + sm->msg_id_base);
  rmp->context = mp->context;

  rmp->enabled = sm->forwarding_enabled;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void *vl_api_nat44_forwarding_is_enabled_t_print
  (vl_api_nat44_forwarding_is_enabled_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_forwarding_is_enabled ");

  FINISH;
}

/* List of message types that this plugin understands */
#define foreach_snat_plugin_api_msg                                     \
_(NAT_CONTROL_PING, nat_control_ping)                                   \
_(NAT_SHOW_CONFIG, nat_show_config)                                     \
_(NAT_SHOW_CONFIG_2, nat_show_config_2)                                 \
_(NAT_SET_WORKERS, nat_set_workers)                                     \
_(NAT_WORKER_DUMP, nat_worker_dump)                                     \
_(NAT44_PLUGIN_ENABLE_DISABLE, nat44_plugin_enable_disable)             \
_(NAT44_DEL_USER, nat44_del_user)                                       \
_(NAT44_SET_SESSION_LIMIT, nat44_set_session_limit)                     \
_(NAT_SET_LOG_LEVEL, nat_set_log_level)                                 \
_(NAT_IPFIX_ENABLE_DISABLE, nat_ipfix_enable_disable)                   \
_(NAT_SET_TIMEOUTS, nat_set_timeouts)                                   \
_(NAT_GET_TIMEOUTS, nat_get_timeouts)                                   \
_(NAT_SET_ADDR_AND_PORT_ALLOC_ALG, nat_set_addr_and_port_alloc_alg)     \
_(NAT_GET_ADDR_AND_PORT_ALLOC_ALG, nat_get_addr_and_port_alloc_alg)     \
_(NAT_SET_MSS_CLAMPING, nat_set_mss_clamping)                           \
_(NAT_GET_MSS_CLAMPING, nat_get_mss_clamping)                           \
_(NAT_HA_SET_LISTENER, nat_ha_set_listener)                             \
_(NAT_HA_SET_FAILOVER, nat_ha_set_failover)                             \
_(NAT_HA_GET_LISTENER, nat_ha_get_listener)                             \
_(NAT_HA_GET_FAILOVER, nat_ha_get_failover)                             \
_(NAT_HA_FLUSH, nat_ha_flush)                                           \
_(NAT_HA_RESYNC, nat_ha_resync)                                         \
_(NAT44_ADD_DEL_ADDRESS_RANGE, nat44_add_del_address_range)             \
_(NAT44_INTERFACE_ADD_DEL_FEATURE, nat44_interface_add_del_feature)     \
_(NAT44_ADD_DEL_STATIC_MAPPING, nat44_add_del_static_mapping)           \
_(NAT44_ADD_DEL_STATIC_MAPPING_V2, nat44_add_del_static_mapping_v2)     \
_(NAT44_ADD_DEL_IDENTITY_MAPPING, nat44_add_del_identity_mapping)       \
_(NAT44_STATIC_MAPPING_DUMP, nat44_static_mapping_dump)                 \
_(NAT44_IDENTITY_MAPPING_DUMP, nat44_identity_mapping_dump)             \
_(NAT44_ADDRESS_DUMP, nat44_address_dump)                               \
_(NAT44_INTERFACE_DUMP, nat44_interface_dump)                           \
_(NAT44_ADD_DEL_INTERFACE_ADDR, nat44_add_del_interface_addr)           \
_(NAT44_INTERFACE_ADDR_DUMP, nat44_interface_addr_dump)                 \
_(NAT44_USER_DUMP, nat44_user_dump)                                     \
_(NAT44_USER_SESSION_DUMP, nat44_user_session_dump)                     \
_(NAT44_INTERFACE_ADD_DEL_OUTPUT_FEATURE,                               \
  nat44_interface_add_del_output_feature)                               \
_(NAT44_INTERFACE_OUTPUT_FEATURE_DUMP,                                  \
  nat44_interface_output_feature_dump)                                  \
_(NAT44_ADD_DEL_LB_STATIC_MAPPING, nat44_add_del_lb_static_mapping)     \
_(NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL,                                \
  nat44_lb_static_mapping_add_del_local)                                \
_(NAT44_LB_STATIC_MAPPING_DUMP, nat44_lb_static_mapping_dump)           \
_(NAT44_DEL_SESSION, nat44_del_session)                                 \
_(NAT44_FORWARDING_ENABLE_DISABLE, nat44_forwarding_enable_disable)     \
_(NAT44_FORWARDING_IS_ENABLED, nat44_forwarding_is_enabled)

/* Set up the API message handling tables */
static clib_error_t *
snat_plugin_api_hookup (vlib_main_t * vm)
{
  snat_main_t *sm __attribute__ ((unused)) = &snat_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_snat_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <nat/nat_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (snat_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_nat;
#undef _
}

static void
plugin_custom_dump_configure (snat_main_t * sm)
{
#define _(n,f) sm->api_main->msg_print_handlers \
  [VL_API_##n + sm->msg_id_base]                \
    = (void *) vl_api_##f##_t_print;
  foreach_snat_plugin_api_msg;
#undef _
}

clib_error_t *
snat_api_init (vlib_main_t * vm, snat_main_t * sm)
{
  u8 *name;
  clib_error_t *error = 0;

  name = format (0, "nat_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base =
    vl_msg_api_get_msg_ids ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = snat_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, sm->api_main);

  plugin_custom_dump_configure (sm);

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
