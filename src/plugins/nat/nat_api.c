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
#include <nat/nat_det.h>
#include <nat/nat64.h>
#include <nat/nat66.h>
#include <nat/dslite.h>
#include <nat/nat_reass.h>
#include <nat/nat_inlines.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <nat/nat_msg_enum.h>
#include <vnet/fib/fib_table.h>

#define vl_api_nat44_lb_addr_port_t_endian vl_noop_handler
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
  dslite_main_t *dm = &dslite_main;
  nat64_main_t *n64m = &nat64_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_SHOW_CONFIG_REPLY,
  ({
    rmp->translation_buckets = htonl (sm->translation_buckets);
    rmp->translation_memory_size = htonl (sm->translation_memory_size);
    rmp->user_buckets = htonl (sm->user_buckets);
    rmp->user_memory_size = htonl (sm->user_memory_size);
    rmp->max_translations_per_user = htonl (sm->max_translations_per_user);
    rmp->outside_vrf_id = htonl (sm->outside_vrf_id);
    rmp->inside_vrf_id = htonl (sm->inside_vrf_id);
    rmp->static_mapping_only = sm->static_mapping_only;
    rmp->static_mapping_connection_tracking =
      sm->static_mapping_connection_tracking;
    rmp->deterministic = sm->deterministic;
    rmp->endpoint_dependent = sm->endpoint_dependent;
    rmp->out2in_dpo = sm->out2in_dpo;
    rmp->dslite_ce = dm->is_ce;
    rmp->nat64_bib_buckets = n64m->bib_buckets;
    rmp->nat64_bib_memory_size = n64m->bib_memory_size;
    rmp->nat64_st_buckets = n64m->st_buckets;
    rmp->nat64_st_memory_size = n64m->st_memory_size;
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
vl_api_nat_set_workers_t_handler (vl_api_nat_set_workers_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_workers_reply_t *rmp;
  int rv = 0;
  uword *bitmap = 0;
  u64 mask;

  if (sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

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

  if (sm->deterministic)
    return;

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
vl_api_nat_ipfix_enable_disable_t_handler (vl_api_nat_ipfix_enable_disable_t *
					   mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ipfix_enable_disable_reply_t *rmp;
  int rv = 0;

  rv = snat_ipfix_logging_enable_disable (mp->enable,
					  clib_host_to_net_u32
					  (mp->domain_id),
					  clib_host_to_net_u16
					  (mp->src_port));

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
vl_api_nat_set_reass_t_handler (vl_api_nat_set_reass_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_reass_reply_t *rmp;
  int rv = 0;

  rv =
    nat_reass_set (ntohl (mp->timeout), ntohs (mp->max_reass), mp->max_frag,
		   mp->drop_frag, mp->is_ip6);

  REPLY_MACRO (VL_API_NAT_SET_REASS_REPLY);
}

static void *
vl_api_nat_set_reass_t_print (vl_api_nat_set_reass_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_set_reass ");
  s = format (s, "timeout %d max_reass %d max_frag %d drop_frag %d is_ip6 %d",
	      clib_host_to_net_u32 (mp->timeout),
	      clib_host_to_net_u16 (mp->max_reass),
	      mp->max_frag, mp->drop_frag, mp->is_ip6);

  FINISH;
}

static void
vl_api_nat_get_reass_t_handler (vl_api_nat_get_reass_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_get_reass_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_GET_REASS_REPLY,
  ({
    rmp->ip4_timeout = htonl (nat_reass_get_timeout(0));
    rmp->ip4_max_reass = htons (nat_reass_get_max_reass(0));
    rmp->ip4_max_frag = nat_reass_get_max_frag(0);
    rmp->ip4_drop_frag = nat_reass_is_drop_frag(0);
    rmp->ip6_timeout = htonl (nat_reass_get_timeout(1));
    rmp->ip6_max_reass = htons (nat_reass_get_max_reass(1));
    rmp->ip6_max_frag = nat_reass_get_max_frag(1);
    rmp->ip6_drop_frag = nat_reass_is_drop_frag(1);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_nat_get_reass_t_print (vl_api_nat_get_reass_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_get_reass");

  FINISH;
}

typedef struct nat_api_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} nat_api_walk_ctx_t;

static int
nat_ip4_reass_walk_api (nat_reass_ip4_t * reass, void *arg)
{
  vl_api_nat_reass_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_REASS_DETAILS + sm->msg_id_base);
  rmp->context = ctx->context;
  clib_memcpy (rmp->src_addr, &(reass->key.src), 4);
  clib_memcpy (rmp->dst_addr, &(reass->key.dst), 4);
  rmp->proto = reass->key.proto;
  rmp->frag_id = ntohl (reass->key.frag_id);
  rmp->frag_n = reass->frag_n;
  rmp->is_ip4 = 1;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static int
nat_ip6_reass_walk_api (nat_reass_ip6_t * reass, void *arg)
{
  vl_api_nat_reass_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_REASS_DETAILS + sm->msg_id_base);
  rmp->context = ctx->context;
  clib_memcpy (rmp->src_addr, &(reass->key.src), 16);
  clib_memcpy (rmp->dst_addr, &(reass->key.dst), 16);
  rmp->proto = reass->key.proto;
  rmp->frag_id = ntohl (reass->key.frag_id);
  rmp->frag_n = reass->frag_n;
  rmp->is_ip4 = 0;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat_reass_dump_t_handler (vl_api_nat_reass_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  nat_ip4_reass_walk (nat_ip4_reass_walk_api, &ctx);
  nat_ip6_reass_walk (nat_ip6_reass_walk_api, &ctx);
}

static void *
vl_api_nat_reass_dump_t_print (vl_api_nat_reass_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_reass_dump");

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

  rv = nat64_set_icmp_timeout (ntohl (mp->icmp));
  if (rv)
    goto send_reply;
  rv = nat64_set_udp_timeout (ntohl (mp->udp));
  if (rv)
    goto send_reply;
  rv =
    nat64_set_tcp_timeouts (ntohl (mp->tcp_transitory),
			    ntohl (mp->tcp_established));

send_reply:
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

  if (sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

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
    {
      sm->mss_clamping = ntohs (mp->mss_value);
      sm->mss_value_net = mp->mss_value;
    }
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

/*************/
/*** NAT44 ***/
/*************/
static void
  vl_api_nat44_add_del_address_range_t_handler
  (vl_api_nat44_add_del_address_range_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_address_range_reply_t *rmp;
  ip4_address_t this_addr;
  u32 start_host_order, end_host_order;
  u32 vrf_id;
  int i, count;
  int rv = 0;
  u32 *tmp;

  if (sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  if (sm->static_mapping_only)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

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
      if (mp->is_add)
	rv = snat_add_address (sm, &this_addr, vrf_id, mp->twice_nat);
      else
	rv = snat_del_address (sm, this_addr, 0, mp->twice_nat);

      if (rv)
	goto send_reply;

      if (sm->out2in_dpo)
	nat44_add_del_address_dpo (this_addr, mp->is_add);

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
  s = format (s, "twice_nat %d ", mp->twice_nat);
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
  rmp->twice_nat = twice_nat;
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_address_dump_t_handler (vl_api_nat44_address_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_address_t *a;

  if (sm->deterministic)
    return;

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
  u8 is_del = mp->is_add == 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_interface_add_del (sw_if_index, mp->is_inside, is_del);

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
	      mp->is_inside ? "in" : "out", mp->is_add ? "" : "del");

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
  rmp->is_inside = (nat_interface_is_inside (i)
		    && nat_interface_is_outside (i)) ? 2 :
    nat_interface_is_inside (i);
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
  u8 is_del = mp->is_add == 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  if (sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_interface_add_del_output_feature (sw_if_index, mp->is_inside,
					      is_del);

  BAD_SW_IF_INDEX_LABEL;
send_reply:
  REPLY_MACRO (VL_API_NAT44_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY);
}

static void *vl_api_nat44_interface_add_del_output_feature_t_print
  (vl_api_nat44_interface_add_del_output_feature_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_interface_add_del_output_feature ");
  s = format (s, "sw_if_index %d %s %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->is_inside ? "in" : "out", mp->is_add ? "" : "del");

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
  rmp->is_inside = nat_interface_is_inside (i);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_nat44_interface_output_feature_dump_t_handler
  (vl_api_nat44_interface_output_feature_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;

  if (sm->deterministic)
    return;

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
  ip4_address_t local_addr, external_addr;
  u16 local_port = 0, external_port = 0;
  u32 vrf_id, external_sw_if_index;
  twice_nat_type_t twice_nat = TWICE_NAT_DISABLED;
  int rv = 0;
  snat_protocol_t proto;
  u8 *tag = 0;

  if (sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  memcpy (&local_addr.as_u8, mp->local_ip_address, 4);
  memcpy (&external_addr.as_u8, mp->external_ip_address, 4);
  if (mp->addr_only == 0)
    {
      local_port = clib_net_to_host_u16 (mp->local_port);
      external_port = clib_net_to_host_u16 (mp->external_port);
    }
  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  external_sw_if_index = clib_net_to_host_u32 (mp->external_sw_if_index);
  proto = ip_proto_to_snat_proto (mp->protocol);
  if (mp->twice_nat)
    twice_nat = TWICE_NAT;
  else if (mp->self_twice_nat)
    twice_nat = TWICE_NAT_SELF;
  mp->tag[sizeof (mp->tag) - 1] = 0;
  tag = format (0, "%s", mp->tag);
  vec_terminate_c_string (tag);

  rv = snat_add_static_mapping (local_addr, external_addr, local_port,
				external_port, vrf_id, mp->addr_only,
				external_sw_if_index, proto, mp->is_add,
				twice_nat, mp->out2in_only, tag, 0);

  vec_free (tag);

send_reply:
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY);
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

  if (mp->addr_only == 0)
    s = format (s, "local_port %d external_port %d ",
		clib_net_to_host_u16 (mp->local_port),
		clib_net_to_host_u16 (mp->external_port));

  s = format (s, "twice_nat %d out2in_only %d ",
	      mp->twice_nat, mp->out2in_only);

  if (mp->vrf_id != ~0)
    s = format (s, "vrf %d", clib_net_to_host_u32 (mp->vrf_id));

  if (mp->external_sw_if_index != ~0)
    s = format (s, "external_sw_if_index %d",
		clib_net_to_host_u32 (mp->external_sw_if_index));
  FINISH;
}

static void
send_nat44_static_mapping_details (snat_static_mapping_t * m,
				   vl_api_registration_t * reg, u32 context)
{
  vl_api_nat44_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_STATIC_MAPPING_DETAILS + sm->msg_id_base);
  rmp->addr_only = is_addr_only_static_mapping (m);
  clib_memcpy (rmp->local_ip_address, &(m->local_addr), 4);
  clib_memcpy (rmp->external_ip_address, &(m->external_addr), 4);
  rmp->external_sw_if_index = ~0;
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->context = context;
  if (m->twice_nat == TWICE_NAT)
    rmp->twice_nat = 1;
  else if (m->twice_nat == TWICE_NAT_SELF)
    rmp->self_twice_nat = 1;
  rmp->out2in_only = is_out2in_only_static_mapping (m);
  if (rmp->addr_only == 0)
    {
      rmp->protocol = snat_proto_to_ip_proto (m->proto);
      rmp->external_port = htons (m->external_port);
      rmp->local_port = htons (m->local_port);
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
  rmp->addr_only = m->addr_only;
  clib_memcpy (rmp->local_ip_address, &(m->l_addr), 4);
  rmp->external_sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->context = context;
  rmp->twice_nat = m->twice_nat;
  if (m->addr_only == 0)
    {
      rmp->protocol = snat_proto_to_ip_proto (m->proto);
      rmp->external_port = htons (m->e_port);
      rmp->local_port = htons (m->l_port);
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

  if (sm->deterministic)
    return;

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
  ip4_address_t addr;
  u16 port = 0;
  u32 vrf_id, sw_if_index;
  int rv = 0;
  snat_protocol_t proto = ~0;
  u8 *tag = 0;

  if (sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  if (mp->addr_only == 0)
    {
      port = clib_net_to_host_u16 (mp->port);
      proto = ip_proto_to_snat_proto (mp->protocol);
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
    snat_add_static_mapping (addr, addr, port, port, vrf_id, mp->addr_only,
			     sw_if_index, proto, mp->is_add, 0, 0, tag, 1);

  vec_free (tag);

send_reply:
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

  if (mp->addr_only == 0)
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

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_IDENTITY_MAPPING_DETAILS + sm->msg_id_base);
  rmp->addr_only = is_addr_only_static_mapping (m);
  clib_memcpy (rmp->ip_address, &(m->local_addr), 4);
  rmp->port = htons (m->local_port);
  rmp->sw_if_index = ~0;
  rmp->vrf_id = htonl (m->locals[index].vrf_id);
  rmp->protocol = snat_proto_to_ip_proto (m->proto);
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
  rmp->addr_only = m->addr_only;
  rmp->port = htons (m->l_port);
  rmp->sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->protocol = snat_proto_to_ip_proto (m->proto);
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

  if (sm->deterministic)
    return;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (m, sm->static_mappings,
  ({
      if (is_identity_static_mapping(m) && !is_lb_static_mapping (m))
        {
          for (j = 0; j < vec_len (m->locals); j++)
            send_nat44_identity_mapping_details (m, j, reg, mp->context);
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
  u8 is_del = mp->is_add == 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  if (sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_add_interface_address (sm, sw_if_index, is_del, mp->twice_nat);

  BAD_SW_IF_INDEX_LABEL;
send_reply:
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY);
}

static void *vl_api_nat44_add_del_interface_addr_t_print
  (vl_api_nat44_add_del_interface_addr_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_interface_addr ");
  s = format (s, "sw_if_index %d twice_nat %d %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->twice_nat, mp->is_add ? "" : "del");

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
  rmp->twice_nat = twice_nat;
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

  if (sm->deterministic)
    return;

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
vl_api_nat44_user_dump_t_handler (vl_api_nat44_user_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  snat_user_t *u;

  if (sm->deterministic)
    return;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach (tsm, sm->per_thread_data)
    {
      pool_foreach (u, tsm->users,
      ({
        send_nat44_user_details (u, reg, mp->context);
      }));
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
  rmp->is_static = snat_is_session_static (s) ? 1 : 0;
  rmp->is_twicenat = is_twice_nat_session (s) ? 1 : 0;
  rmp->ext_host_valid = is_ed_session (s)
    || is_fwd_bypass_session (s) ? 1 : 0;
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
      rmp->protocol = ntohs (snat_proto_to_ip_proto (s->in2out.protocol));
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

  if (sm->deterministic)
    return;

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
			sm->worker_in2out_cb (&ip, ukey.fib_index));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);
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
			     u8 addr_port_pair_num)
{
  u8 i;
  nat44_lb_addr_port_t *lb_addr_port_pairs = 0, lb_addr_port;
  vl_api_nat44_lb_addr_port_t *ap;

  for (i = 0; i < addr_port_pair_num; i++)
    {
      ap = &addr_port_pairs[i];
      clib_memset (&lb_addr_port, 0, sizeof (lb_addr_port));
      clib_memcpy (&lb_addr_port.addr, ap->addr, 4);
      lb_addr_port.port = clib_net_to_host_u16 (ap->port);
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
  snat_protocol_t proto;
  u8 *tag = 0;

  if (!sm->endpoint_dependent)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  locals = unformat_nat44_lb_addr_port (mp->locals, mp->local_num);
  clib_memcpy (&e_addr, mp->external_addr, 4);
  proto = ip_proto_to_snat_proto (mp->protocol);
  if (mp->twice_nat)
    twice_nat = TWICE_NAT;
  else if (mp->self_twice_nat)
    twice_nat = TWICE_NAT_SELF;
  mp->tag[sizeof (mp->tag) - 1] = 0;
  tag = format (0, "%s", mp->tag);
  vec_terminate_c_string (tag);

  rv =
    nat44_add_del_lb_static_mapping (e_addr,
				     clib_net_to_host_u16 (mp->external_port),
				     proto, locals, mp->is_add, twice_nat,
				     mp->out2in_only, tag,
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
	      mp->is_add, mp->twice_nat, mp->out2in_only);

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

  rmp =
    vl_msg_api_alloc (sizeof (*rmp) +
		      (vec_len (m->locals) * sizeof (nat44_lb_addr_port_t)));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_LB_STATIC_MAPPING_DETAILS + sm->msg_id_base);

  clib_memcpy (rmp->external_addr, &(m->external_addr), 4);
  rmp->external_port = ntohs (m->external_port);
  rmp->protocol = snat_proto_to_ip_proto (m->proto);
  rmp->context = context;
  if (m->twice_nat == TWICE_NAT)
    rmp->twice_nat = 1;
  else if (m->twice_nat == TWICE_NAT_SELF)
    rmp->self_twice_nat = 1;
  rmp->out2in_only = is_out2in_only_static_mapping (m);
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  locals = (vl_api_nat44_lb_addr_port_t *) rmp->locals;
  vec_foreach (ap, m->locals)
  {
    clib_memcpy (locals->addr, &(ap->addr), 4);
    locals->port = htons (ap->port);
    locals->probability = ap->probability;
    locals->vrf_id = ntohl (ap->vrf_id);
    locals++;
    rmp->local_num++;
  }

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
  snat_protocol_t proto;

  if (sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  memcpy (&addr.as_u8, mp->address, 4);
  port = clib_net_to_host_u16 (mp->port);
  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  proto = ip_proto_to_snat_proto (mp->protocol);
  memcpy (&eh_addr.as_u8, mp->ext_host_address, 4);
  eh_port = clib_net_to_host_u16 (mp->ext_host_port);

  if (mp->ext_host_valid)
    rv =
      nat44_del_ed_session (sm, &addr, port, &eh_addr, eh_port, mp->protocol,
			    vrf_id, mp->is_in);
  else
    rv = nat44_del_session (sm, &addr, port, proto, vrf_id, mp->is_in);

send_reply:
  REPLY_MACRO (VL_API_NAT44_DEL_SESSION_REPLY);
}

static void *
vl_api_nat44_del_session_t_print (vl_api_nat44_del_session_t * mp,
				  void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_static_mapping ");
  s = format (s, "addr %U port %d protocol %d vrf_id %d is_in %d",
	      format_ip4_address, mp->address,
	      clib_net_to_host_u16 (mp->port),
	      mp->protocol, clib_net_to_host_u32 (mp->vrf_id), mp->is_in);
  if (mp->ext_host_valid)
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
        vec_foreach (ses_index, ses_to_be_removed)
        {
          s = pool_elt_at_index(tsm->sessions, ses_index[0]);
          nat_free_session_data (sm, s, tsm - sm->per_thread_data);
          nat44_delete_session (sm, s, tsm - sm->per_thread_data);
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

/*******************************/
/*** Deterministic NAT (CGN) ***/
/*******************************/

static void
vl_api_nat_det_add_del_map_t_handler (vl_api_nat_det_add_del_map_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_det_add_del_map_reply_t *rmp;
  int rv = 0;
  ip4_address_t in_addr, out_addr;

  if (!sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  if (!mp->is_nat44)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto send_reply;
    }

  clib_memcpy (&in_addr, mp->in_addr, 4);
  clib_memcpy (&out_addr, mp->out_addr, 4);
  rv = snat_det_add_map (sm, &in_addr, mp->in_plen, &out_addr,
			 mp->out_plen, mp->is_add);

send_reply:
  REPLY_MACRO (VL_API_NAT_DET_ADD_DEL_MAP_REPLY);
}

static void *
vl_api_nat_det_add_del_map_t_print (vl_api_nat_det_add_del_map_t * mp,
				    void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_det_add_del_map ");
  s = format (s, "inside address %U/%d outside address %U/%d\n",
	      format_ip4_address, mp->in_addr, mp->in_plen,
	      format_ip4_address, mp->out_addr, mp->out_plen);

  FINISH;
}

static void
vl_api_nat_det_forward_t_handler (vl_api_nat_det_forward_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_det_forward_reply_t *rmp;
  int rv = 0;
  u16 lo_port = 0, hi_port = 0;
  snat_det_map_t *dm;
  ip4_address_t in_addr, out_addr;

  if (!sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      REPLY_MACRO (VL_API_NAT_DET_FORWARD_REPLY);
      return;
    }

  if (!mp->is_nat44)
    {
      out_addr.as_u32 = 0;
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto send_reply;
    }

  out_addr.as_u32 = 0;
  clib_memcpy (&in_addr, mp->in_addr, 4);
  dm = snat_det_map_by_user (sm, &in_addr);
  if (!dm)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

  snat_det_forward (dm, &in_addr, &out_addr, &lo_port);
  hi_port = lo_port + dm->ports_per_host - 1;

send_reply:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_DET_FORWARD_REPLY,
  ({
    rmp->out_port_lo = ntohs (lo_port);
    rmp->out_port_hi = ntohs (hi_port);
    clib_memcpy (rmp->out_addr, &out_addr, 4);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_nat_det_forward_t_print (vl_api_nat_det_forward_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_det_forward");
  s = format (s, "inside ip address %U\n", format_ip4_address, mp->in_addr);

  FINISH;
}

static void
vl_api_nat_det_reverse_t_handler (vl_api_nat_det_reverse_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_det_reverse_reply_t *rmp;
  int rv = 0;
  ip4_address_t out_addr, in_addr;
  snat_det_map_t *dm;

  if (!sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      REPLY_MACRO (VL_API_NAT_DET_REVERSE_REPLY);
      return;
    }

  in_addr.as_u32 = 0;
  clib_memcpy (&out_addr, mp->out_addr, 4);
  dm = snat_det_map_by_out (sm, &out_addr);
  if (!dm)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

  snat_det_reverse (dm, &out_addr, htons (mp->out_port), &in_addr);

send_reply:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_DET_REVERSE_REPLY,
  ({
    rmp->is_nat44 = 1;
    clib_memset (rmp->in_addr, 0, 16);
    clib_memcpy (rmp->in_addr, &in_addr, 4);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_nat_det_reverse_t_print (vl_api_nat_det_reverse_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_det_reverse");
  s = format (s, "outside ip address %U outside port %d",
	      format_ip4_address, mp->out_addr, ntohs (mp->out_port));

  FINISH;
}

static void
sent_nat_det_map_details (snat_det_map_t * m, vl_api_registration_t * reg,
			  u32 context)
{
  vl_api_nat_det_map_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_DET_MAP_DETAILS + sm->msg_id_base);
  rmp->is_nat44 = 1;
  clib_memcpy (rmp->in_addr, &m->in_addr, 4);
  rmp->in_plen = m->in_plen;
  clib_memcpy (rmp->out_addr, &m->out_addr, 4);
  rmp->out_plen = m->out_plen;
  rmp->sharing_ratio = htonl (m->sharing_ratio);
  rmp->ports_per_host = htons (m->ports_per_host);
  rmp->ses_num = htonl (m->ses_num);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat_det_map_dump_t_handler (vl_api_nat_det_map_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_det_map_t *m;

  if (!sm->deterministic)
    return;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach(m, sm->det_maps)
    sent_nat_det_map_details(m, reg, mp->context);
  /* *INDENT-ON* */
}

static void *
vl_api_nat_det_map_dump_t_print (vl_api_nat_det_map_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_det_map_dump ");

  FINISH;
}

static void
vl_api_nat_det_close_session_out_t_handler (vl_api_nat_det_close_session_out_t
					    * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_det_close_session_out_reply_t *rmp;
  ip4_address_t out_addr, ext_addr, in_addr;
  snat_det_out_key_t key;
  snat_det_map_t *dm;
  snat_det_session_t *ses;
  int rv = 0;

  if (!sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  clib_memcpy (&out_addr, mp->out_addr, 4);
  clib_memcpy (&ext_addr, mp->ext_addr, 4);

  dm = snat_det_map_by_out (sm, &out_addr);
  if (!dm)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }
  snat_det_reverse (dm, &ext_addr, ntohs (mp->out_port), &in_addr);
  key.ext_host_addr = ext_addr;
  key.ext_host_port = mp->ext_port;
  key.out_port = mp->out_port;
  ses = snat_det_get_ses_by_out (dm, &in_addr, key.as_u64);
  if (!ses)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }
  snat_det_ses_close (dm, ses);

send_reply:
  REPLY_MACRO (VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY);
}

static void *
vl_api_nat_det_close_session_out_t_print (vl_api_nat_det_close_session_out_t *
					  mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_det_close_session_out ");
  s = format (s, "out_addr %U out_port %d "
	      "ext_addr %U ext_port %d\n",
	      format_ip4_address, mp->out_addr, ntohs (mp->out_port),
	      format_ip4_address, mp->ext_addr, ntohs (mp->ext_port));

  FINISH;
}

static void
vl_api_nat_det_close_session_in_t_handler (vl_api_nat_det_close_session_in_t *
					   mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_det_close_session_in_reply_t *rmp;
  ip4_address_t in_addr, ext_addr;
  snat_det_out_key_t key;
  snat_det_map_t *dm;
  snat_det_session_t *ses;
  int rv = 0;

  if (!sm->deterministic)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto send_reply;
    }

  if (!mp->is_nat44)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto send_reply;
    }

  clib_memcpy (&in_addr, mp->in_addr, 4);
  clib_memcpy (&ext_addr, mp->ext_addr, 4);

  dm = snat_det_map_by_user (sm, &in_addr);
  if (!dm)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }
  key.ext_host_addr = ext_addr;
  key.ext_host_port = mp->ext_port;
  ses = snat_det_find_ses_by_in (dm, &in_addr, mp->in_port, key);
  if (!ses)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }
  snat_det_ses_close (dm, ses);

send_reply:
  REPLY_MACRO (VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY);
}

static void *
vl_api_nat_det_close_session_in_t_print (vl_api_nat_det_close_session_in_t *
					 mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: nat_det_close_session_in ");
  s = format (s, "in_addr %U in_port %d ext_addr %U ext_port %d\n",
	      format_ip4_address, mp->in_addr, ntohs (mp->in_port),
	      format_ip4_address, mp->ext_addr, ntohs (mp->ext_port));

  FINISH;
}

static void
send_nat_det_session_details (snat_det_session_t * s,
			      vl_api_registration_t * reg, u32 context)
{
  vl_api_nat_det_session_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_DET_SESSION_DETAILS + sm->msg_id_base);
  rmp->in_port = s->in_port;
  clib_memcpy (rmp->ext_addr, &s->out.ext_host_addr, 4);
  rmp->ext_port = s->out.ext_host_port;
  rmp->out_port = s->out.out_port;
  rmp->state = s->state;
  rmp->expire = ntohl (s->expire);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat_det_session_dump_t_handler (vl_api_nat_det_session_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  ip4_address_t user_addr;
  snat_det_map_t *dm;
  snat_det_session_t *s, empty_ses;
  u16 i;

  if (!sm->deterministic)
    return;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  if (!mp->is_nat44)
    return;

  clib_memset (&empty_ses, 0, sizeof (empty_ses));
  clib_memcpy (&user_addr, mp->user_addr, 4);
  dm = snat_det_map_by_user (sm, &user_addr);
  if (!dm)
    return;

  s = dm->sessions + snat_det_user_ses_offset (&user_addr, dm->in_plen);
  for (i = 0; i < SNAT_DET_SES_PER_USER; i++)
    {
      if (s->out.as_u64)
	send_nat_det_session_details (s, reg, mp->context);
      s++;
    }
}

static void *
vl_api_nat_det_session_dump_t_print (vl_api_nat_det_session_dump_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_det_session_dump ");
  s = format (s, "user_addr %U\n", format_ip4_address, mp->user_addr);

  FINISH;
}

/*************/
/*** NAT64 ***/
/*************/

static void
  vl_api_nat64_add_del_pool_addr_range_t_handler
  (vl_api_nat64_add_del_pool_addr_range_t * mp)
{
  vl_api_nat64_add_del_pool_addr_range_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  int rv = 0;
  ip4_address_t this_addr;
  u32 start_host_order, end_host_order;
  u32 vrf_id;
  int i, count;
  u32 *tmp;

  tmp = (u32 *) mp->start_addr;
  start_host_order = clib_host_to_net_u32 (tmp[0]);
  tmp = (u32 *) mp->end_addr;
  end_host_order = clib_host_to_net_u32 (tmp[0]);

  count = (end_host_order - start_host_order) + 1;

  vrf_id = clib_host_to_net_u32 (mp->vrf_id);

  memcpy (&this_addr.as_u8, mp->start_addr, 4);

  for (i = 0; i < count; i++)
    {
      if ((rv = nat64_add_del_pool_addr (&this_addr, vrf_id, mp->is_add)))
	goto send_reply;

      increment_v4_address (&this_addr);
    }

send_reply:
  REPLY_MACRO (VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY);
}

static void *vl_api_nat64_add_del_pool_addr_range_t_print
  (vl_api_nat64_add_del_pool_addr_range_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat64_add_del_pool_addr_range ");
  s = format (s, "%U - %U vrf_id %u %s\n",
	      format_ip4_address, mp->start_addr,
	      format_ip4_address, mp->end_addr,
	      ntohl (mp->vrf_id), mp->is_add ? "" : "del");

  FINISH;
}

typedef struct nat64_api_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
  nat64_db_t *db;
} nat64_api_walk_ctx_t;

static int
nat64_api_pool_walk (snat_address_t * a, void *arg)
{
  vl_api_nat64_pool_addr_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat64_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_POOL_ADDR_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->address, &(a->addr), 4);
  if (a->fib_index != ~0)
    {
      fib_table_t *fib = fib_table_get (a->fib_index, FIB_PROTOCOL_IP6);
      if (!fib)
	return -1;
      rmp->vrf_id = ntohl (fib->ft_table_id);
    }
  else
    rmp->vrf_id = ~0;
  rmp->context = ctx->context;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_pool_addr_dump_t_handler (vl_api_nat64_pool_addr_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  nat64_pool_addr_walk (nat64_api_pool_walk, &ctx);
}

static void *
vl_api_nat64_pool_addr_dump_t_print (vl_api_nat64_pool_addr_dump_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat64_pool_addr_dump\n");

  FINISH;
}

static void
vl_api_nat64_add_del_interface_t_handler (vl_api_nat64_add_del_interface_t *
					  mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat64_add_del_interface_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    nat64_add_del_interface (ntohl (mp->sw_if_index), mp->is_inside,
			     mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT64_ADD_DEL_INTERFACE_REPLY);
}

static void *
vl_api_nat64_add_del_interface_t_print (vl_api_nat64_add_del_interface_t * mp,
					void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat64_add_del_interface ");
  s = format (s, "sw_if_index %d %s %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->is_inside ? "in" : "out", mp->is_add ? "" : "del");

  FINISH;
}

static int
nat64_api_interface_walk (snat_interface_t * i, void *arg)
{
  vl_api_nat64_interface_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat64_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_INTERFACE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->is_inside = (nat_interface_is_inside (i)
		    && nat_interface_is_outside (i)) ? 2 :
    nat_interface_is_inside (i);
  rmp->context = ctx->context;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_interface_dump_t_handler (vl_api_nat64_interface_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  nat64_interfaces_walk (nat64_api_interface_walk, &ctx);
}

static void *
vl_api_nat64_interface_dump_t_print (vl_api_nat64_interface_dump_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_interface_dump ");

  FINISH;
}

static void
  vl_api_nat64_add_del_static_bib_t_handler
  (vl_api_nat64_add_del_static_bib_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat64_add_del_static_bib_reply_t *rmp;
  ip6_address_t in_addr;
  ip4_address_t out_addr;
  int rv = 0;

  memcpy (&in_addr.as_u8, mp->i_addr, 16);
  memcpy (&out_addr.as_u8, mp->o_addr, 4);

  rv =
    nat64_add_del_static_bib_entry (&in_addr, &out_addr,
				    clib_net_to_host_u16 (mp->i_port),
				    clib_net_to_host_u16 (mp->o_port),
				    mp->proto,
				    clib_net_to_host_u32 (mp->vrf_id),
				    mp->is_add);

  REPLY_MACRO (VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY);
}

static void *vl_api_nat64_add_del_static_bib_t_print
  (vl_api_nat64_add_del_static_bib_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat64_add_del_static_bib ");
  s = format (s, "protocol %d i_addr %U o_addr %U ",
	      mp->proto,
	      format_ip6_address, mp->i_addr, format_ip4_address, mp->o_addr);

  if (mp->vrf_id != ~0)
    s = format (s, "vrf %d", clib_net_to_host_u32 (mp->vrf_id));

  FINISH;
}

static int
nat64_api_bib_walk (nat64_db_bib_entry_t * bibe, void *arg)
{
  vl_api_nat64_bib_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat64_api_walk_ctx_t *ctx = arg;
  fib_table_t *fib;

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_BIB_DETAILS + sm->msg_id_base);
  rmp->context = ctx->context;
  clib_memcpy (rmp->i_addr, &(bibe->in_addr), 16);
  clib_memcpy (rmp->o_addr, &(bibe->out_addr), 4);
  rmp->i_port = bibe->in_port;
  rmp->o_port = bibe->out_port;
  rmp->vrf_id = ntohl (fib->ft_table_id);
  rmp->proto = bibe->proto;
  rmp->is_static = bibe->is_static;
  rmp->ses_num = ntohl (bibe->ses_num);

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_bib_dump_t_handler (vl_api_nat64_bib_dump_t * mp)
{
  vl_api_registration_t *reg;
  nat64_main_t *nm = &nat64_main;
  nat64_db_t *db;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  /* *INDENT-OFF* */
  vec_foreach (db, nm->db)
    nat64_db_bib_walk (db, mp->proto, nat64_api_bib_walk, &ctx);
  /* *INDENT-ON* */
}

static void *
vl_api_nat64_bib_dump_t_print (vl_api_nat64_bib_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_bib_dump protocol %d", mp->proto);

  FINISH;
}

static int
nat64_api_st_walk (nat64_db_st_entry_t * ste, void *arg)
{
  vl_api_nat64_st_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat64_api_walk_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  fib_table_t *fib;

  bibe = nat64_db_bib_entry_by_index (ctx->db, ste->proto, ste->bibe_index);
  if (!bibe)
    return -1;

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_ST_DETAILS + sm->msg_id_base);
  rmp->context = ctx->context;
  clib_memcpy (rmp->il_addr, &(bibe->in_addr), 16);
  clib_memcpy (rmp->ol_addr, &(bibe->out_addr), 4);
  rmp->il_port = bibe->in_port;
  rmp->ol_port = bibe->out_port;
  clib_memcpy (rmp->ir_addr, &(ste->in_r_addr), 16);
  clib_memcpy (rmp->or_addr, &(ste->out_r_addr), 4);
  rmp->il_port = ste->r_port;
  rmp->vrf_id = ntohl (fib->ft_table_id);
  rmp->proto = ste->proto;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_st_dump_t_handler (vl_api_nat64_st_dump_t * mp)
{
  vl_api_registration_t *reg;
  nat64_main_t *nm = &nat64_main;
  nat64_db_t *db;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  /* *INDENT-OFF* */
  vec_foreach (db, nm->db)
    {
      ctx.db = db;
      nat64_db_st_walk (db, mp->proto, nat64_api_st_walk, &ctx);
    }
  /* *INDENT-ON* */
}

static void *
vl_api_nat64_st_dump_t_print (vl_api_nat64_st_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_st_dump protocol %d", mp->proto);

  FINISH;
}

static void
vl_api_nat64_add_del_prefix_t_handler (vl_api_nat64_add_del_prefix_t * mp)
{
  vl_api_nat64_add_del_prefix_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  ip6_address_t prefix;
  int rv = 0;

  memcpy (&prefix.as_u8, mp->prefix, 16);

  rv =
    nat64_add_del_prefix (&prefix, mp->prefix_len,
			  clib_net_to_host_u32 (mp->vrf_id), mp->is_add);
  REPLY_MACRO (VL_API_NAT64_ADD_DEL_PREFIX_REPLY);
}

static void *
vl_api_nat64_add_del_prefix_t_print (vl_api_nat64_add_del_prefix_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat64_add_del_prefix %U/%u vrf_id %u %s\n",
	      format_ip6_address, mp->prefix, mp->prefix_len,
	      ntohl (mp->vrf_id), mp->is_add ? "" : "del");

  FINISH;
}

static int
nat64_api_prefix_walk (nat64_prefix_t * p, void *arg)
{
  vl_api_nat64_prefix_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat64_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_PREFIX_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->prefix, &(p->prefix), 16);
  rmp->prefix_len = p->plen;
  rmp->vrf_id = ntohl (p->vrf_id);
  rmp->context = ctx->context;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_prefix_dump_t_handler (vl_api_nat64_prefix_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  nat64_prefix_walk (nat64_api_prefix_walk, &ctx);
}

static void *
vl_api_nat64_prefix_dump_t_print (vl_api_nat64_prefix_dump_t * mp,
				  void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat64_prefix_dump\n");

  FINISH;
}

static void
  vl_api_nat64_add_del_interface_addr_t_handler
  (vl_api_nat64_add_del_interface_addr_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat64_add_del_interface_addr_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = nat64_add_interface_address (sw_if_index, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY);
}

static void *vl_api_nat64_add_del_interface_addr_t_print
  (vl_api_nat64_add_del_interface_addr_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat64_add_del_interface_addr ");
  s = format (s, "sw_if_index %d %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->is_add ? "" : "del");

  FINISH;
}

/***************/
/*** DS-Lite ***/
/***************/

static void
vl_api_dslite_set_aftr_addr_t_handler (vl_api_dslite_set_aftr_addr_t * mp)
{
  vl_api_dslite_set_aftr_addr_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;
  ip6_address_t ip6_addr;
  ip4_address_t ip4_addr;

  memcpy (&ip6_addr.as_u8, mp->ip6_addr, 16);
  memcpy (&ip4_addr.as_u8, mp->ip4_addr, 4);

  rv = dslite_set_aftr_ip6_addr (dm, &ip6_addr);
  if (rv == 0)
    rv = dslite_set_aftr_ip4_addr (dm, &ip4_addr);

  REPLY_MACRO (VL_API_DSLITE_SET_AFTR_ADDR_REPLY);
}

static void *
vl_api_dslite_set_aftr_addr_t_print (vl_api_dslite_set_aftr_addr_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: dslite_set_aftr_addr ");
  s = format (s, "ip6_addr %U ip4_addr %U\n",
	      format_ip6_address, mp->ip6_addr,
	      format_ip4_address, mp->ip4_addr);

  FINISH;
}

static void
vl_api_dslite_get_aftr_addr_t_handler (vl_api_dslite_get_aftr_addr_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_dslite_get_aftr_addr_reply_t *rmp;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_DSLITE_GET_AFTR_ADDR_REPLY,
  ({
    memcpy (rmp->ip4_addr, &dm->aftr_ip4_addr.as_u8, 4);
    memcpy (rmp->ip6_addr, &dm->aftr_ip6_addr.as_u8, 16);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_dslite_get_aftr_addr_t_print (vl_api_dslite_get_aftr_addr_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: dslite_get_aftr_addr");

  FINISH;
}

static void
vl_api_dslite_set_b4_addr_t_handler (vl_api_dslite_set_b4_addr_t * mp)
{
  vl_api_dslite_set_b4_addr_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;
  ip6_address_t ip6_addr;
  ip4_address_t ip4_addr;

  memcpy (&ip6_addr.as_u8, mp->ip6_addr, 16);
  memcpy (&ip4_addr.as_u8, mp->ip4_addr, 4);

  rv = dslite_set_b4_ip6_addr (dm, &ip6_addr);
  if (rv == 0)
    rv = dslite_set_b4_ip4_addr (dm, &ip4_addr);

  REPLY_MACRO (VL_API_DSLITE_SET_B4_ADDR_REPLY);
}

static void *
vl_api_dslite_set_b4_addr_t_print (vl_api_dslite_set_b4_addr_t * mp,
				   void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: dslite_set_b4_addr ");
  s = format (s, "ip6_addr %U ip4_addr %U\n",
	      format_ip6_address, mp->ip6_addr,
	      format_ip6_address, mp->ip4_addr);

  FINISH;
}

static void
vl_api_dslite_get_b4_addr_t_handler (vl_api_dslite_get_b4_addr_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_dslite_get_b4_addr_reply_t *rmp;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_DSLITE_GET_AFTR_ADDR_REPLY,
  ({
    memcpy (rmp->ip4_addr, &dm->b4_ip4_addr.as_u8, 4);
    memcpy (rmp->ip6_addr, &dm->b4_ip6_addr.as_u8, 16);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_dslite_get_b4_addr_t_print (vl_api_dslite_get_b4_addr_t * mp,
				   void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: dslite_get_b4_addr");

  FINISH;
}

static void
  vl_api_dslite_add_del_pool_addr_range_t_handler
  (vl_api_dslite_add_del_pool_addr_range_t * mp)
{
  vl_api_dslite_add_del_pool_addr_range_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;
  ip4_address_t this_addr;
  u32 start_host_order, end_host_order;
  int i, count;
  u32 *tmp;

  tmp = (u32 *) mp->start_addr;
  start_host_order = clib_host_to_net_u32 (tmp[0]);
  tmp = (u32 *) mp->end_addr;
  end_host_order = clib_host_to_net_u32 (tmp[0]);

  count = (end_host_order - start_host_order) + 1;
  memcpy (&this_addr.as_u8, mp->start_addr, 4);

  for (i = 0; i < count; i++)
    {
      if ((rv = dslite_add_del_pool_addr (dm, &this_addr, mp->is_add)))
	goto send_reply;

      increment_v4_address (&this_addr);
    }

send_reply:
  REPLY_MACRO (VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE_REPLY);
}

static void
send_dslite_address_details (snat_address_t * ap,
			     vl_api_registration_t * reg, u32 context)
{
  vl_api_dslite_address_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));

  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs (VL_API_DSLITE_ADDRESS_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->ip_address, &(ap->addr), 4);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_dslite_address_dump_t_handler (vl_api_dslite_address_dump_t * mp)
{
  vl_api_registration_t *reg;
  dslite_main_t *dm = &dslite_main;
  snat_address_t *ap;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach (ap, dm->addr_pool)
    {
      send_dslite_address_details (ap, reg, mp->context);
    }
  /* *INDENT-ON* */
}

static void *
vl_api_dslite_address_dump_t_print (vl_api_dslite_address_dump_t * mp,
				    void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: dslite_address_dump ");

  FINISH;
}

static void *vl_api_dslite_add_del_pool_addr_range_t_print
  (vl_api_dslite_add_del_pool_addr_range_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: dslite_add_del_pool_addr_range ");
  s = format (s, "%U - %U\n",
	      format_ip4_address, mp->start_addr,
	      format_ip4_address, mp->end_addr);

  FINISH;
}


/*************/
/*** NAT66 ***/
/*************/

static void
vl_api_nat66_add_del_interface_t_handler (vl_api_nat66_add_del_interface_t *
					  mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat66_add_del_interface_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    nat66_interface_add_del (ntohl (mp->sw_if_index), mp->is_inside,
			     mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT66_ADD_DEL_INTERFACE_REPLY);
}

static void *
vl_api_nat66_add_del_interface_t_print (vl_api_nat66_add_del_interface_t * mp,
					void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat66_add_del_interface ");
  s = format (s, "sw_if_index %d %s %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->is_inside ? "in" : "out", mp->is_add ? "" : "del");

  FINISH;
}

static void
  vl_api_nat66_add_del_static_mapping_t_handler
  (vl_api_nat66_add_del_static_mapping_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat66_add_del_static_mapping_reply_t *rmp;
  ip6_address_t l_addr, e_addr;
  int rv = 0;

  memcpy (&l_addr.as_u8, mp->local_ip_address, 16);
  memcpy (&e_addr.as_u8, mp->external_ip_address, 16);

  rv =
    nat66_static_mapping_add_del (&l_addr, &e_addr,
				  clib_net_to_host_u32 (mp->vrf_id),
				  mp->is_add);

  REPLY_MACRO (VL_API_NAT66_ADD_DEL_STATIC_MAPPING_REPLY);
}

static void *vl_api_nat66_add_del_static_mapping_t_print
  (vl_api_nat66_add_del_static_mapping_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat66_add_del_static_mapping ");
  s = format (s, "local_ip_address %U external_ip_address %U vrf_id %d %s",
	      format_ip6_address, mp->local_ip_address,
	      format_ip6_address, mp->external_ip_address,
	      clib_net_to_host_u32 (mp->vrf_id), mp->is_add ? "" : "del");

  FINISH;
}

typedef struct nat66_api_walk_ctx_t_
{
  svm_queue_t *q;
  u32 context;
} nat66_api_walk_ctx_t;

static int
nat66_api_interface_walk (snat_interface_t * i, void *arg)
{
  vl_api_nat66_interface_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat66_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT66_INTERFACE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->is_inside = nat_interface_is_inside (i);
  rmp->context = ctx->context;

  vl_msg_api_send_shmem (ctx->q, (u8 *) & rmp);

  return 0;
}

static void
vl_api_nat66_interface_dump_t_handler (vl_api_nat66_interface_dump_t * mp)
{
  svm_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  nat66_api_walk_ctx_t ctx = {
    .q = q,
    .context = mp->context,
  };

  nat66_interfaces_walk (nat66_api_interface_walk, &ctx);
}

static void *
vl_api_nat66_interface_dump_t_print (vl_api_nat66_interface_dump_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat66_interface_dump ");

  FINISH;
}

static int
nat66_api_static_mapping_walk (nat66_static_mapping_t * m, void *arg)
{
  vl_api_nat66_static_mapping_details_t *rmp;
  nat66_main_t *nm = &nat66_main;
  snat_main_t *sm = &snat_main;
  nat66_api_walk_ctx_t *ctx = arg;
  fib_table_t *fib;
  vlib_counter_t vc;

  fib = fib_table_get (m->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  vlib_get_combined_counter (&nm->session_counters, m - nm->sm, &vc);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT66_STATIC_MAPPING_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->local_ip_address, &m->l_addr, 16);
  clib_memcpy (rmp->external_ip_address, &m->e_addr, 16);
  rmp->vrf_id = ntohl (fib->ft_table_id);
  rmp->total_bytes = clib_host_to_net_u64 (vc.bytes);
  rmp->total_pkts = clib_host_to_net_u64 (vc.packets);
  rmp->context = ctx->context;

  vl_msg_api_send_shmem (ctx->q, (u8 *) & rmp);

  return 0;
}

static void
vl_api_nat66_static_mapping_dump_t_handler (vl_api_nat66_static_mapping_dump_t
					    * mp)
{
  svm_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  nat66_api_walk_ctx_t ctx = {
    .q = q,
    .context = mp->context,
  };

  nat66_static_mappings_walk (nat66_api_static_mapping_walk, &ctx);
}

static void *
vl_api_nat66_static_mapping_dump_t_print (vl_api_nat66_static_mapping_dump_t *
					  mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat66_static_mapping_dump ");

  FINISH;
}


/* List of message types that this plugin understands */
#define foreach_snat_plugin_api_msg                                     \
_(NAT_CONTROL_PING, nat_control_ping)                                   \
_(NAT_SHOW_CONFIG, nat_show_config)                                     \
_(NAT_SET_WORKERS, nat_set_workers)                                     \
_(NAT_WORKER_DUMP, nat_worker_dump)                                     \
_(NAT_IPFIX_ENABLE_DISABLE, nat_ipfix_enable_disable)                   \
_(NAT_SET_REASS, nat_set_reass)                                         \
_(NAT_GET_REASS, nat_get_reass)                                         \
_(NAT_REASS_DUMP, nat_reass_dump)                                       \
_(NAT_SET_TIMEOUTS, nat_set_timeouts)                                   \
_(NAT_GET_TIMEOUTS, nat_get_timeouts)                                   \
_(NAT_SET_ADDR_AND_PORT_ALLOC_ALG, nat_set_addr_and_port_alloc_alg)     \
_(NAT_GET_ADDR_AND_PORT_ALLOC_ALG, nat_get_addr_and_port_alloc_alg)     \
_(NAT_SET_MSS_CLAMPING, nat_set_mss_clamping)                           \
_(NAT_GET_MSS_CLAMPING, nat_get_mss_clamping)                           \
_(NAT44_ADD_DEL_ADDRESS_RANGE, nat44_add_del_address_range)             \
_(NAT44_INTERFACE_ADD_DEL_FEATURE, nat44_interface_add_del_feature)     \
_(NAT44_ADD_DEL_STATIC_MAPPING, nat44_add_del_static_mapping)           \
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
_(NAT44_LB_STATIC_MAPPING_DUMP, nat44_lb_static_mapping_dump)           \
_(NAT44_DEL_SESSION, nat44_del_session)                                 \
_(NAT44_FORWARDING_ENABLE_DISABLE, nat44_forwarding_enable_disable)     \
_(NAT44_FORWARDING_IS_ENABLED, nat44_forwarding_is_enabled)             \
_(NAT_DET_ADD_DEL_MAP, nat_det_add_del_map)                             \
_(NAT_DET_FORWARD, nat_det_forward)                                     \
_(NAT_DET_REVERSE, nat_det_reverse)                                     \
_(NAT_DET_MAP_DUMP, nat_det_map_dump)                                   \
_(NAT_DET_CLOSE_SESSION_OUT, nat_det_close_session_out)                 \
_(NAT_DET_CLOSE_SESSION_IN, nat_det_close_session_in)                   \
_(NAT_DET_SESSION_DUMP, nat_det_session_dump)                           \
_(NAT64_ADD_DEL_POOL_ADDR_RANGE, nat64_add_del_pool_addr_range)         \
_(NAT64_POOL_ADDR_DUMP, nat64_pool_addr_dump)                           \
_(NAT64_ADD_DEL_INTERFACE, nat64_add_del_interface)                     \
_(NAT64_INTERFACE_DUMP, nat64_interface_dump)                           \
_(NAT64_ADD_DEL_STATIC_BIB, nat64_add_del_static_bib)                   \
_(NAT64_BIB_DUMP, nat64_bib_dump)                                       \
_(NAT64_ST_DUMP, nat64_st_dump)                                         \
_(NAT64_ADD_DEL_PREFIX, nat64_add_del_prefix)                           \
_(NAT64_PREFIX_DUMP, nat64_prefix_dump)                                 \
_(NAT64_ADD_DEL_INTERFACE_ADDR, nat64_add_del_interface_addr)           \
_(DSLITE_ADD_DEL_POOL_ADDR_RANGE, dslite_add_del_pool_addr_range)       \
_(DSLITE_ADDRESS_DUMP, dslite_address_dump)				\
_(DSLITE_SET_AFTR_ADDR, dslite_set_aftr_addr)                           \
_(DSLITE_GET_AFTR_ADDR, dslite_get_aftr_addr)                           \
_(DSLITE_SET_B4_ADDR, dslite_set_b4_addr)                               \
_(DSLITE_GET_B4_ADDR, dslite_get_b4_addr)                               \
_(NAT66_ADD_DEL_INTERFACE, nat66_add_del_interface)                     \
_(NAT66_INTERFACE_DUMP, nat66_interface_dump)                           \
_(NAT66_ADD_DEL_STATIC_MAPPING, nat66_add_del_static_mapping)           \
_(NAT66_STATIC_MAPPING_DUMP, nat66_static_mapping_dump)

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
