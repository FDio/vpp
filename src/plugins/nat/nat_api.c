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

static void
  vl_api_snat_add_address_range_t_handler
  (vl_api_snat_add_address_range_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_add_address_range_reply_t *rmp;
  ip4_address_t this_addr;
  u32 start_host_order, end_host_order;
  u32 vrf_id;
  int i, count;
  int rv = 0;
  u32 *tmp;

  if (mp->is_ip4 != 1)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
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
    clib_warning ("%U - %U, %d addresses...",
		  format_ip4_address, mp->first_ip_address,
		  format_ip4_address, mp->last_ip_address, count);

  memcpy (&this_addr.as_u8, mp->first_ip_address, 4);

  for (i = 0; i < count; i++)
    {
      if (mp->is_add)
	snat_add_address (sm, &this_addr, vrf_id);
      else
	rv = snat_del_address (sm, this_addr, 0);

      if (rv)
	goto send_reply;

      increment_v4_address (&this_addr);
    }

send_reply:
  REPLY_MACRO (VL_API_SNAT_ADD_ADDRESS_RANGE_REPLY);
}

static void *vl_api_snat_add_address_range_t_print
  (vl_api_snat_add_address_range_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_add_address_range ");
  s = format (s, "%U ", format_ip4_address, mp->first_ip_address);
  if (memcmp (mp->first_ip_address, mp->last_ip_address, 4))
    {
      s = format (s, " - %U ", format_ip4_address, mp->last_ip_address);
    }
  FINISH;
}

static void
  send_snat_address_details
  (snat_address_t * a, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_address_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SNAT_ADDRESS_DETAILS + sm->msg_id_base);
  rmp->is_ip4 = 1;
  clib_memcpy (rmp->ip_address, &(a->addr), 4);
  if (a->fib_index != ~0)
    {
      fib_table_t *fib = fib_table_get (a->fib_index, FIB_PROTOCOL_IP4);
      rmp->vrf_id = ntohl (fib->ft_table_id);
    }
  else
    rmp->vrf_id = ~0;
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_snat_address_dump_t_handler (vl_api_snat_address_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_address_t *a;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach (a, sm->addresses)
    send_snat_address_details (a, q, mp->context);
  /* *INDENT-ON* */
}

static void *vl_api_snat_address_dump_t_print
  (vl_api_snat_address_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_address_dump ");

  FINISH;
}

static void
  vl_api_snat_interface_add_del_feature_t_handler
  (vl_api_snat_interface_add_del_feature_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_interface_add_del_feature_reply_t *rmp;
  u8 is_del = mp->is_add == 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_interface_add_del (sw_if_index, mp->is_inside, is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SNAT_INTERFACE_ADD_DEL_FEATURE_REPLY);
}

static void *vl_api_snat_interface_add_del_feature_t_print
  (vl_api_snat_interface_add_del_feature_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_interface_add_del_feature ");
  s = format (s, "sw_if_index %d %s %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->is_inside ? "in" : "out", mp->is_add ? "" : "del");

  FINISH;
}

static void
  send_snat_interface_details
  (snat_interface_t * i, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_interface_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SNAT_INTERFACE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->is_inside = i->is_inside;
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_snat_interface_dump_t_handler (vl_api_snat_interface_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
  ({
    send_snat_interface_details(i, q, mp->context);
  }));
  /* *INDENT-ON* */
}

static void *vl_api_snat_interface_dump_t_print
  (vl_api_snat_interface_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_interface_dump ");

  FINISH;
}

static void
  vl_api_snat_interface_add_del_output_feature_t_handler
  (vl_api_snat_interface_add_del_output_feature_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_interface_add_del_output_feature_reply_t *rmp;
  u8 is_del = mp->is_add == 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_interface_add_del_output_feature (sw_if_index, mp->is_inside,
					      is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SNAT_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY);
}

static void *vl_api_snat_interface_add_del_output_feature_t_print
  (vl_api_snat_interface_add_del_output_feature_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_interface_add_del_output_feature ");
  s = format (s, "sw_if_index %d %s %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->is_inside ? "in" : "out", mp->is_add ? "" : "del");

  FINISH;
}

static void
send_snat_interface_output_feature_details (snat_interface_t * i,
					    unix_shared_memory_queue_t * q,
					    u32 context)
{
  vl_api_snat_interface_output_feature_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_SNAT_INTERFACE_OUTPUT_FEATURE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->context = context;
  rmp->is_inside = i->is_inside;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_snat_interface_output_feature_dump_t_handler
  (vl_api_snat_interface_output_feature_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (i, sm->output_feature_interfaces,
  ({
    send_snat_interface_output_feature_details(i, q, mp->context);
  }));
  /* *INDENT-ON* */
}

static void *vl_api_snat_interface_output_feature_dump_t_print
  (vl_api_snat_interface_output_feature_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_interface_output_feature_dump ");

  FINISH;
}

static void
  vl_api_snat_add_static_mapping_t_handler
  (vl_api_snat_add_static_mapping_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_add_static_mapping_reply_t *rmp;
  ip4_address_t local_addr, external_addr;
  u16 local_port = 0, external_port = 0;
  u32 vrf_id, external_sw_if_index;
  int rv = 0;
  snat_protocol_t proto;

  if (mp->is_ip4 != 1)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
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

  rv = snat_add_static_mapping (local_addr, external_addr, local_port,
				external_port, vrf_id, mp->addr_only,
				external_sw_if_index, proto, mp->is_add);

send_reply:
  REPLY_MACRO (VL_API_SNAT_ADD_ADDRESS_RANGE_REPLY);
}

static void *vl_api_snat_add_static_mapping_t_print
  (vl_api_snat_add_static_mapping_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_add_static_mapping ");
  s = format (s, "protocol %d local_addr %U external_addr %U ",
	      mp->protocol,
	      format_ip4_address, mp->local_ip_address,
	      format_ip4_address, mp->external_ip_address);

  if (mp->addr_only == 0)
    s = format (s, "local_port %d external_port %d ",
		clib_net_to_host_u16 (mp->local_port),
		clib_net_to_host_u16 (mp->external_port));

  if (mp->vrf_id != ~0)
    s = format (s, "vrf %d", clib_net_to_host_u32 (mp->vrf_id));

  if (mp->external_sw_if_index != ~0)
    s = format (s, "external_sw_if_index %d",
		clib_net_to_host_u32 (mp->external_sw_if_index));
  FINISH;
}

static void
  send_snat_static_mapping_details
  (snat_static_mapping_t * m, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_SNAT_STATIC_MAPPING_DETAILS + sm->msg_id_base);
  rmp->is_ip4 = 1;
  rmp->addr_only = m->addr_only;
  clib_memcpy (rmp->local_ip_address, &(m->local_addr), 4);
  clib_memcpy (rmp->external_ip_address, &(m->external_addr), 4);
  rmp->local_port = htons (m->local_port);
  rmp->external_port = htons (m->external_port);
  rmp->external_sw_if_index = ~0;
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->protocol = snat_proto_to_ip_proto (m->proto);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  send_snat_static_map_resolve_details
  (snat_static_map_resolve_t * m, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_SNAT_STATIC_MAPPING_DETAILS + sm->msg_id_base);
  rmp->is_ip4 = 1;
  rmp->addr_only = m->addr_only;
  clib_memcpy (rmp->local_ip_address, &(m->l_addr), 4);
  rmp->local_port = htons (m->l_port);
  rmp->external_port = htons (m->e_port);
  rmp->external_sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->protocol = snat_proto_to_ip_proto (m->proto);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_snat_static_mapping_dump_t_handler
  (vl_api_snat_static_mapping_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_static_map_resolve_t *rp;
  int j;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (m, sm->static_mappings,
  ({
      if (!vec_len(m->locals))
        send_snat_static_mapping_details (m, q, mp->context);
  }));
  /* *INDENT-ON* */

  for (j = 0; j < vec_len (sm->to_resolve); j++)
    {
      rp = sm->to_resolve + j;
      send_snat_static_map_resolve_details (rp, q, mp->context);
    }
}

static void *vl_api_snat_static_mapping_dump_t_print
  (vl_api_snat_static_mapping_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_static_mapping_dump ");

  FINISH;
}

static void
vl_api_snat_control_ping_t_handler (vl_api_snat_control_ping_t * mp)
{
  vl_api_snat_control_ping_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SNAT_CONTROL_PING_REPLY,
  ({
    rmp->vpe_pid = ntohl (getpid ());
  }));
  /* *INDENT-ON* */
}

static void *vl_api_snat_control_ping_t_print
  (vl_api_snat_control_ping_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_control_ping ");

  FINISH;
}

static void
vl_api_snat_show_config_t_handler (vl_api_snat_show_config_t * mp)
{
  vl_api_snat_show_config_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SNAT_SHOW_CONFIG_REPLY,
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
  }));
  /* *INDENT-ON* */
}

static void *vl_api_snat_show_config_t_print
  (vl_api_snat_show_config_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_show_config ");

  FINISH;
}

static void
vl_api_snat_set_workers_t_handler (vl_api_snat_set_workers_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_set_workers_reply_t *rmp;
  int rv = 0;
  uword *bitmap = 0;
  u64 mask = clib_net_to_host_u64 (mp->worker_mask);

  if (sm->num_workers < 2)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  bitmap = clib_bitmap_set_multiple (bitmap, 0, mask, BITS (mask));
  rv = snat_set_workers (bitmap);
  clib_bitmap_free (bitmap);

send_reply:
  REPLY_MACRO (VL_API_SNAT_SET_WORKERS_REPLY);
}

static void *vl_api_snat_set_workers_t_print
  (vl_api_snat_set_workers_t * mp, void *handle)
{
  u8 *s;
  uword *bitmap = 0;
  u8 first = 1;
  int i;
  u64 mask = clib_net_to_host_u64 (mp->worker_mask);

  s = format (0, "SCRIPT: snat_set_workers ");
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
  send_snat_worker_details
  (u32 worker_index, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_worker_details_t *rmp;
  snat_main_t *sm = &snat_main;
  vlib_worker_thread_t *w =
    vlib_worker_threads + worker_index + sm->first_worker_index;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SNAT_WORKER_DETAILS + sm->msg_id_base);
  rmp->context = context;
  rmp->worker_index = htonl (worker_index);
  rmp->lcore_id = htonl (w->lcore_id);
  strncpy ((char *) rmp->name, (char *) w->name, ARRAY_LEN (rmp->name) - 1);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_snat_worker_dump_t_handler (vl_api_snat_worker_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  u32 *worker_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach (worker_index, sm->workers)
    send_snat_worker_details(*worker_index, q, mp->context);
  /* *INDENT-ON* */
}

static void *vl_api_snat_worker_dump_t_print
  (vl_api_snat_worker_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_worker_dump ");

  FINISH;
}

static void
  vl_api_snat_add_del_interface_addr_t_handler
  (vl_api_snat_add_del_interface_addr_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_add_del_interface_addr_reply_t *rmp;
  u8 is_del = mp->is_add == 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_add_interface_address (sm, sw_if_index, is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SNAT_ADD_DEL_INTERFACE_ADDR_REPLY);
}

static void *vl_api_snat_add_del_interface_addr_t_print
  (vl_api_snat_add_del_interface_addr_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_add_del_interface_addr ");
  s = format (s, "sw_if_index %d %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->is_add ? "" : "del");

  FINISH;
}

static void
  send_snat_interface_addr_details
  (u32 sw_if_index, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_interface_addr_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_SNAT_INTERFACE_ADDR_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (sw_if_index);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_snat_interface_addr_dump_t_handler
  (vl_api_snat_interface_addr_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  u32 *i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach (i, sm->auto_add_sw_if_indices)
    send_snat_interface_addr_details(*i, q, mp->context);
  /* *INDENT-ON* */
}

static void *vl_api_snat_interface_addr_dump_t_print
  (vl_api_snat_interface_addr_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_interface_addr_dump ");

  FINISH;
}

static void
  vl_api_snat_ipfix_enable_disable_t_handler
  (vl_api_snat_ipfix_enable_disable_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_ipfix_enable_disable_reply_t *rmp;
  int rv = 0;

  rv = snat_ipfix_logging_enable_disable (mp->enable,
					  clib_host_to_net_u32
					  (mp->domain_id),
					  clib_host_to_net_u16
					  (mp->src_port));

  REPLY_MACRO (VL_API_SNAT_IPFIX_ENABLE_DISABLE_REPLY);
}

static void *vl_api_snat_ipfix_enable_disable_t_print
  (vl_api_snat_ipfix_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_ipfix_enable_disable ");
  if (mp->domain_id)
    s = format (s, "domain %d ", clib_net_to_host_u32 (mp->domain_id));
  if (mp->src_port)
    s = format (s, "src_port %d ", clib_net_to_host_u16 (mp->src_port));
  if (!mp->enable)
    s = format (s, "disable ");

  FINISH;
}

static void
  send_snat_user_details
  (snat_user_t * u, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_user_details_t *rmp;
  snat_main_t *sm = &snat_main;
  fib_table_t *fib = fib_table_get (u->fib_index, FIB_PROTOCOL_IP4);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SNAT_USER_DETAILS + sm->msg_id_base);

  rmp->vrf_id = ntohl (fib->ft_table_id);

  rmp->is_ip4 = 1;
  clib_memcpy (rmp->ip_address, &(u->addr), 4);
  rmp->nsessions = ntohl (u->nsessions);
  rmp->nstaticsessions = ntohl (u->nstaticsessions);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_snat_user_dump_t_handler (vl_api_snat_user_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  snat_user_t *u;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach (tsm, sm->per_thread_data)
    vec_foreach (u, tsm->users)
      send_snat_user_details (u, q, mp->context);
  /* *INDENT-ON* */
}

static void *vl_api_snat_user_dump_t_print
  (vl_api_snat_user_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_user_dump ");

  FINISH;
}

static void
  send_snat_user_session_details
  (snat_session_t * s, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_user_session_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_SNAT_USER_SESSION_DETAILS + sm->msg_id_base);
  rmp->is_ip4 = 1;
  clib_memcpy (rmp->outside_ip_address, (&s->out2in.addr), 4);
  clib_memcpy (rmp->inside_ip_address, (&s->in2out.addr), 4);
  rmp->is_static = s->flags & SNAT_SESSION_FLAG_STATIC_MAPPING ? 1 : 0;
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

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_snat_user_session_dump_t_handler
  (vl_api_snat_user_session_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  snat_session_t *s;
  clib_bihash_kv_8_8_t key, value;
  snat_user_key_t ukey;
  snat_user_t *u;
  u32 session_index, head_index, elt_index;
  dlist_elt_t *head, *elt;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;
  if (!mp->is_ip4)
    return;

  clib_memcpy (&ukey.addr, mp->ip_address, 4);
  ukey.fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->vrf_id));
  key.key = ukey.as_u64;
  if (!clib_bihash_search_8_8 (&sm->worker_by_in, &key, &value))
    tsm = vec_elt_at_index (sm->per_thread_data, value.value);
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

      send_snat_user_session_details (s, q, mp->context);

      elt_index = elt->next;
      elt = pool_elt_at_index (tsm->list_pool, elt_index);
      session_index = elt->value;
    }
}

static void *vl_api_snat_user_session_dump_t_print
  (vl_api_snat_user_session_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_user_session_dump ");
  s = format (s, "ip_address %U vrf_id %d\n",
	      format_ip4_address, mp->ip_address,
	      clib_net_to_host_u32 (mp->vrf_id));

  FINISH;
}

/******************************************************************/
/*** detrministic NAT/CGN (old, will be deprecated after 17.10) ***/
/******************************************************************/

static void
vl_api_snat_add_det_map_t_handler (vl_api_snat_add_det_map_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_add_det_map_reply_t *rmp;
  int rv = 0;
  ip4_address_t in_addr, out_addr;

  clib_memcpy (&in_addr, mp->in_addr, 4);
  clib_memcpy (&out_addr, mp->out_addr, 4);
  rv = snat_det_add_map (sm, &in_addr, mp->in_plen, &out_addr,
			 mp->out_plen, mp->is_add);

  REPLY_MACRO (VL_API_SNAT_ADD_DET_MAP_REPLY);
}

static void *vl_api_snat_add_det_map_t_print
  (vl_api_snat_add_det_map_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_add_det_map ");
  s = format (s, "inside address %U/%d outside address %U/%d\n",
	      format_ip4_address, mp->in_addr, mp->in_plen,
	      format_ip4_address, mp->out_addr, mp->out_plen);

  FINISH;
}

static void
vl_api_snat_det_forward_t_handler (vl_api_snat_det_forward_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_det_forward_reply_t *rmp;
  int rv = 0;
  u16 lo_port = 0, hi_port = 0;
  snat_det_map_t *dm;
  ip4_address_t in_addr, out_addr;

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
  REPLY_MACRO2 (VL_API_SNAT_DET_FORWARD_REPLY,
  ({
    rmp->out_port_lo = ntohs (lo_port);
    rmp->out_port_hi = ntohs (hi_port);
    rmp->is_ip4 = 1;
    memset (rmp->out_addr, 0, 16);
    clib_memcpy (rmp->out_addr, &out_addr, 4);
  }))
  /* *INDENT-ON* */
}

static void *vl_api_snat_det_forward_t_print
  (vl_api_snat_det_forward_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: smat_det_forward_t");
  s = format (s, "inside ip address %U\n", format_ip4_address, mp->in_addr);

  FINISH;
}

static void
vl_api_snat_det_reverse_t_handler (vl_api_snat_det_reverse_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_det_reverse_reply_t *rmp;
  int rv = 0;
  ip4_address_t out_addr, in_addr;
  snat_det_map_t *dm;

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
  REPLY_MACRO2 (VL_API_SNAT_DET_REVERSE_REPLY,
  ({
    rmp->is_ip4 = 1;
    memset (rmp->in_addr, 0, 16);
    clib_memcpy (rmp->in_addr, &in_addr, 4);
  }))
  /* *INDENT-ON* */
}

static void *vl_api_snat_det_reverse_t_print
  (vl_api_snat_det_reverse_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: smat_det_reverse_t");
  s = format (s, "outside ip address %U outside port %d",
	      format_ip4_address, mp->out_addr, ntohs (mp->out_port));

  FINISH;
}

static void
  sent_snat_det_map_details
  (snat_det_map_t * m, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_det_map_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SNAT_DET_MAP_DETAILS + sm->msg_id_base);
  rmp->is_ip4 = 1;
  clib_memcpy (rmp->in_addr, &m->in_addr, 4);
  rmp->in_plen = m->in_plen;
  clib_memcpy (rmp->out_addr, &m->out_addr, 4);
  rmp->out_plen = m->out_plen;
  rmp->sharing_ratio = htonl (m->sharing_ratio);
  rmp->ports_per_host = htons (m->ports_per_host);
  rmp->ses_num = htonl (m->ses_num);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_snat_det_map_dump_t_handler (vl_api_snat_det_map_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_det_map_t *m;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach(m, sm->det_maps)
    sent_snat_det_map_details(m, q, mp->context);
  /* *INDENT-ON* */
}

static void *vl_api_snat_det_map_dump_t_print
  (vl_api_snat_det_map_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_det_map_dump ");

  FINISH;
}

static void
vl_api_snat_det_set_timeouts_t_handler (vl_api_snat_det_set_timeouts_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_det_set_timeouts_reply_t *rmp;
  int rv = 0;

  sm->udp_timeout = ntohl (mp->udp);
  sm->tcp_established_timeout = ntohl (mp->tcp_established);
  sm->tcp_transitory_timeout = ntohl (mp->tcp_transitory);
  sm->icmp_timeout = ntohl (mp->icmp);

  REPLY_MACRO (VL_API_SNAT_DET_SET_TIMEOUTS_REPLY);
}

static void *vl_api_snat_det_set_timeouts_t_print
  (vl_api_snat_det_set_timeouts_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_det_set_timeouts ");
  s = format (s, "udp %d tcp_established %d tcp_transitory %d icmp %d\n",
	      ntohl (mp->udp),
	      ntohl (mp->tcp_established),
	      ntohl (mp->tcp_transitory), ntohl (mp->icmp));

  FINISH;
}

static void
vl_api_snat_det_get_timeouts_t_handler (vl_api_snat_det_get_timeouts_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_det_get_timeouts_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SNAT_DET_GET_TIMEOUTS_REPLY,
  ({
    rmp->udp = htonl (sm->udp_timeout);
    rmp->tcp_established = htonl (sm->tcp_established_timeout);
    rmp->tcp_transitory = htonl (sm->tcp_transitory_timeout);
    rmp->icmp = htonl (sm->icmp_timeout);
  }))
  /* *INDENT-ON* */
}

static void *vl_api_snat_det_get_timeouts_t_print
  (vl_api_snat_det_get_timeouts_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_det_get_timeouts");

  FINISH;
}

static void
  vl_api_snat_det_close_session_out_t_handler
  (vl_api_snat_det_close_session_out_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_det_close_session_out_reply_t *rmp;
  ip4_address_t out_addr, ext_addr, in_addr;
  snat_det_out_key_t key;
  snat_det_map_t *dm;
  snat_det_session_t *ses;
  int rv = 0;

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
  REPLY_MACRO (VL_API_SNAT_DET_CLOSE_SESSION_OUT_REPLY);
}

static void *vl_api_snat_det_close_session_out_t_print
  (vl_api_snat_det_close_session_out_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_det_close_session_out ");
  s = format (s, "out_addr %U out_port %d "
	      "ext_addr %U ext_port %d\n",
	      format_ip4_address, mp->out_addr, ntohs (mp->out_port),
	      format_ip4_address, mp->ext_addr, ntohs (mp->ext_port));

  FINISH;
}

static void
  vl_api_snat_det_close_session_in_t_handler
  (vl_api_snat_det_close_session_in_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_snat_det_close_session_in_reply_t *rmp;
  ip4_address_t in_addr, ext_addr;
  snat_det_out_key_t key;
  snat_det_map_t *dm;
  snat_det_session_t *ses;
  int rv = 0;

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
  REPLY_MACRO (VL_API_SNAT_DET_CLOSE_SESSION_OUT_REPLY);
}

static void *vl_api_snat_det_close_session_in_t_print
  (vl_api_snat_det_close_session_in_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: snat_det_close_session_in ");
  s = format (s, "in_addr %U in_port %d "
	      "ext_addr %U ext_port %d\n",
	      format_ip4_address, mp->in_addr, ntohs (mp->in_port),
	      format_ip4_address, mp->ext_addr, ntohs (mp->ext_port));

  FINISH;
}

static void
  send_snat_det_session_details
  (snat_det_session_t * s, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_snat_det_session_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SNAT_DET_SESSION_DETAILS + sm->msg_id_base);
  rmp->is_ip4 = 1;
  rmp->in_port = s->in_port;
  clib_memcpy (rmp->ext_addr, &s->out.ext_host_addr, 4);
  rmp->ext_port = s->out.ext_host_port;
  rmp->out_port = s->out.out_port;
  rmp->state = s->state;
  rmp->expire = ntohl (s->expire);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_snat_det_session_dump_t_handler (vl_api_snat_det_session_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  ip4_address_t user_addr;
  snat_det_map_t *dm;
  snat_det_session_t *s, empty_ses;
  u16 i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;
  if (!mp->is_ip4)
    return;

  memset (&empty_ses, 0, sizeof (empty_ses));
  clib_memcpy (&user_addr, mp->user_addr, 4);
  dm = snat_det_map_by_user (sm, &user_addr);
  if (!dm)
    return;

  s = dm->sessions + snat_det_user_ses_offset (&user_addr, dm->in_plen);
  for (i = 0; i < SNAT_DET_SES_PER_USER; i++)
    {
      if (s->out.as_u64)
	send_snat_det_session_details (s, q, mp->context);
      s++;
    }
}

static void *vl_api_snat_det_session_dump_t_print
  (vl_api_snat_det_session_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_det_session_dump ");
  s = format (s, "user_addr %U\n", format_ip4_address, mp->user_addr);

  FINISH;
}

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
  vl_api_snat_set_workers_reply_t *rmp;
  int rv = 0;
  uword *bitmap = 0;
  u64 mask = clib_net_to_host_u64 (mp->worker_mask);

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
send_nat_worker_details (u32 worker_index, unix_shared_memory_queue_t * q,
			 u32 context)
{
  vl_api_nat_worker_details_t *rmp;
  snat_main_t *sm = &snat_main;
  vlib_worker_thread_t *w =
    vlib_worker_threads + worker_index + sm->first_worker_index;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_WORKER_DETAILS + sm->msg_id_base);
  rmp->context = context;
  rmp->worker_index = htonl (worker_index);
  rmp->lcore_id = htonl (w->lcore_id);
  strncpy ((char *) rmp->name, (char *) w->name, ARRAY_LEN (rmp->name) - 1);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nat_worker_dump_t_handler (vl_api_nat_worker_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  u32 *worker_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach (worker_index, sm->workers)
    send_nat_worker_details(*worker_index, q, mp->context);
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
    clib_warning ("%U - %U, %d addresses...",
		  format_ip4_address, mp->first_ip_address,
		  format_ip4_address, mp->last_ip_address, count);

  memcpy (&this_addr.as_u8, mp->first_ip_address, 4);

  for (i = 0; i < count; i++)
    {
      if (mp->is_add)
	snat_add_address (sm, &this_addr, vrf_id);
      else
	rv = snat_del_address (sm, this_addr, 0);

      if (rv)
	goto send_reply;

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
  FINISH;
}

static void
send_nat44_address_details (snat_address_t * a,
			    unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_nat44_address_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_ADDRESS_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->ip_address, &(a->addr), 4);
  if (a->fib_index != ~0)
    {
      fib_table_t *fib = fib_table_get (a->fib_index, FIB_PROTOCOL_IP4);
      rmp->vrf_id = ntohl (fib->ft_table_id);
    }
  else
    rmp->vrf_id = ~0;
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nat44_address_dump_t_handler (vl_api_nat44_address_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_address_t *a;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach (a, sm->addresses)
    send_nat44_address_details (a, q, mp->context);
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
			      unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_nat44_interface_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_INTERFACE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->is_inside = i->is_inside;
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nat44_interface_dump_t_handler (vl_api_nat44_interface_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
  ({
    send_nat44_interface_details(i, q, mp->context);
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

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_interface_add_del_output_feature (sw_if_index, mp->is_inside,
					      is_del);

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
	      mp->is_inside ? "in" : "out", mp->is_add ? "" : "del");

  FINISH;
}

static void
send_nat44_interface_output_feature_details (snat_interface_t * i,
					     unix_shared_memory_queue_t * q,
					     u32 context)
{
  vl_api_nat44_interface_output_feature_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_INTERFACE_OUTPUT_FEATURE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->context = context;
  rmp->is_inside = i->is_inside;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_nat44_interface_output_feature_dump_t_handler
  (vl_api_nat44_interface_output_feature_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (i, sm->output_feature_interfaces,
  ({
    send_nat44_interface_output_feature_details(i, q, mp->context);
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
  int rv = 0;
  snat_protocol_t proto;

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

  rv = snat_add_static_mapping (local_addr, external_addr, local_port,
				external_port, vrf_id, mp->addr_only,
				external_sw_if_index, proto, mp->is_add);

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

  if (mp->vrf_id != ~0)
    s = format (s, "vrf %d", clib_net_to_host_u32 (mp->vrf_id));

  if (mp->external_sw_if_index != ~0)
    s = format (s, "external_sw_if_index %d",
		clib_net_to_host_u32 (mp->external_sw_if_index));
  FINISH;
}

static void
send_nat44_static_mapping_details (snat_static_mapping_t * m,
				   unix_shared_memory_queue_t * q,
				   u32 context)
{
  vl_api_nat44_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_STATIC_MAPPING_DETAILS + sm->msg_id_base);
  rmp->addr_only = m->addr_only;
  clib_memcpy (rmp->local_ip_address, &(m->local_addr), 4);
  clib_memcpy (rmp->external_ip_address, &(m->external_addr), 4);
  rmp->local_port = htons (m->local_port);
  rmp->external_port = htons (m->external_port);
  rmp->external_sw_if_index = ~0;
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->protocol = snat_proto_to_ip_proto (m->proto);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
send_nat44_static_map_resolve_details (snat_static_map_resolve_t * m,
				       unix_shared_memory_queue_t * q,
				       u32 context)
{
  vl_api_nat44_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_STATIC_MAPPING_DETAILS + sm->msg_id_base);
  rmp->addr_only = m->addr_only;
  clib_memcpy (rmp->local_ip_address, &(m->l_addr), 4);
  rmp->local_port = htons (m->l_port);
  rmp->external_port = htons (m->e_port);
  rmp->external_sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->protocol = snat_proto_to_ip_proto (m->proto);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nat44_static_mapping_dump_t_handler (vl_api_nat44_static_mapping_dump_t
					    * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_static_map_resolve_t *rp;
  int j;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (m, sm->static_mappings,
  ({
      if (!vec_len(m->locals))
        send_nat44_static_mapping_details (m, q, mp->context);
  }));
  /* *INDENT-ON* */

  for (j = 0; j < vec_len (sm->to_resolve); j++)
    {
      rp = sm->to_resolve + j;
      send_nat44_static_map_resolve_details (rp, q, mp->context);
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
  vl_api_nat44_add_del_interface_addr_t_handler
  (vl_api_nat44_add_del_interface_addr_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_interface_addr_reply_t *rmp;
  u8 is_del = mp->is_add == 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = snat_add_interface_address (sm, sw_if_index, is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY);
}

static void *vl_api_nat44_add_del_interface_addr_t_print
  (vl_api_nat44_add_del_interface_addr_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_interface_addr ");
  s = format (s, "sw_if_index %d %s",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      mp->is_add ? "" : "del");

  FINISH;
}

static void
send_nat44_interface_addr_details (u32 sw_if_index,
				   unix_shared_memory_queue_t * q,
				   u32 context)
{
  vl_api_nat44_interface_addr_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_INTERFACE_ADDR_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (sw_if_index);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nat44_interface_addr_dump_t_handler (vl_api_nat44_interface_addr_dump_t
					    * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  u32 *i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach (i, sm->auto_add_sw_if_indices)
    send_nat44_interface_addr_details(*i, q, mp->context);
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
send_nat44_user_details (snat_user_t * u, unix_shared_memory_queue_t * q,
			 u32 context)
{
  vl_api_nat44_user_details_t *rmp;
  snat_main_t *sm = &snat_main;
  fib_table_t *fib = fib_table_get (u->fib_index, FIB_PROTOCOL_IP4);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_USER_DETAILS + sm->msg_id_base);

  rmp->vrf_id = ntohl (fib->ft_table_id);

  clib_memcpy (rmp->ip_address, &(u->addr), 4);
  rmp->nsessions = ntohl (u->nsessions);
  rmp->nstaticsessions = ntohl (u->nstaticsessions);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nat44_user_dump_t_handler (vl_api_nat44_user_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  snat_user_t *u;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach (tsm, sm->per_thread_data)
    vec_foreach (u, tsm->users)
      send_nat44_user_details (u, q, mp->context);
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
				 unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_nat44_user_session_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_USER_SESSION_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->outside_ip_address, (&s->out2in.addr), 4);
  clib_memcpy (rmp->inside_ip_address, (&s->in2out.addr), 4);
  rmp->is_static = s->flags & SNAT_SESSION_FLAG_STATIC_MAPPING ? 1 : 0;
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

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nat44_user_session_dump_t_handler (vl_api_nat44_user_session_dump_t *
					  mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  snat_session_t *s;
  clib_bihash_kv_8_8_t key, value;
  snat_user_key_t ukey;
  snat_user_t *u;
  u32 session_index, head_index, elt_index;
  dlist_elt_t *head, *elt;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  clib_memcpy (&ukey.addr, mp->ip_address, 4);
  ukey.fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->vrf_id));
  key.key = ukey.as_u64;
  if (!clib_bihash_search_8_8 (&sm->worker_by_in, &key, &value))
    tsm = vec_elt_at_index (sm->per_thread_data, value.value);
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

      send_nat44_user_session_details (s, q, mp->context);

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
      memset (&lb_addr_port, 0, sizeof (lb_addr_port));
      clib_memcpy (&lb_addr_port.addr, ap->addr, 4);
      lb_addr_port.port = clib_net_to_host_u16 (ap->port);
      lb_addr_port.probability = ap->probability;
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
  int rv = 0;
  nat44_lb_addr_port_t *locals = 0;
  ip4_address_t e_addr;
  snat_protocol_t proto;

  locals = unformat_nat44_lb_addr_port (mp->locals, mp->local_num);
  clib_memcpy (&e_addr, mp->external_addr, 4);
  proto = ip_proto_to_snat_proto (mp->protocol);

  rv =
    nat44_add_del_lb_static_mapping (e_addr,
				     clib_net_to_host_u16 (mp->external_port),
				     proto, clib_net_to_host_u32 (mp->vrf_id),
				     locals, mp->is_add);

  vec_free (locals);

  REPLY_MACRO (VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY);
}

static void *vl_api_nat44_add_del_lb_static_mapping_t_print
  (vl_api_nat44_add_del_lb_static_mapping_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat44_add_del_lb_static_mapping ");
  s = format (s, "is_add %d\n", mp->is_add);

  FINISH;
}

static void
send_nat44_lb_static_mapping_details (snat_static_mapping_t * m,
				      unix_shared_memory_queue_t * q,
				      u32 context)
{
  vl_api_nat44_lb_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat44_lb_addr_port_t *ap;
  vl_api_nat44_lb_addr_port_t *locals;

  rmp =
    vl_msg_api_alloc (sizeof (*rmp) +
		      (vec_len (m->locals) * sizeof (nat44_lb_addr_port_t)));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_LB_STATIC_MAPPING_DETAILS + sm->msg_id_base);

  clib_memcpy (rmp->external_addr, &(m->external_addr), 4);
  rmp->external_port = ntohs (m->external_port);
  rmp->protocol = snat_proto_to_ip_proto (m->proto);
  rmp->vrf_id = ntohl (m->vrf_id);
  rmp->context = context;

  locals = (vl_api_nat44_lb_addr_port_t *) rmp->locals;
  vec_foreach (ap, m->locals)
  {
    clib_memcpy (locals->addr, &(ap->addr), 4);
    locals->port = htons (ap->port);
    locals->probability = ap->probability;
    locals++;
    rmp->local_num++;
  }

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_nat44_lb_static_mapping_dump_t_handler
  (vl_api_nat44_lb_static_mapping_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (m, sm->static_mappings,
  ({
      if (vec_len(m->locals))
        send_nat44_lb_static_mapping_details (m, q, mp->context);
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
    memset (rmp->in_addr, 0, 16);
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
sent_nat_det_map_details (snat_det_map_t * m, unix_shared_memory_queue_t * q,
			  u32 context)
{
  vl_api_nat_det_map_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
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

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nat_det_map_dump_t_handler (vl_api_nat_det_map_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  snat_det_map_t *m;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  vec_foreach(m, sm->det_maps)
    sent_nat_det_map_details(m, q, mp->context);
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
vl_api_nat_det_set_timeouts_t_handler (vl_api_nat_det_set_timeouts_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_det_set_timeouts_reply_t *rmp;
  int rv = 0;

  sm->udp_timeout = ntohl (mp->udp);
  sm->tcp_established_timeout = ntohl (mp->tcp_established);
  sm->tcp_transitory_timeout = ntohl (mp->tcp_transitory);
  sm->icmp_timeout = ntohl (mp->icmp);

  REPLY_MACRO (VL_API_NAT_DET_SET_TIMEOUTS_REPLY);
}

static void *
vl_api_nat_det_set_timeouts_t_print (vl_api_nat_det_set_timeouts_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_det_set_timeouts ");
  s = format (s, "udp %d tcp_established %d tcp_transitory %d icmp %d\n",
	      ntohl (mp->udp),
	      ntohl (mp->tcp_established),
	      ntohl (mp->tcp_transitory), ntohl (mp->icmp));

  FINISH;
}

static void
vl_api_nat_det_get_timeouts_t_handler (vl_api_nat_det_get_timeouts_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_det_get_timeouts_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_DET_GET_TIMEOUTS_REPLY,
  ({
    rmp->udp = htonl (sm->udp_timeout);
    rmp->tcp_established = htonl (sm->tcp_established_timeout);
    rmp->tcp_transitory = htonl (sm->tcp_transitory_timeout);
    rmp->icmp = htonl (sm->icmp_timeout);
  }))
  /* *INDENT-ON* */
}

static void *
vl_api_nat_det_get_timeouts_t_print (vl_api_nat_det_get_timeouts_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat_det_get_timeouts");

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
			      unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_nat_det_session_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_DET_SESSION_DETAILS + sm->msg_id_base);
  rmp->in_port = s->in_port;
  clib_memcpy (rmp->ext_addr, &s->out.ext_host_addr, 4);
  rmp->ext_port = s->out.ext_host_port;
  rmp->out_port = s->out.out_port;
  rmp->state = s->state;
  rmp->expire = ntohl (s->expire);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_nat_det_session_dump_t_handler (vl_api_nat_det_session_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  snat_main_t *sm = &snat_main;
  ip4_address_t user_addr;
  snat_det_map_t *dm;
  snat_det_session_t *s, empty_ses;
  u16 i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;
  if (!mp->is_nat44)
    return;

  memset (&empty_ses, 0, sizeof (empty_ses));
  clib_memcpy (&user_addr, mp->user_addr, 4);
  dm = snat_det_map_by_user (sm, &user_addr);
  if (!dm)
    return;

  s = dm->sessions + snat_det_user_ses_offset (&user_addr, dm->in_plen);
  for (i = 0; i < SNAT_DET_SES_PER_USER; i++)
    {
      if (s->out.as_u64)
	send_nat_det_session_details (s, q, mp->context);
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
  nat64_main_t *nm = &nat64_main;
  int rv = 0;
  ip4_address_t this_addr;
  u32 start_host_order, end_host_order;
  u32 vrf_id;
  int i, count;
  u32 *tmp;

  if (nm->is_disabled)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

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
  unix_shared_memory_queue_t *q;
  u32 context;
} nat64_api_walk_ctx_t;

static int
nat64_api_pool_walk (snat_address_t * a, void *arg)
{
  vl_api_nat64_pool_addr_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat64_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
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

  vl_msg_api_send_shmem (ctx->q, (u8 *) & rmp);

  return 0;
}

static void
vl_api_nat64_pool_addr_dump_t_handler (vl_api_nat64_pool_addr_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  nat64_main_t *nm = &nat64_main;

  if (nm->is_disabled)
    return;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  nat64_api_walk_ctx_t ctx = {
    .q = q,
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
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_add_del_interface_reply_t *rmp;
  int rv = 0;

  if (nm->is_disabled)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    nat64_add_del_interface (ntohl (mp->sw_if_index), mp->is_inside,
			     mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

send_reply:
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
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_INTERFACE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->is_inside = i->is_inside;
  rmp->context = ctx->context;

  vl_msg_api_send_shmem (ctx->q, (u8 *) & rmp);

  return 0;
}

static void
vl_api_nat64_interface_dump_t_handler (vl_api_nat64_interface_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  nat64_main_t *nm = &nat64_main;

  if (nm->is_disabled)
    return;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  nat64_api_walk_ctx_t ctx = {
    .q = q,
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
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_add_del_static_bib_reply_t *rmp;
  ip6_address_t in_addr;
  ip4_address_t out_addr;
  int rv = 0;

  if (nm->is_disabled)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  memcpy (&in_addr.as_u8, mp->i_addr, 16);
  memcpy (&out_addr.as_u8, mp->o_addr, 4);

  rv =
    nat64_add_del_static_bib_entry (&in_addr, &out_addr,
				    clib_net_to_host_u16 (mp->i_port),
				    clib_net_to_host_u16 (mp->o_port),
				    mp->proto,
				    clib_net_to_host_u32 (mp->vrf_id),
				    mp->is_add);

send_reply:
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
  memset (rmp, 0, sizeof (*rmp));
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

  vl_msg_api_send_shmem (ctx->q, (u8 *) & rmp);

  return 0;
}

static void
vl_api_nat64_bib_dump_t_handler (vl_api_nat64_bib_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  nat64_main_t *nm = &nat64_main;

  if (nm->is_disabled)
    return;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  nat64_api_walk_ctx_t ctx = {
    .q = q,
    .context = mp->context,
  };

  nat64_db_bib_walk (&nm->db, mp->proto, nat64_api_bib_walk, &ctx);
}

static void *
vl_api_nat64_bib_dump_t_print (vl_api_nat64_bib_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: snat_bib_dump protocol %d", mp->proto);

  FINISH;
}

static void
vl_api_nat64_set_timeouts_t_handler (vl_api_nat64_set_timeouts_t * mp)
{
  snat_main_t *sm = &snat_main;
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_set_timeouts_reply_t *rmp;
  int rv = 0;

  if (nm->is_disabled)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  rv = nat64_set_icmp_timeout (ntohl (mp->icmp));
  if (rv)
    goto send_reply;
  rv = nat64_set_udp_timeout (ntohl (mp->udp));
  if (rv)
    goto send_reply;
  rv =
    nat64_set_tcp_timeouts (ntohl (mp->tcp_trans), ntohl (mp->tcp_est),
			    ntohl (mp->tcp_incoming_syn));

send_reply:
  REPLY_MACRO (VL_API_NAT64_SET_TIMEOUTS_REPLY);
}

static void *vl_api_nat64_set_timeouts_t_print
  (vl_api_nat64_set_timeouts_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat64_set_timeouts ");
  s =
    format (s,
	    "udp %d icmp %d, tcp_trans %d, tcp_est %d, tcp_incoming_syn %d\n",
	    ntohl (mp->udp), ntohl (mp->icmp), ntohl (mp->tcp_trans),
	    ntohl (mp->tcp_est), ntohl (mp->tcp_incoming_syn));

  FINISH;
}

static void
vl_api_nat64_get_timeouts_t_handler (vl_api_nat64_get_timeouts_t * mp)
{
  snat_main_t *sm = &snat_main;
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_get_timeouts_reply_t *rmp;
  int rv = 0;

  if (nm->is_disabled)
    return;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT64_GET_TIMEOUTS_REPLY,
  ({
    rmp->udp = htonl (nat64_get_udp_timeout());
    rmp->icmp = htonl (nat64_get_icmp_timeout());
    rmp->tcp_trans = htonl (nat64_get_tcp_trans_timeout());
    rmp->tcp_est = htonl (nat64_get_tcp_est_timeout());
    rmp->tcp_incoming_syn = htonl (nat64_get_tcp_incoming_syn_timeout());
  }))
  /* *INDENT-ON* */
}

static void *vl_api_nat64_get_timeouts_t_print
  (vl_api_nat64_get_timeouts_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: nat64_get_timeouts");

  FINISH;
}

static int
nat64_api_st_walk (nat64_db_st_entry_t * ste, void *arg)
{
  vl_api_nat64_st_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat64_api_walk_ctx_t *ctx = arg;
  nat64_main_t *nm = &nat64_main;
  nat64_db_bib_entry_t *bibe;
  fib_table_t *fib;

  bibe = nat64_db_bib_entry_by_index (&nm->db, ste->proto, ste->bibe_index);
  if (!bibe)
    return -1;

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
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

  vl_msg_api_send_shmem (ctx->q, (u8 *) & rmp);

  return 0;
}

static void
vl_api_nat64_st_dump_t_handler (vl_api_nat64_st_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  nat64_main_t *nm = &nat64_main;

  if (nm->is_disabled)
    return;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  nat64_api_walk_ctx_t ctx = {
    .q = q,
    .context = mp->context,
  };

  nat64_db_st_walk (&nm->db, mp->proto, nat64_api_st_walk, &ctx);
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
  nat64_main_t *nm = &nat64_main;
  ip6_address_t prefix;
  int rv = 0;

  if (nm->is_disabled)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  memcpy (&prefix.as_u8, mp->prefix, 16);

  rv =
    nat64_add_del_prefix (&prefix, mp->prefix_len,
			  clib_net_to_host_u32 (mp->vrf_id), mp->is_add);
send_reply:
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
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_PREFIX_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->prefix, &(p->prefix), 16);
  rmp->prefix_len = p->plen;
  rmp->vrf_id = ntohl (p->vrf_id);
  rmp->context = ctx->context;

  vl_msg_api_send_shmem (ctx->q, (u8 *) & rmp);

  return 0;
}

static void
vl_api_nat64_prefix_dump_t_handler (vl_api_nat64_prefix_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  nat64_main_t *nm = &nat64_main;

  if (nm->is_disabled)
    return;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  nat64_api_walk_ctx_t ctx = {
    .q = q,
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

/* List of message types that this plugin understands */
#define foreach_snat_plugin_api_msg                                     \
_(SNAT_ADD_ADDRESS_RANGE, snat_add_address_range)                       \
_(SNAT_INTERFACE_ADD_DEL_FEATURE, snat_interface_add_del_feature)       \
_(SNAT_ADD_STATIC_MAPPING, snat_add_static_mapping)                     \
_(SNAT_CONTROL_PING, snat_control_ping)                                 \
_(SNAT_STATIC_MAPPING_DUMP, snat_static_mapping_dump)                   \
_(SNAT_SHOW_CONFIG, snat_show_config)                                   \
_(SNAT_ADDRESS_DUMP, snat_address_dump)                                 \
_(SNAT_INTERFACE_DUMP, snat_interface_dump)                             \
_(SNAT_SET_WORKERS, snat_set_workers)                                   \
_(SNAT_WORKER_DUMP, snat_worker_dump)                                   \
_(SNAT_ADD_DEL_INTERFACE_ADDR, snat_add_del_interface_addr)             \
_(SNAT_INTERFACE_ADDR_DUMP, snat_interface_addr_dump)                   \
_(SNAT_IPFIX_ENABLE_DISABLE, snat_ipfix_enable_disable)                 \
_(SNAT_USER_DUMP, snat_user_dump)                                       \
_(SNAT_USER_SESSION_DUMP, snat_user_session_dump)                       \
_(SNAT_INTERFACE_ADD_DEL_OUTPUT_FEATURE,                                \
  snat_interface_add_del_output_feature)                                \
_(SNAT_INTERFACE_OUTPUT_FEATURE_DUMP,                                   \
  snat_interface_output_feature_dump)                                   \
_(SNAT_ADD_DET_MAP, snat_add_det_map)                                   \
_(SNAT_DET_FORWARD, snat_det_forward)                                   \
_(SNAT_DET_REVERSE, snat_det_reverse)                                   \
_(SNAT_DET_MAP_DUMP, snat_det_map_dump)                                 \
_(SNAT_DET_SET_TIMEOUTS, snat_det_set_timeouts)                         \
_(SNAT_DET_GET_TIMEOUTS, snat_det_get_timeouts)                         \
_(SNAT_DET_CLOSE_SESSION_OUT, snat_det_close_session_out)               \
_(SNAT_DET_CLOSE_SESSION_IN, snat_det_close_session_in)                 \
_(SNAT_DET_SESSION_DUMP, snat_det_session_dump)                         \
_(NAT_CONTROL_PING, nat_control_ping)                                   \
_(NAT_SHOW_CONFIG, nat_show_config)                                     \
_(NAT_SET_WORKERS, nat_set_workers)                                     \
_(NAT_WORKER_DUMP, nat_worker_dump)                                     \
_(NAT_IPFIX_ENABLE_DISABLE, nat_ipfix_enable_disable)                   \
_(NAT44_ADD_DEL_ADDRESS_RANGE, nat44_add_del_address_range)             \
_(NAT44_INTERFACE_ADD_DEL_FEATURE, nat44_interface_add_del_feature)     \
_(NAT44_ADD_DEL_STATIC_MAPPING, nat44_add_del_static_mapping)           \
_(NAT44_STATIC_MAPPING_DUMP, nat44_static_mapping_dump)                 \
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
_(NAT_DET_ADD_DEL_MAP, nat_det_add_del_map)                             \
_(NAT_DET_FORWARD, nat_det_forward)                                     \
_(NAT_DET_REVERSE, nat_det_reverse)                                     \
_(NAT_DET_MAP_DUMP, nat_det_map_dump)                                   \
_(NAT_DET_SET_TIMEOUTS, nat_det_set_timeouts)                           \
_(NAT_DET_GET_TIMEOUTS, nat_det_get_timeouts)                           \
_(NAT_DET_CLOSE_SESSION_OUT, nat_det_close_session_out)                 \
_(NAT_DET_CLOSE_SESSION_IN, nat_det_close_session_in)                   \
_(NAT_DET_SESSION_DUMP, nat_det_session_dump)                           \
_(NAT64_ADD_DEL_POOL_ADDR_RANGE, nat64_add_del_pool_addr_range)         \
_(NAT64_POOL_ADDR_DUMP, nat64_pool_addr_dump)                           \
_(NAT64_ADD_DEL_INTERFACE, nat64_add_del_interface)                     \
_(NAT64_INTERFACE_DUMP, nat64_interface_dump)                           \
_(NAT64_ADD_DEL_STATIC_BIB, nat64_add_del_static_bib)                   \
_(NAT64_BIB_DUMP, nat64_bib_dump)                                       \
_(NAT64_SET_TIMEOUTS, nat64_set_timeouts)                               \
_(NAT64_GET_TIMEOUTS, nat64_get_timeouts)                               \
_(NAT64_ST_DUMP, nat64_st_dump)                                         \
_(NAT64_ADD_DEL_PREFIX, nat64_add_del_prefix)                           \
_(NAT64_PREFIX_DUMP, nat64_prefix_dump)

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

  name = format (0, "snat_%08x%c", api_version, 0);

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
