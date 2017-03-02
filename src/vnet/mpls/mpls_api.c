/*
 *------------------------------------------------------------------
 * mpls_api.c - mpls api
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
#include <vnet/mpls/mpls.h>
#include <vnet/mpls/mpls_tunnel.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_api.h>

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

#define foreach_vpe_api_msg                                 \
_(MPLS_IP_BIND_UNBIND, mpls_ip_bind_unbind)                 \
_(MPLS_ROUTE_ADD_DEL, mpls_route_add_del)                   \
_(MPLS_TUNNEL_ADD_DEL, mpls_tunnel_add_del)                 \
_(MPLS_TUNNEL_DUMP, mpls_tunnel_dump)                       \
_(MPLS_FIB_DUMP, mpls_fib_dump)

extern void stats_dslock_with_hint (int hint, int tag);
extern void stats_dsunlock (void);

static int
mpls_ip_bind_unbind_handler (vnet_main_t * vnm,
			     vl_api_mpls_ip_bind_unbind_t * mp)
{
  u32 mpls_fib_index, ip_fib_index;

  mpls_fib_index =
    fib_table_find (FIB_PROTOCOL_MPLS, ntohl (mp->mb_mpls_table_id));

  if (~0 == mpls_fib_index)
    {
      if (mp->mb_create_table_if_needed)
	{
	  mpls_fib_index =
	    fib_table_find_or_create_and_lock (FIB_PROTOCOL_MPLS,
					       ntohl (mp->mb_mpls_table_id));
	}
      else
	return VNET_API_ERROR_NO_SUCH_FIB;
    }

  ip_fib_index = fib_table_find ((mp->mb_is_ip4 ?
				  FIB_PROTOCOL_IP4 :
				  FIB_PROTOCOL_IP6),
				 ntohl (mp->mb_ip_table_id));
  if (~0 == ip_fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_prefix_t pfx = {
    .fp_len = mp->mb_address_length,
  };

  if (mp->mb_is_ip4)
    {
      pfx.fp_proto = FIB_PROTOCOL_IP4;
      clib_memcpy (&pfx.fp_addr.ip4, mp->mb_address,
		   sizeof (pfx.fp_addr.ip4));
    }
  else
    {
      pfx.fp_proto = FIB_PROTOCOL_IP6;
      clib_memcpy (&pfx.fp_addr.ip6, mp->mb_address,
		   sizeof (pfx.fp_addr.ip6));
    }

  if (mp->mb_is_bind)
    fib_table_entry_local_label_add (ip_fib_index, &pfx,
				     ntohl (mp->mb_label));
  else
    fib_table_entry_local_label_remove (ip_fib_index, &pfx,
					ntohl (mp->mb_label));

  return (0);
}

void
vl_api_mpls_ip_bind_unbind_t_handler (vl_api_mpls_ip_bind_unbind_t * mp)
{
  vl_api_mpls_ip_bind_unbind_reply_t *rmp;
  vnet_main_t *vnm;
  int rv;

  vnm = vnet_get_main ();
  vnm->api_errno = 0;

  rv = mpls_ip_bind_unbind_handler (vnm, mp);
  rv = (rv == 0) ? vnm->api_errno : rv;

  REPLY_MACRO (VL_API_MPLS_IP_BIND_UNBIND_REPLY);
}

static int
mpls_route_add_del_t_handler (vnet_main_t * vnm,
			      vl_api_mpls_route_add_del_t * mp)
{
  u32 fib_index, next_hop_fib_index;
  mpls_label_t *label_stack = NULL;
  int rv, ii, n_labels;;

  fib_prefix_t pfx = {
    .fp_len = 21,
    .fp_proto = FIB_PROTOCOL_MPLS,
    .fp_eos = mp->mr_eos,
    .fp_label = ntohl (mp->mr_label),
  };
  if (pfx.fp_eos)
    {
      if (mp->mr_next_hop_proto_is_ip4)
	{
	  pfx.fp_payload_proto = DPO_PROTO_IP4;
	}
      else
	{
	  pfx.fp_payload_proto = DPO_PROTO_IP6;
	}
    }
  else
    {
      pfx.fp_payload_proto = DPO_PROTO_MPLS;
    }

  rv = add_del_route_check (FIB_PROTOCOL_MPLS,
			    mp->mr_table_id,
			    mp->mr_next_hop_sw_if_index,
			    dpo_proto_to_fib (pfx.fp_payload_proto),
			    mp->mr_next_hop_table_id,
			    mp->mr_create_table_if_needed,
			    &fib_index, &next_hop_fib_index);

  if (0 != rv)
    return (rv);

  ip46_address_t nh;
  memset (&nh, 0, sizeof (nh));

  if (mp->mr_next_hop_proto_is_ip4)
    memcpy (&nh.ip4, mp->mr_next_hop, sizeof (nh.ip4));
  else
    memcpy (&nh.ip6, mp->mr_next_hop, sizeof (nh.ip6));

  n_labels = mp->mr_next_hop_n_out_labels;
  if (n_labels == 0)
    ;
  else if (1 == n_labels)
    vec_add1 (label_stack, ntohl (mp->mr_next_hop_out_label_stack[0]));
  else
    {
      vec_validate (label_stack, n_labels - 1);
      for (ii = 0; ii < n_labels; ii++)
	label_stack[ii] = ntohl (mp->mr_next_hop_out_label_stack[ii]);
    }

  return (add_del_route_t_handler (mp->mr_is_multipath, mp->mr_is_add, 0,	// mp->is_drop,
				   0,	// mp->is_unreach,
				   0,	// mp->is_prohibit,
				   0,	// mp->is_local,
				   mp->mr_is_classify,
				   mp->mr_classify_table_index,
				   mp->mr_is_resolve_host,
				   mp->mr_is_resolve_attached,
				   fib_index, &pfx,
				   mp->mr_next_hop_proto_is_ip4,
				   &nh, ntohl (mp->mr_next_hop_sw_if_index),
				   next_hop_fib_index,
				   mp->mr_next_hop_weight,
				   ntohl (mp->mr_next_hop_via_label),
				   label_stack));
}

void
vl_api_mpls_route_add_del_t_handler (vl_api_mpls_route_add_del_t * mp)
{
  vl_api_mpls_route_add_del_reply_t *rmp;
  vnet_main_t *vnm;
  int rv;

  vnm = vnet_get_main ();
  vnm->api_errno = 0;

  rv = mpls_route_add_del_t_handler (vnm, mp);

  rv = (rv == 0) ? vnm->api_errno : rv;

  REPLY_MACRO (VL_API_MPLS_ROUTE_ADD_DEL_REPLY);
}

static void
vl_api_mpls_tunnel_add_del_t_handler (vl_api_mpls_tunnel_add_del_t * mp)
{
  vl_api_mpls_tunnel_add_del_reply_t *rmp;
  int rv = 0;
  u32 tunnel_sw_if_index;
  int ii;

  stats_dslock_with_hint (1 /* release hint */ , 5 /* tag */ );

  if (mp->mt_is_add)
    {
      fib_route_path_t rpath, *rpaths = NULL;
      mpls_label_t *label_stack = NULL;

      memset (&rpath, 0, sizeof (rpath));

      if (mp->mt_next_hop_proto_is_ip4)
	{
	  rpath.frp_proto = FIB_PROTOCOL_IP4;
	  clib_memcpy (&rpath.frp_addr.ip4,
		       mp->mt_next_hop, sizeof (rpath.frp_addr.ip4));
	}
      else
	{
	  rpath.frp_proto = FIB_PROTOCOL_IP6;
	  clib_memcpy (&rpath.frp_addr.ip6,
		       mp->mt_next_hop, sizeof (rpath.frp_addr.ip6));
	}
      rpath.frp_sw_if_index = ntohl (mp->mt_next_hop_sw_if_index);

      for (ii = 0; ii < mp->mt_next_hop_n_out_labels; ii++)
	vec_add1 (label_stack, ntohl (mp->mt_next_hop_out_label_stack[ii]));

      vec_add1 (rpaths, rpath);

      vnet_mpls_tunnel_add (rpaths, label_stack,
			    mp->mt_l2_only, &tunnel_sw_if_index);
      vec_free (rpaths);
      vec_free (label_stack);
    }
  else
    {
      tunnel_sw_if_index = ntohl (mp->mt_sw_if_index);
      vnet_mpls_tunnel_del (tunnel_sw_if_index);
    }

  stats_dsunlock ();

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MPLS_TUNNEL_ADD_DEL_REPLY,
  ({
    rmp->sw_if_index = ntohl(tunnel_sw_if_index);
  }));
  /* *INDENT-ON* */
}

typedef struct mpls_tunnel_send_walk_ctx_t_
{
  unix_shared_memory_queue_t *q;
  u32 index;
  u32 context;
} mpls_tunnel_send_walk_ctx_t;

static void
send_mpls_tunnel_entry (u32 mti, void *arg)
{
  mpls_tunnel_send_walk_ctx_t *ctx;
  vl_api_mpls_tunnel_details_t *mp;
  const mpls_tunnel_t *mt;
  u32 nlabels;

  ctx = arg;

  if (~0 != ctx->index && mti != ctx->index)
    return;

  mt = mpls_tunnel_get (mti);
  nlabels = vec_len (mt->mt_label_stack);

  mp = vl_msg_api_alloc (sizeof (*mp) + nlabels * sizeof (u32));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MPLS_TUNNEL_DETAILS);
  mp->context = ctx->context;

  mp->tunnel_index = ntohl (mti);
  memcpy (mp->mt_next_hop_out_labels,
	  mt->mt_label_stack, nlabels * sizeof (u32));

  // FIXME

  vl_msg_api_send_shmem (ctx->q, (u8 *) & mp);
}

static void
vl_api_mpls_tunnel_dump_t_handler (vl_api_mpls_tunnel_dump_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  mpls_tunnel_send_walk_ctx_t ctx = {
    .q = q,
    .index = ntohl (mp->tunnel_index),
    .context = mp->context,
  };
  mpls_tunnel_walk (send_mpls_tunnel_entry, &ctx);
}

static void
send_mpls_fib_details (vpe_api_main_t * am,
		       unix_shared_memory_queue_t * q,
		       u32 table_id, u32 label, u32 eos,
		       fib_route_path_encode_t * api_rpaths, u32 context)
{
  vl_api_mpls_fib_details_t *mp;
  fib_route_path_encode_t *api_rpath;
  vl_api_fib_path2_t *fp;
  int path_count;

  path_count = vec_len (api_rpaths);
  mp = vl_msg_api_alloc (sizeof (*mp) + path_count * sizeof (*fp));
  if (!mp)
    return;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MPLS_FIB_DETAILS);
  mp->context = context;

  mp->table_id = htonl (table_id);
  mp->eos_bit = eos;
  mp->label = htonl (label);

  mp->count = htonl (path_count);
  fp = mp->path;
  vec_foreach (api_rpath, api_rpaths)
  {
    memset (fp, 0, sizeof (*fp));
    fp->weight = htonl (api_rpath->rpath.frp_weight);
    fp->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
    copy_fib_next_hop (api_rpath, fp);
    fp++;
  }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_mpls_fib_dump_t_handler (vl_api_mpls_fib_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  mpls_main_t *mm = &mpls_main;
  fib_table_t *fib_table;
  fib_node_index_t lfei, *lfeip, *lfeis = NULL;
  mpls_label_t key;
  fib_prefix_t pfx;
  u32 fib_index;
  fib_route_path_encode_t *api_rpaths;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (fib_table, mm->fibs,
  ({
    hash_foreach(key, lfei, fib_table->mpls.mf_entries,
    ({
  vec_add1(lfeis, lfei);
    }));
  }));
  /* *INDENT-ON* */
  vec_sort_with_function (lfeis, fib_entry_cmp_for_sort);

  vec_foreach (lfeip, lfeis)
  {
    fib_entry_get_prefix (*lfeip, &pfx);
    fib_index = fib_entry_get_fib_index (*lfeip);
    fib_table = fib_table_get (fib_index, pfx.fp_proto);
    api_rpaths = NULL;
    fib_entry_encode (*lfeip, &api_rpaths);
    send_mpls_fib_details (am, q,
			   fib_table->ft_table_id,
			   pfx.fp_label, pfx.fp_eos, api_rpaths, mp->context);
    vec_free (api_rpaths);
  }

  vec_free (lfeis);
}

/*
 * mpls_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
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
  foreach_vl_msg_name_crc_mpls;
#undef _
}

static clib_error_t *
mpls_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

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
   * Trace space for 8 MPLS encap labels
   */
  am->api_trace_cfg[VL_API_MPLS_TUNNEL_ADD_DEL].size += 8 * sizeof (u32);

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (mpls_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
