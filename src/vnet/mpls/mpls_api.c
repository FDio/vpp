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
#include <vnet/fib/mpls_fib.h>
#include <vnet/fib/fib_path_list.h>

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
_(MPLS_TABLE_ADD_DEL, mpls_table_add_del)                   \
_(MPLS_TUNNEL_ADD_DEL, mpls_tunnel_add_del)                 \
_(MPLS_TUNNEL_DUMP, mpls_tunnel_dump)                       \
_(SW_INTERFACE_SET_MPLS_ENABLE, sw_interface_set_mpls_enable) \
_(MPLS_FIB_DUMP, mpls_fib_dump)

extern void stats_dslock_with_hint (int hint, int tag);
extern void stats_dsunlock (void);

void
mpls_table_delete (u32 table_id, u8 is_api)
{
  u32 fib_index;

  /*
   * The MPLS defult table must also be explicitly created via the API.
   * So in contrast to IP, it gets no special treatment here.
   *
   * The API holds only one lock on the table.
   * i.e. it can be added many times via the API but needs to be
   * deleted only once.
   */
  fib_index = fib_table_find (FIB_PROTOCOL_MPLS, table_id);

  if (~0 != fib_index)
    {
      fib_table_unlock (fib_index,
			FIB_PROTOCOL_MPLS,
			(is_api ? FIB_SOURCE_API : FIB_SOURCE_CLI));
    }
}

void
vl_api_mpls_table_add_del_t_handler (vl_api_mpls_table_add_del_t * mp)
{
  vl_api_mpls_table_add_del_reply_t *rmp;
  vnet_main_t *vnm;
  int rv = 0;

  vnm = vnet_get_main ();
  vnm->api_errno = 0;

  if (mp->mt_is_add)
    mpls_table_create (ntohl (mp->mt_table_id), 1, mp->mt_name);
  else
    mpls_table_delete (ntohl (mp->mt_table_id), 1);

  // NB: Nothing sets rv; none of the above returns an error

  REPLY_MACRO (VL_API_MPLS_TABLE_ADD_DEL_REPLY);
}

static int
mpls_ip_bind_unbind_handler (vnet_main_t * vnm,
			     vl_api_mpls_ip_bind_unbind_t * mp)
{
  u32 mpls_fib_index, ip_fib_index;

  mpls_fib_index =
    fib_table_find (FIB_PROTOCOL_MPLS, ntohl (mp->mb_mpls_table_id));

  if (~0 == mpls_fib_index)
    {
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
      pfx.fp_payload_proto = mp->mr_next_hop_proto;
    }
  else
    {
      pfx.fp_payload_proto = DPO_PROTO_MPLS;
    }

  rv = add_del_route_check (FIB_PROTOCOL_MPLS,
			    mp->mr_table_id,
			    mp->mr_next_hop_sw_if_index,
			    pfx.fp_payload_proto,
			    mp->mr_next_hop_table_id,
			    mp->mr_is_rpf_id,
			    &fib_index, &next_hop_fib_index);

  if (0 != rv)
    return (rv);

  ip46_address_t nh;
  memset (&nh, 0, sizeof (nh));

  if (DPO_PROTO_IP4 == mp->mr_next_hop_proto)
    memcpy (&nh.ip4, mp->mr_next_hop, sizeof (nh.ip4));
  else if (DPO_PROTO_IP6 == mp->mr_next_hop_proto)
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

  /* *INDENT-OFF* */
  return (add_del_route_t_handler (mp->mr_is_multipath, mp->mr_is_add,
                                   0,	// mp->is_drop,
				   0,	// mp->is_unreach,
				   0,	// mp->is_prohibit,
				   0,	// mp->is_local,
				   mp->mr_is_multicast,
                                   mp->mr_is_classify,
                                   mp->mr_classify_table_index,
                                   mp->mr_is_resolve_host,
                                   mp->mr_is_resolve_attached,
                                   mp->mr_is_interface_rx,
                                   mp->mr_is_rpf_id,
                                   0,	// l2_bridged
                                   0,   // is source_lookup
                                   0,   // is_udp_encap
				   fib_index, &pfx,
				   mp->mr_next_hop_proto,
				   &nh, ~0, // next_hop_id
                                   ntohl (mp->mr_next_hop_sw_if_index),
				   next_hop_fib_index,
				   mp->mr_next_hop_weight,
				   mp->mr_next_hop_preference,
				   ntohl (mp->mr_next_hop_via_label),
				   label_stack));
  /* *INDENT-ON* */
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

void
mpls_table_create (u32 table_id, u8 is_api, const u8 * name)
{
  u32 fib_index;

  /*
   * The MPLS defult table must also be explicitly created via the API.
   * So in contrast to IP, it gets no special treatment here.
   */

  /*
   * The API holds only one lock on the table.
   * i.e. it can be added many times via the API but needs to be
   * deleted only once.
   */
  fib_index = fib_table_find (FIB_PROTOCOL_MPLS, table_id);

  if (~0 == fib_index)
    {
      fib_table_find_or_create_and_lock_w_name (FIB_PROTOCOL_MPLS,
						table_id,
						(is_api ?
						 FIB_SOURCE_API :
						 FIB_SOURCE_CLI), name);
    }
}

static void
vl_api_mpls_tunnel_add_del_t_handler (vl_api_mpls_tunnel_add_del_t * mp)
{
  vl_api_mpls_tunnel_add_del_reply_t *rmp;
  int rv = 0;
  u32 tunnel_sw_if_index;
  int ii;
  fib_route_path_t rpath, *rpaths = NULL;

  memset (&rpath, 0, sizeof (rpath));

  stats_dslock_with_hint (1 /* release hint */ , 5 /* tag */ );

  if (mp->mt_next_hop_proto_is_ip4)
    {
      rpath.frp_proto = DPO_PROTO_IP4;
      clib_memcpy (&rpath.frp_addr.ip4,
		   mp->mt_next_hop, sizeof (rpath.frp_addr.ip4));
    }
  else
    {
      rpath.frp_proto = DPO_PROTO_IP6;
      clib_memcpy (&rpath.frp_addr.ip6,
		   mp->mt_next_hop, sizeof (rpath.frp_addr.ip6));
    }
  rpath.frp_sw_if_index = ntohl (mp->mt_next_hop_sw_if_index);
  rpath.frp_weight = 1;

  if (mp->mt_is_add)
    {
      for (ii = 0; ii < mp->mt_next_hop_n_out_labels; ii++)
	vec_add1 (rpath.frp_label_stack,
		  ntohl (mp->mt_next_hop_out_label_stack[ii]));
    }

  vec_add1 (rpaths, rpath);

  tunnel_sw_if_index = ntohl (mp->mt_sw_if_index);

  if (mp->mt_is_add)
    {
      if (~0 == tunnel_sw_if_index)
	tunnel_sw_if_index = vnet_mpls_tunnel_create (mp->mt_l2_only,
						      mp->mt_is_multicast);
      vnet_mpls_tunnel_path_add (tunnel_sw_if_index, rpaths);
    }
  else
    {
      tunnel_sw_if_index = ntohl (mp->mt_sw_if_index);
      if (!vnet_mpls_tunnel_path_remove (tunnel_sw_if_index, rpaths))
	vnet_mpls_tunnel_del (tunnel_sw_if_index);
    }

  vec_free (rpaths);

  stats_dsunlock ();

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MPLS_TUNNEL_ADD_DEL_REPLY,
  ({
    rmp->sw_if_index = ntohl(tunnel_sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_sw_interface_set_mpls_enable_t_handler
  (vl_api_sw_interface_set_mpls_enable_t * mp)
{
  vl_api_sw_interface_set_mpls_enable_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = mpls_sw_interface_enable_disable (&mpls_main,
					 ntohl (mp->sw_if_index),
					 mp->enable, 1);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY);
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
  fib_route_path_encode_t *api_rpaths = NULL, *api_rpath;
  mpls_tunnel_send_walk_ctx_t *ctx;
  vl_api_mpls_tunnel_details_t *mp;
  const mpls_tunnel_t *mt;
  vl_api_fib_path2_t *fp;
  u32 n;

  ctx = arg;

  if (~0 != ctx->index && mti != ctx->index)
    return;

  mt = mpls_tunnel_get (mti);
  n = fib_path_list_get_n_paths (mt->mt_path_list);

  mp = vl_msg_api_alloc (sizeof (*mp) + n * sizeof (vl_api_fib_path2_t));
  memset (mp, 0, sizeof (*mp) + n * sizeof (vl_api_fib_path2_t));

  mp->_vl_msg_id = ntohs (VL_API_MPLS_TUNNEL_DETAILS);
  mp->context = ctx->context;

  mp->mt_tunnel_index = ntohl (mti);
  mp->mt_count = ntohl (n);

  fib_path_list_walk (mt->mt_path_list, fib_path_encode, &api_rpaths);

  fp = mp->mt_paths;
  vec_foreach (api_rpath, api_rpaths)
  {
    memset (fp, 0, sizeof (*fp));

    fp->weight = api_rpath->rpath.frp_weight;
    fp->preference = api_rpath->rpath.frp_preference;
    fp->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
    copy_fib_next_hop (api_rpath, fp);
    fp++;
  }

  // FIXME
  // memcpy (mp->mt_next_hop_out_labels,
  //   mt->mt_label_stack, nlabels * sizeof (u32));


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
		       const fib_table_t * table,
		       u32 label, u32 eos,
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

  mp->table_id = htonl (table->ft_table_id);
  memcpy (mp->table_name, table->ft_desc,
	  clib_min (vec_len (table->ft_desc), sizeof (mp->table_name)));
  mp->eos_bit = eos;
  mp->label = htonl (label);

  mp->count = htonl (path_count);
  fp = mp->path;
  vec_foreach (api_rpath, api_rpaths)
  {
    memset (fp, 0, sizeof (*fp));
    fp->weight = api_rpath->rpath.frp_weight;
    fp->preference = api_rpath->rpath.frp_preference;
    fp->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
    copy_fib_next_hop (api_rpath, fp);
    fp++;
  }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

typedef struct vl_api_mpls_fib_dump_table_walk_ctx_t_
{
  fib_node_index_t *lfeis;
} vl_api_mpls_fib_dump_table_walk_ctx_t;

static int
vl_api_mpls_fib_dump_table_walk (fib_node_index_t fei, void *arg)
{
  vl_api_mpls_fib_dump_table_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->lfeis, fei);

  return (1);
}

static void
vl_api_mpls_fib_dump_t_handler (vl_api_mpls_fib_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  mpls_main_t *mm = &mpls_main;
  fib_table_t *fib_table;
  mpls_fib_t *mpls_fib;
  fib_node_index_t *lfeip = NULL;
  fib_prefix_t pfx;
  u32 fib_index;
  fib_route_path_encode_t *api_rpaths;
  vl_api_mpls_fib_dump_table_walk_ctx_t ctx = {
    .lfeis = NULL,
  };

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (mpls_fib, mm->mpls_fibs,
  ({
    mpls_fib_table_walk (mpls_fib,
                         vl_api_mpls_fib_dump_table_walk,
                         &ctx);
  }));
  /* *INDENT-ON* */
  vec_sort_with_function (ctx.lfeis, fib_entry_cmp_for_sort);

  vec_foreach (lfeip, ctx.lfeis)
  {
    fib_entry_get_prefix (*lfeip, &pfx);
    fib_index = fib_entry_get_fib_index (*lfeip);
    fib_table = fib_table_get (fib_index, pfx.fp_proto);
    api_rpaths = NULL;
    fib_entry_encode (*lfeip, &api_rpaths);
    send_mpls_fib_details (am, q,
			   fib_table, pfx.fp_label,
			   pfx.fp_eos, api_rpaths, mp->context);
    vec_free (api_rpaths);
  }

  vec_free (ctx.lfeis);
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
