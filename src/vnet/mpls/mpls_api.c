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
			      vl_api_mpls_route_add_del_t * mp,
			      u32 * stats_index)
{
  fib_mpls_label_t *label_stack = NULL;
  u32 fib_index, next_hop_fib_index;
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
  else
    {
      vec_validate (label_stack, n_labels - 1);
      for (ii = 0; ii < n_labels; ii++)
	{
	  label_stack[ii].fml_value =
	    ntohl (mp->mr_next_hop_out_label_stack[ii].label);
	  label_stack[ii].fml_ttl = mp->mr_next_hop_out_label_stack[ii].ttl;
	  label_stack[ii].fml_exp = mp->mr_next_hop_out_label_stack[ii].exp;
	  label_stack[ii].fml_mode =
	    (mp->mr_next_hop_out_label_stack[ii].is_uniform ?
	     FIB_MPLS_LSP_MODE_UNIFORM : FIB_MPLS_LSP_MODE_PIPE);
	}
    }

  /* *INDENT-OFF* */
  rv = add_del_route_t_handler (mp->mr_is_multipath, mp->mr_is_add,
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
                                label_stack);
  /* *INDENT-ON* */

  if (mp->mr_is_add && 0 == rv)
    *stats_index = fib_table_entry_get_stats_index (fib_index, &pfx);

  return (rv);
}

void
vl_api_mpls_route_add_del_t_handler (vl_api_mpls_route_add_del_t * mp)
{
  vl_api_mpls_route_add_del_reply_t *rmp;
  vnet_main_t *vnm;
  u32 stats_index;
  int rv;

  vnm = vnet_get_main ();
  stats_index = ~0;

  rv = mpls_route_add_del_t_handler (vnm, mp, &stats_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_MPLS_ROUTE_ADD_DEL_REPLY,
  ({
    rmp->stats_index = htonl (stats_index);
  }));
  /* *INDENT-ON* */
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
  u32 tunnel_sw_if_index = ~0, tunnel_index = ~0, next_hop_via_label;
  vl_api_mpls_tunnel_add_del_reply_t *rmp;
  fib_route_path_t rpath, *rpaths = NULL;
  int ii, rv = 0;

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
  rpath.frp_weight = mp->mt_next_hop_weight;
  rpath.frp_preference = mp->mt_next_hop_preference;

  next_hop_via_label = ntohl (mp->mt_next_hop_via_label);
  if ((MPLS_LABEL_INVALID != next_hop_via_label) && (0 != next_hop_via_label))
    {
      rpath.frp_proto = DPO_PROTO_MPLS;
      rpath.frp_local_label = next_hop_via_label;
      rpath.frp_eos = MPLS_NON_EOS;
    }

  if (rpath.frp_sw_if_index == ~0)
    {				/* recursive path, set fib index */
      rpath.frp_fib_index =
	fib_table_find (dpo_proto_to_fib (rpath.frp_proto),
			ntohl (mp->mt_next_hop_table_id));
      if (rpath.frp_fib_index == ~0)
	{
	  rv = VNET_API_ERROR_NO_SUCH_FIB;
	  goto out;
	}
    }

  if (mp->mt_is_add)
    {
      for (ii = 0; ii < mp->mt_next_hop_n_out_labels; ii++)
	{
	  fib_mpls_label_t fml = {
	    .fml_value = ntohl (mp->mt_next_hop_out_label_stack[ii].label),
	    .fml_ttl = mp->mt_next_hop_out_label_stack[ii].ttl,
	    .fml_exp = mp->mt_next_hop_out_label_stack[ii].exp,
	    .fml_mode = (mp->mt_next_hop_out_label_stack[ii].is_uniform ?
			 FIB_MPLS_LSP_MODE_UNIFORM : FIB_MPLS_LSP_MODE_PIPE),
	  };
	  vec_add1 (rpath.frp_label_stack, fml);
	}
    }

  vec_add1 (rpaths, rpath);

  tunnel_sw_if_index = ntohl (mp->mt_sw_if_index);

  if (mp->mt_is_add)
    {
      if (~0 == tunnel_sw_if_index)
	tunnel_sw_if_index = vnet_mpls_tunnel_create (mp->mt_l2_only,
						      mp->mt_is_multicast);
      vnet_mpls_tunnel_path_add (tunnel_sw_if_index, rpaths);

      tunnel_index = vnet_mpls_tunnel_get_index (tunnel_sw_if_index);
    }
  else
    {
      tunnel_index = vnet_mpls_tunnel_get_index (tunnel_sw_if_index);
      tunnel_sw_if_index = ntohl (mp->mt_sw_if_index);
      if (!vnet_mpls_tunnel_path_remove (tunnel_sw_if_index, rpaths))
	vnet_mpls_tunnel_del (tunnel_sw_if_index);
    }

  vec_free (rpaths);

  stats_dsunlock ();

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MPLS_TUNNEL_ADD_DEL_REPLY,
  ({
    rmp->sw_if_index = ntohl(tunnel_sw_if_index);
    rmp->tunnel_index = ntohl(tunnel_index);
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
  vl_api_registration_t *reg;
  u32 sw_if_index;
  u32 context;
} mpls_tunnel_send_walk_ctx_t;

static void
send_mpls_tunnel_entry (u32 mti, void *arg)
{
  fib_route_path_encode_t *api_rpaths = NULL, *api_rpath;
  mpls_tunnel_send_walk_ctx_t *ctx;
  vl_api_mpls_tunnel_details_t *mp;
  const mpls_tunnel_t *mt;
  vl_api_fib_path_t *fp;
  u32 n;

  ctx = arg;

  mt = mpls_tunnel_get (mti);

  if (~0 != ctx->sw_if_index && mt->mt_sw_if_index != ctx->sw_if_index)
    return;

  n = fib_path_list_get_n_paths (mt->mt_path_list);

  mp = vl_msg_api_alloc (sizeof (*mp) + n * sizeof (vl_api_fib_path_t));
  memset (mp, 0, sizeof (*mp) + n * sizeof (vl_api_fib_path_t));

  mp->_vl_msg_id = ntohs (VL_API_MPLS_TUNNEL_DETAILS);
  mp->context = ctx->context;

  mp->mt_tunnel_index = ntohl (mti);
  mp->mt_sw_if_index = ntohl (mt->mt_sw_if_index);
  mp->mt_count = ntohl (n);

  fib_path_list_walk (mt->mt_path_list, fib_path_encode, &api_rpaths);

  fp = mp->mt_paths;
  vec_foreach (api_rpath, api_rpaths)
  {
    fib_api_path_encode (api_rpath, fp);
    fp++;
  }

  vl_api_send_msg (ctx->reg, (u8 *) mp);
}

static void
vl_api_mpls_tunnel_dump_t_handler (vl_api_mpls_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  mpls_tunnel_send_walk_ctx_t ctx = {
    .reg = reg,
    .sw_if_index = ntohl (mp->sw_if_index),
    .context = mp->context,
  };
  mpls_tunnel_walk (send_mpls_tunnel_entry, &ctx);
}

static void
send_mpls_fib_details (vpe_api_main_t * am,
		       vl_api_registration_t * reg,
		       const fib_table_t * table,
		       const fib_prefix_t * pfx,
		       fib_route_path_encode_t * api_rpaths, u32 context)
{
  vl_api_mpls_fib_details_t *mp;
  fib_route_path_encode_t *api_rpath;
  vl_api_fib_path_t *fp;
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
  mp->eos_bit = pfx->fp_eos;
  mp->label = htonl (pfx->fp_label);

  mp->count = htonl (path_count);
  fp = mp->path;
  vec_foreach (api_rpath, api_rpaths)
  {
    fib_api_path_encode (api_rpath, fp);
    fp++;
  }

  vl_api_send_msg (reg, (u8 *) mp);
}

typedef struct vl_api_mpls_fib_dump_table_walk_ctx_t_
{
  fib_node_index_t *lfeis;
} vl_api_mpls_fib_dump_table_walk_ctx_t;

static fib_table_walk_rc_t
vl_api_mpls_fib_dump_table_walk (fib_node_index_t fei, void *arg)
{
  vl_api_mpls_fib_dump_table_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->lfeis, fei);

  return (FIB_TABLE_WALK_CONTINUE);
}

static void
vl_api_mpls_fib_dump_t_handler (vl_api_mpls_fib_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  mpls_main_t *mm = &mpls_main;
  fib_table_t *fib_table;
  mpls_fib_t *mpls_fib;
  fib_node_index_t *lfeip = NULL;
  const fib_prefix_t *pfx;
  u32 fib_index;
  fib_route_path_encode_t *api_rpaths;
  vl_api_mpls_fib_dump_table_walk_ctx_t ctx = {
    .lfeis = NULL,
  };

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
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
    pfx = fib_entry_get_prefix (*lfeip);
    fib_index = fib_entry_get_fib_index (*lfeip);
    fib_table = fib_table_get (fib_index, pfx->fp_proto);
    api_rpaths = NULL;
    fib_entry_encode (*lfeip, &api_rpaths);
    send_mpls_fib_details (am, reg, fib_table, pfx, api_rpaths, mp->context);
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
