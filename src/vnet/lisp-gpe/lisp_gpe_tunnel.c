/*
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
 */
/**
 * @file
 * @brief Common utility functions for IPv4, IPv6 and L2 LISP-GPE tunnels.
 *
 */
#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe_tunnel.h>
#include <vnet/lisp-gpe/lisp_gpe_adjacency.h>

#include <vnet/fib/fib_table.h>

/**
 * @brief Pool of all LISP tunnels
 */
static lisp_gpe_tunnel_t *lisp_gpe_tunnel_pool;

/**
 * @brief a DB of all tunnels
 */
static uword *lisp_gpe_tunnel_db;

/**
 * @brief Compute IP-UDP-GPE sub-tunnel encap/rewrite header.
 *
 * @param[in]   t       Parent of the sub-tunnel.
 * @param[in]   st      Sub-tunnel.
 * @param[in]   lp      Local and remote locators used in the encap header.
 *
 * @return 0 on success.
 */
u8 *
lisp_gpe_tunnel_build_rewrite (const lisp_gpe_tunnel_t * lgt,
			       const lisp_gpe_adjacency_t * ladj,
			       lisp_gpe_next_protocol_e payload_proto)
{
  lisp_gpe_header_t *lisp0;
  u8 *rw = 0;
  int len;
  gpe_encap_mode_t encap_mode = vnet_gpe_get_encap_mode ();

  if (IP4 == ip_addr_version (&lgt->key->lcl))
    {
      ip4_udp_lisp_gpe_header_t *h0;
      ip4_header_t *ip0;

      len = sizeof (*h0);

      vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

      h0 = (ip4_udp_lisp_gpe_header_t *) rw;

      /* Fixed portion of the (outer) ip4 header */
      ip0 = &h0->ip4;
      ip0->ip_version_and_header_length = 0x45;
      ip0->ttl = 254;
      ip0->protocol = IP_PROTOCOL_UDP;

      /* we fix up the ip4 header length and checksum after-the-fact */
      ip_address_copy_addr (&ip0->src_address, &lgt->key->lcl);
      ip_address_copy_addr (&ip0->dst_address, &lgt->key->rmt);
      ip0->checksum = ip4_header_checksum (ip0);

      /* UDP header, randomize src port on something, maybe? */
      h0->udp.src_port = clib_host_to_net_u16 (4341);
      h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_lisp_gpe);

      /* LISP-gpe header */
      lisp0 = &h0->lisp;
    }
  else
    {
      ip6_udp_lisp_gpe_header_t *h0;
      ip6_header_t *ip0;

      len = sizeof (*h0);

      vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

      h0 = (ip6_udp_lisp_gpe_header_t *) rw;

      /* Fixed portion of the (outer) ip6 header */
      ip0 = &h0->ip6;
      ip0->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (0x6 << 28);
      ip0->hop_limit = 254;
      ip0->protocol = IP_PROTOCOL_UDP;

      /* we fix up the ip6 header length after-the-fact */
      ip_address_copy_addr (&ip0->src_address, &lgt->key->lcl);
      ip_address_copy_addr (&ip0->dst_address, &lgt->key->rmt);

      /* UDP header, randomize src port on something, maybe? */
      h0->udp.src_port = clib_host_to_net_u16 (4341);
      h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_lisp_gpe);

      /* LISP-gpe header */
      lisp0 = &h0->lisp;
    }

  lisp0->flags = ladj->flags;
  if (GPE_ENCAP_VXLAN == encap_mode)
    /* unset P flag */
    lisp0->flags &= ~LISP_GPE_FLAGS_P;

  lisp0->ver_res = 0;
  lisp0->res = 0;
  lisp0->next_protocol = payload_proto;
  lisp0->iid = clib_host_to_net_u32 (ladj->vni) >> 8;	/* first 24 bits only */

  return (rw);
}

static lisp_gpe_tunnel_t *
lisp_gpe_tunnel_db_find (const lisp_gpe_tunnel_key_t * key)
{
  uword *p;

  p = hash_get_mem (lisp_gpe_tunnel_db, (void *) key);

  if (NULL != p)
    {
      return (pool_elt_at_index (lisp_gpe_tunnel_pool, p[0]));
    }
  return (NULL);
}

lisp_gpe_tunnel_t *
lisp_gpe_tunnel_get_i (index_t lgti)
{
  return (pool_elt_at_index (lisp_gpe_tunnel_pool, lgti));
}

index_t
lisp_gpe_tunnel_find_or_create_and_lock (const locator_pair_t * pair,
					 u32 rloc_fib_index)
{
  lisp_gpe_tunnel_key_t key = {
    .lcl = pair->lcl_loc,
    .rmt = pair->rmt_loc,
    .fib_index = rloc_fib_index,
  };
  lisp_gpe_tunnel_t *lgt;
  fib_prefix_t pfx;

  lgt = lisp_gpe_tunnel_db_find (&key);

  if (NULL == lgt)
    {
      pool_get (lisp_gpe_tunnel_pool, lgt);
      memset (lgt, 0, sizeof (*lgt));

      lgt->key = clib_mem_alloc (sizeof (*lgt->key));
      memset (lgt->key, 0, sizeof (*lgt->key));

      lgt->key->rmt = pair->rmt_loc;
      lgt->key->lcl = pair->lcl_loc;
      lgt->key->fib_index = rloc_fib_index;

      /*
       * source the FIB entry for the RLOC so we can track its forwarding
       * chain
       */
      ip_address_to_fib_prefix (&lgt->key->rmt, &pfx);

      lgt->fib_entry_index = fib_table_entry_special_add (rloc_fib_index,
							  &pfx,
							  FIB_SOURCE_RR,
							  FIB_ENTRY_FLAG_NONE);

      hash_set_mem (lisp_gpe_tunnel_db, &lgt->key,
		    (lgt - lisp_gpe_tunnel_pool));
    }

  lgt->locks++;

  return (lgt - lisp_gpe_tunnel_pool);
}

void
lisp_gpe_tunnel_unlock (index_t lgti)
{
  lisp_gpe_tunnel_t *lgt;

  lgt = lisp_gpe_tunnel_get_i (lgti);
  lgt->locks--;

  if (0 == lgt->locks)
    {
      hash_unset_mem (lisp_gpe_tunnel_db, &lgt->key);
      clib_mem_free (lgt->key);
      pool_put (lisp_gpe_tunnel_pool, lgt);
    }
}

const lisp_gpe_tunnel_t *
lisp_gpe_tunnel_get (index_t lgti)
{
  return (lisp_gpe_tunnel_get_i (lgti));
}

/** Format LISP-GPE tunnel. */
u8 *
format_lisp_gpe_tunnel (u8 * s, va_list * args)
{
  lisp_gpe_tunnel_t *lgt = va_arg (*args, lisp_gpe_tunnel_t *);

  s = format (s, "tunnel %d\n", lgt - lisp_gpe_tunnel_pool);
  s = format (s, " fib-index: %d, locks:%d \n",
	      lgt->key->fib_index, lgt->locks);
  s = format (s, " lisp ver 0\n");

  s = format (s, " locator-pair:\n");
  s = format (s, "  local: %U remote: %U\n",
	      format_ip_address, &lgt->key->lcl,
	      format_ip_address, &lgt->key->rmt);
  s = format (s, " RLOC FIB entry: %d\n", lgt->fib_entry_index);

  return s;
}

/**
 * CLI command to show LISP-GPE tunnels.
 */
static clib_error_t *
show_lisp_gpe_tunnel_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  lisp_gpe_tunnel_t *lgt;
  index_t index;

  if (pool_elts (lisp_gpe_tunnel_pool) == 0)
    vlib_cli_output (vm, "No lisp-gpe tunnels configured...");

  if (unformat (input, "%d", &index))
    {
      lgt = lisp_gpe_tunnel_get_i (index);
      vlib_cli_output (vm, "%U", format_lisp_gpe_tunnel, lgt);
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (lgt, lisp_gpe_tunnel_pool,
      ({
	vlib_cli_output (vm, "%U", format_lisp_gpe_tunnel, lgt);
      }));
      /* *INDENT-ON* */
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_lisp_gpe_tunnel_command, static) =
{
  .path = "show gpe tunnel",
  .function = show_lisp_gpe_tunnel_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_gpe_tunnel_module_init (vlib_main_t * vm)
{
  lisp_gpe_tunnel_db = hash_create_mem (0,
					sizeof (lisp_gpe_tunnel_key_t),
					sizeof (uword));

  return (NULL);
}

VLIB_INIT_FUNCTION (lisp_gpe_tunnel_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
