/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#include "fib_entry.h"
#include "fib_entry_src.h"
#include "fib_path_list.h"
#include "fib_internal.h"
#include "fib_table.h"
#include "fib_entry_cover.h"
#include "fib_attached_export.h"

#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip_interface.h>

/**
 * Source initialisation Function 
 */
static void
fib_entry_src_interface_init (fib_entry_src_t *src)
{
    src->u.interface.fesi_cover = FIB_NODE_INDEX_INVALID;
    src->u.interface.fesi_sibling = FIB_NODE_INDEX_INVALID;
    src->u.interface.fesi_entry = FIB_NODE_INDEX_INVALID;
}

static void
fib_entry_src_interface_add (fib_entry_src_t *src,
                             const fib_entry_t *entry,
                             fib_entry_flag_t flags,
                             dpo_proto_t proto,
                             const dpo_id_t *dpo)
{
    src->fes_pl = fib_path_list_create_special(
                      proto,
                      fib_entry_src_flags_2_path_list_flags(flags),
                      dpo);
    src->u.interface.fesi_entry = fib_entry_get_index(entry);
}

/*
 * The glean adjacency of a connected prefix holds, in rx_pfx.fp_addr, the
 * address that ARP/ND requests for hosts in the prefix are sent from. It is
 * the address of a local entry: the host prefix, with FIB_ENTRY_FLAG_LOCAL,
 * of one of the interface's addresses in the prefix. A new glean holds the
 * prefix's network address instead.
 *
 * The address the glean holds decides what happens to it:
 *  - if it is the address of a local entry that still exists, the glean is
 *    left alone;
 *  - otherwise the glean is populated with the address of a local entry in
 *    the prefix, or with the network address if there is none.
 * PROVIDES_GLEAN is display-only, read by nothing but the show formatter:
 * it marks the local entry whose address a glean holds.
 */

static int
fib_entry_src_interface_is_connected (const fib_entry_src_t *src)
{
  return (NULL != src && (FIB_ENTRY_FLAG_CONNECTED & src->fes_entry_flags) &&
	  !(FIB_ENTRY_FLAG_LOCAL & src->fes_entry_flags));
}

/* The glean of a connected prefix, if its interface source has one */
static ip_adjacency_t *
fib_entry_src_interface_get_glean (const fib_entry_t *connected)
{
  ip_adjacency_t *adj;
  adj_index_t ai;

  ai = fib_entry_get_adj_for_source (fib_entry_get_index (connected),
				     FIB_SOURCE_INTERFACE);
  if (ADJ_INDEX_INVALID == ai)
    return (NULL);

  adj = adj_get (ai);
  return (IP_LOOKUP_NEXT_GLEAN == adj->lookup_next_index ? adj : NULL);
}

/* The local entry of an address, if the interface source has one */
static fib_node_index_t
fib_entry_src_interface_find_local (u32 fib_index, fib_protocol_t proto,
				    const ip46_address_t *addr)
{
  const fib_entry_src_t *src;
  fib_node_index_t fei;
  fib_prefix_t pfx;

  fib_prefix_from_ip46_addr (proto, addr, &pfx);
  fei = fib_table_lookup_exact_match (fib_index, &pfx);
  if (FIB_NODE_INDEX_INVALID == fei)
    return (FIB_NODE_INDEX_INVALID);

  src = fib_entry_src_find (fib_entry_get (fei), FIB_SOURCE_INTERFACE);
  if (NULL == src || !(FIB_ENTRY_FLAG_LOCAL & src->fes_entry_flags))
    return (FIB_NODE_INDEX_INVALID);

  return (fei);
}

/* Whether the glean holds the address of a local entry */
static int
fib_entry_src_interface_glean_is_held (const fib_entry_t *connected,
				       const ip_adjacency_t *adj)
{
  const fib_prefix_t *rx = &adj->sub_type.glean.rx_pfx;
  fib_node_index_t fei;

  fei = fib_entry_src_interface_find_local (connected->fe_fib_index,
					    rx->fp_proto, &rx->fp_addr);
  return (FIB_NODE_INDEX_INVALID != fei);
}

static void
fib_entry_src_interface_set_provides (fib_node_index_t fei, int provides)
{
  fib_entry_src_t *src;

  if (FIB_NODE_INDEX_INVALID == fei)
    return;

  src = fib_entry_src_find (fib_entry_get (fei), FIB_SOURCE_INTERFACE);
  if (NULL == src)
    return;

  if (provides)
    src->fes_flags |= FIB_ENTRY_SRC_FLAG_PROVIDES_GLEAN;
  else
    src->fes_flags &= ~FIB_ENTRY_SRC_FLAG_PROVIDES_GLEAN;
}

/*
 * Make a local entry's address the source of the glean's ARP/ND requests,
 * or, with no local entry, go back to the prefix's network address.
 */
static void
fib_entry_src_interface_glean_set (const fib_entry_t *connected,
				   ip_adjacency_t *adj, fib_node_index_t local)
{
  fib_prefix_t *rx = &adj->sub_type.glean.rx_pfx;
  fib_prefix_t net;

  fib_entry_src_interface_set_provides (
    fib_entry_src_interface_find_local (connected->fe_fib_index,
					rx->fp_proto, &rx->fp_addr),
    0);

  if (FIB_NODE_INDEX_INVALID != local)
    {
      rx->fp_addr = fib_entry_get (local)->fe_prefix.fp_addr;
      fib_entry_src_interface_set_provides (local, 1);
    }
  else
    {
      fib_prefix_normalize (rx, &net);
      rx->fp_addr = net.fp_addr;
    }
}

/*
 * A local entry in the connected prefix, other than exclude, to populate
 * its glean from: the one of the first of the interface's addresses in the
 * prefix, in the order they were configured. The interface's addresses are
 * used rather than the entries the prefix covers, since a local entry
 * tracks its nearest less specific entry as its cover, which can be a
 * more-specific route inside the prefix, or a less specific one while the
 * prefix is new.
 */
static fib_node_index_t
fib_entry_src_interface_glean_candidate (const fib_entry_t *connected,
					 fib_node_index_t exclude)
{
  const fib_prefix_t *cpfx = &connected->fe_prefix;
  fib_node_index_t found = FIB_NODE_INDEX_INVALID;
  ip_interface_address_t *ia;
  ip_lookup_main_t *lm;
  u32 sw_if_index;

  switch (cpfx->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
      lm = &ip4_main.lookup_main;
      break;
    case FIB_PROTOCOL_IP6:
      lm = &ip6_main.lookup_main;
      break;
    default:
      return (FIB_NODE_INDEX_INVALID);
    }

  sw_if_index = fib_entry_get_resolving_interface_for_source (
    fib_entry_get_index (connected), FIB_SOURCE_INTERFACE);
  if (~0 == sw_if_index)
    return (FIB_NODE_INDEX_INVALID);

  foreach_ip_interface_address (lm, ia, sw_if_index, 0, ({
    ip46_address_t addr;
    fib_node_index_t fei;
    fib_prefix_t pfx;

    addr = to_ip46 (FIB_PROTOCOL_IP6 == cpfx->fp_proto,
		    ip_interface_address_get_address (lm, ia));
    fib_prefix_from_ip46_addr (cpfx->fp_proto, &addr, &pfx);
    if (!fib_prefix_is_cover (cpfx, &pfx))
      continue;

    fei = fib_entry_src_interface_find_local (connected->fe_fib_index,
					      cpfx->fp_proto, &addr);
    if (FIB_NODE_INDEX_INVALID != fei && exclude != fei)
      {
	found = fei;
	break;
      }
  }));

  return (found);
}

/* Populate the glean of a connected prefix unless a local entry holds it */
static void
fib_entry_src_interface_glean_populate (const fib_entry_t *connected)
{
  ip_adjacency_t *adj;

  adj = fib_entry_src_interface_get_glean (connected);
  if (NULL == adj || fib_entry_src_interface_glean_is_held (connected, adj))
    return;

  fib_entry_src_interface_glean_set (
    connected, adj,
    fib_entry_src_interface_glean_candidate (connected,
					     FIB_NODE_INDEX_INVALID));
}

/*
 * The nearest entry at or above fei that is a connected prefix of the
 * interface source. A local entry whose cover is fei provides the glean of
 * that prefix.
 */
static fib_entry_t *
fib_entry_src_interface_glean_owner (fib_node_index_t fei)
{
  while (FIB_NODE_INDEX_INVALID != fei)
    {
      fib_entry_t *entry = fib_entry_get (fei);

      if (fib_entry_src_interface_is_connected (
	    fib_entry_src_find (entry, FIB_SOURCE_INTERFACE)))
	return (entry);

      if (0 == entry->fe_prefix.fp_len)
	break;
      fei = fib_table_get_less_specific (entry->fe_fib_index,
					 &entry->fe_prefix);
    }
  return (NULL);
}

/*
 * A local entry is going away. Every glean that holds its address is
 * populated from another local entry in its prefix, or goes back to the
 * network address.
 */
static void
fib_entry_src_interface_glean_release (const fib_entry_t *local)
{
  fib_node_index_t fei;

  fei = fib_table_get_less_specific (local->fe_fib_index, &local->fe_prefix);

  while (FIB_NODE_INDEX_INVALID != fei)
    {
      fib_entry_t *entry = fib_entry_get (fei);
      ip_adjacency_t *adj;

      if (fib_entry_src_interface_is_connected (
	    fib_entry_src_find (entry, FIB_SOURCE_INTERFACE)) &&
	  NULL != (adj = fib_entry_src_interface_get_glean (entry)) &&
	  ip46_address_is_equal (&adj->sub_type.glean.rx_pfx.fp_addr,
				 &local->fe_prefix.fp_addr))
	fib_entry_src_interface_glean_set (
	  entry, adj,
	  fib_entry_src_interface_glean_candidate (
	    entry, fib_entry_get_index (local)));

      if (0 == entry->fe_prefix.fp_len)
	break;
      fei = fib_table_get_less_specific (entry->fe_fib_index,
					 &entry->fe_prefix);
    }
}

/*
 * Source removal. Unlike deactivate, it is called whether or not the source
 * is active, so this is where a local entry gives up the gleans that hold
 * its address.
 */
static void
fib_entry_src_interface_remove (fib_entry_src_t *src)
{
    if ((FIB_ENTRY_FLAG_LOCAL & src->fes_entry_flags) &&
        FIB_NODE_INDEX_INVALID != src->u.interface.fesi_entry)
        fib_entry_src_interface_glean_release (
            fib_entry_get (src->u.interface.fesi_entry));

    src->fes_pl = FIB_NODE_INDEX_INVALID;
    ASSERT(src->u.interface.fesi_sibling == ~0);
}

static void
fib_entry_src_interface_path_swap (fib_entry_src_t *src,
				   const fib_entry_t *entry,
				   fib_path_list_flags_t pl_flags,
				   const fib_route_path_t *paths)
{
    src->fes_pl = fib_path_list_create(pl_flags, paths);
}

/*
 * Source activate. 
 * Called when the source is the new best source on the entry
 */
static int
fib_entry_src_interface_activate (fib_entry_src_t *src,
				  const fib_entry_t *fib_entry)
{
    fib_entry_t *cover, *connected;
    ip_adjacency_t *adj;

    if (FIB_ENTRY_FLAG_LOCAL & src->fes_entry_flags)
    {
	/*
	 * Track the covering attached/connected cover. This is so that
	 * during an attached export of the cover, this local prefix is
	 * also exported
	 */
	src->u.interface.fesi_cover =
	    fib_table_get_less_specific(fib_entry->fe_fib_index,
					&fib_entry->fe_prefix);

	ASSERT(FIB_NODE_INDEX_INVALID != src->u.interface.fesi_cover);

	cover = fib_entry_get(src->u.interface.fesi_cover);

	src->u.interface.fesi_sibling =
	    fib_entry_cover_track(cover, fib_entry_get_index(fib_entry));

	/*
	 * Provide the glean of the connected prefix above, unless another
	 * local entry already does. The cover can be a more-specific route
	 * inside that prefix, so look past it.
	 */
	connected = fib_entry_src_interface_glean_owner (
	    src->u.interface.fesi_cover);
	if (NULL != connected &&
	    NULL != (adj = fib_entry_src_interface_get_glean (connected)) &&
	    !fib_entry_src_interface_glean_is_held (connected, adj))
	    fib_entry_src_interface_glean_set (connected, adj,
					       fib_entry_get_index (fib_entry));
    }
    else if (fib_entry_src_interface_is_connected (src))
    {
	/*
	 * A local entry provides the glean when it is activated under this
	 * prefix. That has not happened if the prefix was added after the
	 * local entry was activated under a less specific or a more-specific
	 * entry, or if the prefix joined an entry that already existed from
	 * another source, e.g. a route via the interface: no cover change
	 * reaches the local entry then.
	 */
	fib_entry_src_interface_glean_populate (fib_entry);
    }

    return (!0);
}


/*
 * Source Deactivate. 
 * Called when the source is no longer best source on the entry
 */
static void
fib_entry_src_interface_deactivate (fib_entry_src_t *src,
				    const fib_entry_t *fib_entry)
{
    fib_entry_t *cover;

    /*
     * remove the dependency on the covering entry
     */
    if (FIB_NODE_INDEX_INVALID != src->u.interface.fesi_cover)
    {
	cover = fib_entry_get(src->u.interface.fesi_cover);
	fib_entry_cover_untrack(cover, src->u.interface.fesi_sibling);

	src->u.interface.fesi_cover = FIB_NODE_INDEX_INVALID;
	src->u.interface.fesi_sibling = ~0;
    }
}

static fib_entry_src_cover_res_t
fib_entry_src_interface_cover_change (fib_entry_src_t *src,
				      const fib_entry_t *fib_entry)
{
    fib_entry_src_cover_res_t res = {
	.install = !0,
	.bw_reason = FIB_NODE_BW_REASON_FLAG_NONE,
    };

    if (FIB_NODE_INDEX_INVALID == src->u.interface.fesi_cover)
    {
	/*
	 * not tracking the cover. surprised we got poked?
	 */
	return (res);
    }

    /*
     * this function is called when this entry's cover has a more specific
     * entry inserted benaeth it. That does not necessarily mean that this
     * entry is covered by the new prefix. check that
     */
    if (src->u.interface.fesi_cover !=
        fib_table_get_less_specific(fib_entry->fe_fib_index,
                                    &fib_entry->fe_prefix))
    {
	fib_entry_src_interface_deactivate(src, fib_entry);
	fib_entry_src_interface_activate(src, fib_entry);
    }
    return (res);
}

static void
fib_entry_src_interface_installed (fib_entry_src_t *src,
				   const fib_entry_t *fib_entry)
{
    /*
     * The interface source now rules! poke our cover to get exported
     */
    fib_entry_t *cover;

    if (FIB_NODE_INDEX_INVALID != src->u.interface.fesi_cover)
    {
	cover = fib_entry_get(src->u.interface.fesi_cover);

	fib_attached_export_covered_added(cover,
					  fib_entry_get_index(fib_entry));
    }
}

static u8*
fib_entry_src_interface_format (fib_entry_src_t *src,
				u8* s)
{
    return (format(s, " cover:%d", src->u.interface.fesi_cover));
}

const static fib_entry_src_vft_t interface_src_vft = {
    .fesv_init = fib_entry_src_interface_init,
    .fesv_add = fib_entry_src_interface_add,
    .fesv_remove = fib_entry_src_interface_remove,
    .fesv_path_swap = fib_entry_src_interface_path_swap,
    .fesv_activate = fib_entry_src_interface_activate,
    .fesv_deactivate = fib_entry_src_interface_deactivate,
    .fesv_format = fib_entry_src_interface_format,
    .fesv_installed = fib_entry_src_interface_installed,
    .fesv_cover_change = fib_entry_src_interface_cover_change,
    /*
     * not concerned about updates to the cover. the cover will
     * decide to export or not
     */
};

void
fib_entry_src_interface_register (void)
{
    fib_entry_src_behaviour_register(FIB_SOURCE_BH_INTERFACE,
                                     &interface_src_vft);
}
