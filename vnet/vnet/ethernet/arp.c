/*
 * ethernet/arp.c: IP v4 ARP node
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/l2/l2_input.h>
#include <vppinfra/mhash.h>

void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);

typedef struct
{
  u32 sw_if_index;
  u32 fib_index;
  ip4_address_t ip4_address;
} ethernet_arp_ip4_key_t;

typedef struct
{
  ethernet_arp_ip4_key_t key;
  u8 ethernet_address[6];

  u16 flags;
#define ETHERNET_ARP_IP4_ENTRY_FLAG_STATIC (1 << 0)
#define ETHERNET_ARP_IP4_ENTRY_FLAG_GLEAN  (2 << 0)

  u64 cpu_time_last_updated;

  u32 *adjacencies;
} ethernet_arp_ip4_entry_t;

typedef struct
{
  u32 lo_addr;
  u32 hi_addr;
  u32 fib_index;
} ethernet_proxy_arp_t;

typedef struct
{
  u32 next_index;
  uword node_index;
  uword type_opaque;
  uword data;
  /* Used for arp event notification only */
  void *data_callback;
  u32 pid;
} pending_resolution_t;

typedef struct
{
  /* Hash tables mapping name to opcode. */
  uword *opcode_by_name;

  /* lite beer "glean" adjacency handling */
  uword *pending_resolutions_by_address;
  pending_resolution_t *pending_resolutions;

  /* Mac address change notification */
  uword *mac_changes_by_address;
  pending_resolution_t *mac_changes;

  ethernet_arp_ip4_entry_t *ip4_entry_pool;

  mhash_t ip4_entry_by_key;

  /* ARP attack mitigation */
  u32 arp_delete_rotor;
  u32 limit_arp_cache_size;

  /* Proxy arp vector */
  ethernet_proxy_arp_t *proxy_arps;
} ethernet_arp_main_t;

static ethernet_arp_main_t ethernet_arp_main;

static u8 *
format_ethernet_arp_hardware_type (u8 * s, va_list * va)
{
  ethernet_arp_hardware_type_t h = va_arg (*va, ethernet_arp_hardware_type_t);
  char *t = 0;
  switch (h)
    {
#define _(n,f) case n: t = #f; break;
      foreach_ethernet_arp_hardware_type;
#undef _

    default:
      return format (s, "unknown 0x%x", h);
    }

  return format (s, "%s", t);
}

static u8 *
format_ethernet_arp_opcode (u8 * s, va_list * va)
{
  ethernet_arp_opcode_t o = va_arg (*va, ethernet_arp_opcode_t);
  char *t = 0;
  switch (o)
    {
#define _(f) case ETHERNET_ARP_OPCODE_##f: t = #f; break;
      foreach_ethernet_arp_opcode;
#undef _

    default:
      return format (s, "unknown 0x%x", o);
    }

  return format (s, "%s", t);
}

static uword
unformat_ethernet_arp_opcode_host_byte_order (unformat_input_t * input,
					      va_list * args)
{
  int *result = va_arg (*args, int *);
  ethernet_arp_main_t *am = &ethernet_arp_main;
  int x, i;

  /* Numeric opcode. */
  if (unformat (input, "0x%x", &x) || unformat (input, "%d", &x))
    {
      if (x >= (1 << 16))
	return 0;
      *result = x;
      return 1;
    }

  /* Named type. */
  if (unformat_user (input, unformat_vlib_number_by_name,
		     am->opcode_by_name, &i))
    {
      *result = i;
      return 1;
    }

  return 0;
}

static uword
unformat_ethernet_arp_opcode_net_byte_order (unformat_input_t * input,
					     va_list * args)
{
  int *result = va_arg (*args, int *);
  if (!unformat_user
      (input, unformat_ethernet_arp_opcode_host_byte_order, result))
    return 0;

  *result = clib_host_to_net_u16 ((u16) * result);
  return 1;
}

static u8 *
format_ethernet_arp_header (u8 * s, va_list * va)
{
  ethernet_arp_header_t *a = va_arg (*va, ethernet_arp_header_t *);
  u32 max_header_bytes = va_arg (*va, u32);
  uword indent;
  u16 l2_type, l3_type;

  if (max_header_bytes != 0 && sizeof (a[0]) > max_header_bytes)
    return format (s, "ARP header truncated");

  l2_type = clib_net_to_host_u16 (a->l2_type);
  l3_type = clib_net_to_host_u16 (a->l3_type);

  indent = format_get_indent (s);

  s = format (s, "%U, type %U/%U, address size %d/%d",
	      format_ethernet_arp_opcode, clib_net_to_host_u16 (a->opcode),
	      format_ethernet_arp_hardware_type, l2_type,
	      format_ethernet_type, l3_type,
	      a->n_l2_address_bytes, a->n_l3_address_bytes);

  if (l2_type == ETHERNET_ARP_HARDWARE_TYPE_ethernet
      && l3_type == ETHERNET_TYPE_IP4)
    {
      s = format (s, "\n%U%U/%U -> %U/%U",
		  format_white_space, indent,
		  format_ethernet_address, a->ip4_over_ethernet[0].ethernet,
		  format_ip4_address, &a->ip4_over_ethernet[0].ip4,
		  format_ethernet_address, a->ip4_over_ethernet[1].ethernet,
		  format_ip4_address, &a->ip4_over_ethernet[1].ip4);
    }
  else
    {
      uword n2 = a->n_l2_address_bytes;
      uword n3 = a->n_l3_address_bytes;
      s = format (s, "\n%U%U/%U -> %U/%U",
		  format_white_space, indent,
		  format_hex_bytes, a->data + 0 * n2 + 0 * n3, n2,
		  format_hex_bytes, a->data + 1 * n2 + 0 * n3, n3,
		  format_hex_bytes, a->data + 1 * n2 + 1 * n3, n2,
		  format_hex_bytes, a->data + 2 * n2 + 1 * n3, n3);
    }

  return s;
}

static u8 *
format_ethernet_arp_ip4_entry (u8 * s, va_list * va)
{
  vnet_main_t *vnm = va_arg (*va, vnet_main_t *);
  ethernet_arp_ip4_entry_t *e = va_arg (*va, ethernet_arp_ip4_entry_t *);
  vnet_sw_interface_t *si;
  ip4_fib_t *fib;
  u8 *flags = 0;

  if (!e)
    return format (s, "%=12s%=6s%=16s%=6s%=20s%=24s", "Time", "FIB", "IP4",
		   "Flags", "Ethernet", "Interface");

  fib = find_ip4_fib_by_table_index_or_id (&ip4_main, e->key.fib_index,
					   IP4_ROUTE_FLAG_FIB_INDEX);
  si = vnet_get_sw_interface (vnm, e->key.sw_if_index);

  if (e->flags & ETHERNET_ARP_IP4_ENTRY_FLAG_GLEAN)
    flags = format (flags, "G");

  if (e->flags & ETHERNET_ARP_IP4_ENTRY_FLAG_STATIC)
    flags = format (flags, "S");

  s = format (s, "%=12U%=6u%=16U%=6s%=20U%=24U",
	      format_vlib_cpu_time, vnm->vlib_main, e->cpu_time_last_updated,
	      fib->table_id,
	      format_ip4_address, &e->key.ip4_address,
	      flags ? (char *) flags : "",
	      format_ethernet_address, e->ethernet_address,
	      format_vnet_sw_interface_name, vnm, si);

  vec_free (flags);
  return s;
}

typedef struct
{
  u8 packet_data[64];
} ethernet_arp_input_trace_t;

static u8 *
format_ethernet_arp_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ethernet_arp_input_trace_t *t = va_arg (*va, ethernet_arp_input_trace_t *);

  s = format (s, "%U",
	      format_ethernet_arp_header,
	      t->packet_data, sizeof (t->packet_data));

  return s;
}

clib_error_t *
ethernet_arp_sw_interface_up_down (vnet_main_t * vnm,
				   u32 sw_if_index, u32 flags)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ethernet_arp_ip4_entry_t *e;
  u32 i;
  u32 *to_add_del = 0;

  /* *INDENT-OFF* */
 pool_foreach (e, am->ip4_entry_pool, ({
    if (e->key.sw_if_index == sw_if_index)
	vec_add1 (to_add_del, e - am->ip4_entry_pool);
  }));
 /* *INDENT-ON* */

  for (i = 0; i < vec_len (to_add_del); i++)
    {
      ethernet_arp_ip4_over_ethernet_address_t arp_add;
      e = pool_elt_at_index (am->ip4_entry_pool, to_add_del[i]);

      clib_memcpy (&arp_add.ethernet, e->ethernet_address, 6);
      arp_add.ip4.as_u32 = e->key.ip4_address.as_u32;

      if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
	{
	  vnet_arp_set_ip4_over_ethernet (vnm,
					  e->key.sw_if_index,
					  e->key.fib_index, &arp_add,
					  e->flags &
					  ETHERNET_ARP_IP4_ENTRY_FLAG_STATIC);
	}
      else if ((e->flags & ETHERNET_ARP_IP4_ENTRY_FLAG_STATIC) == 0)
	{
	  vnet_arp_unset_ip4_over_ethernet (vnm,
					    e->key.sw_if_index,
					    e->key.fib_index, &arp_add);
	}
    }

  vec_free (to_add_del);
  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ethernet_arp_sw_interface_up_down);

static int
vnet_arp_set_ip4_over_ethernet_internal (vnet_main_t * vnm,
					 u32 sw_if_index,
					 u32 fib_index,
					 void *a_arg, int is_static);

static int
vnet_arp_unset_ip4_over_ethernet_internal (vnet_main_t * vnm,
					   u32 sw_if_index,
					   u32 fib_index, void *a_arg);

typedef struct
{
  u32 sw_if_index;
  u32 fib_index;
  ethernet_arp_ip4_over_ethernet_address_t a;
  int is_static;
  int is_remove;		/* set is_remove=1 to clear arp entry */
} vnet_arp_set_ip4_over_ethernet_rpc_args_t;

static void set_ip4_over_ethernet_rpc_callback
  (vnet_arp_set_ip4_over_ethernet_rpc_args_t * a)
{
  vnet_main_t *vm = vnet_get_main ();
  ASSERT (os_get_cpu_number () == 0);

  if (a->is_remove)
    vnet_arp_unset_ip4_over_ethernet_internal (vm,
					       a->sw_if_index,
					       a->fib_index, &(a->a));
  else
    vnet_arp_set_ip4_over_ethernet_internal (vm,
					     a->sw_if_index,
					     a->fib_index,
					     &(a->a), a->is_static);
}

int
vnet_arp_set_ip4_over_ethernet (vnet_main_t * vnm,
				u32 sw_if_index,
				u32 fib_index, void *a_arg, int is_static)
{
  ethernet_arp_ip4_over_ethernet_address_t *a = a_arg;
  vnet_arp_set_ip4_over_ethernet_rpc_args_t args;

  args.sw_if_index = sw_if_index;
  args.fib_index = fib_index;
  args.is_static = is_static;
  args.is_remove = 0;
  clib_memcpy (&args.a, a, sizeof (*a));

  vl_api_rpc_call_main_thread (set_ip4_over_ethernet_rpc_callback,
			       (u8 *) & args, sizeof (args));
  return 0;
}

int
vnet_arp_set_ip4_over_ethernet_internal (vnet_main_t * vnm,
					 u32 sw_if_index,
					 u32 fib_index,
					 void *a_arg, int is_static)
{
  ethernet_arp_ip4_key_t k;
  ethernet_arp_ip4_entry_t *e = 0;
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ethernet_arp_ip4_over_ethernet_address_t *a = a_arg;
  vlib_main_t *vm = vlib_get_main ();
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  int make_new_arp_cache_entry = 1;
  uword *p;
  ip4_add_del_route_args_t args;
  ip_adjacency_t adj, *existing_adj;
  pending_resolution_t *pr, *mc;

  u32 next_index;
  u32 adj_index;

  fib_index = (fib_index != (u32) ~ 0)
    ? fib_index : im->fib_index_by_sw_if_index[sw_if_index];

  k.sw_if_index = sw_if_index;
  k.ip4_address = a->ip4;
  k.fib_index = fib_index;

  p = mhash_get (&am->ip4_entry_by_key, &k);
  if (p)
    {
      e = pool_elt_at_index (am->ip4_entry_pool, p[0]);

      /* Refuse to over-write static arp. */
      if (!is_static && (e->flags & ETHERNET_ARP_IP4_ENTRY_FLAG_STATIC))
	return -2;
      make_new_arp_cache_entry = 0;
    }

  /* Note: always install the route. It might have been deleted */
  memset (&adj, 0, sizeof (adj));
  adj.lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
  adj.n_adj = 1;		/*  otherwise signature compare fails */

  vnet_rewrite_for_sw_interface (vnm, VNET_L3_PACKET_TYPE_IP4, sw_if_index, ip4_rewrite_node.index, a->ethernet,	/* destination address */
				 &adj.rewrite_header,
				 sizeof (adj.rewrite_data));

  /* result of this lookup should be next-hop adjacency */
  adj_index = ip4_fib_lookup_with_table (im, fib_index, &a->ip4, 0);
  existing_adj = ip_get_adjacency (lm, adj_index);

  if (existing_adj->lookup_next_index == IP_LOOKUP_NEXT_ARP &&
      existing_adj->arp.next_hop.ip4.as_u32 == a->ip4.as_u32)
    {
      u32 *ai;
      u32 *adjs = vec_dup (e->adjacencies);
      /* Update all adj assigned to this arp entry */
      vec_foreach (ai, adjs)
      {
	int i;
	ip_adjacency_t *uadj = ip_get_adjacency (lm, *ai);
	for (i = 0; i < uadj->n_adj; i++)
	  if (uadj[i].lookup_next_index == IP_LOOKUP_NEXT_ARP &&
	      uadj[i].arp.next_hop.ip4.as_u32 == a->ip4.as_u32)
	    ip_update_adjacency (lm, *ai + i, &adj);
      }
      vec_free (adjs);
    }
  else
    {
      /* Check that new adjacency actually isn't exactly the same as
       *  what is already there. If we over-write the adjacency with
       *  exactly the same info, its technically a new adjacency with
       *  new counters, but to user it appears as counters reset.
       */
      if (vnet_ip_adjacency_share_compare (&adj, existing_adj) == 0)
	{
	  /* create new adj */
	  args.table_index_or_table_id = fib_index;
	  args.flags =
	    IP4_ROUTE_FLAG_FIB_INDEX | IP4_ROUTE_FLAG_ADD |
	    IP4_ROUTE_FLAG_NEIGHBOR;
	  args.dst_address = a->ip4;
	  args.dst_address_length = 32;
	  args.adj_index = ~0;
	  args.add_adj = &adj;
	  args.n_add_adj = 1;
	  ip4_add_del_route (im, &args);
	}
    }

  if (make_new_arp_cache_entry)
    {
      pool_get (am->ip4_entry_pool, e);
      mhash_set (&am->ip4_entry_by_key, &k, e - am->ip4_entry_pool,
		 /* old value */ 0);
      e->key = k;
    }

  /* Update time stamp and ethernet address. */
  clib_memcpy (e->ethernet_address, a->ethernet,
	       sizeof (e->ethernet_address));
  e->cpu_time_last_updated = clib_cpu_time_now ();
  if (is_static)
    e->flags |= ETHERNET_ARP_IP4_ENTRY_FLAG_STATIC;

  /* Customer(s) waiting for this address to be resolved? */
  p = hash_get (am->pending_resolutions_by_address, a->ip4.as_u32);
  if (p)
    {
      next_index = p[0];

      while (next_index != (u32) ~ 0)
	{
	  pr = pool_elt_at_index (am->pending_resolutions, next_index);
	  vlib_process_signal_event (vm, pr->node_index,
				     pr->type_opaque, pr->data);
	  next_index = pr->next_index;
	  pool_put (am->pending_resolutions, pr);
	}

      hash_unset (am->pending_resolutions_by_address, a->ip4.as_u32);
    }

  /* Customer(s) requesting ARP event for this address? */
  p = hash_get (am->mac_changes_by_address, a->ip4.as_u32);
  if (p)
    {
      next_index = p[0];

      while (next_index != (u32) ~ 0)
	{
	  int (*fp) (u32, u8 *, u32, u32);
	  int rv = 1;
	  mc = pool_elt_at_index (am->mac_changes, next_index);
	  fp = mc->data_callback;

	  /* Call the user's data callback, return 1 to suppress dup events */
	  if (fp)
	    rv = (*fp) (mc->data, a->ethernet, sw_if_index, 0);

	  /* 
	   * Signal the resolver process, as long as the user
	   * says they want to be notified
	   */
	  if (rv == 0)
	    vlib_process_signal_event (vm, mc->node_index,
				       mc->type_opaque, mc->data);
	  next_index = mc->next_index;
	}
    }

  return 0;
}

void
vnet_register_ip4_arp_resolution_event (vnet_main_t * vnm,
					void *address_arg,
					uword node_index,
					uword type_opaque, uword data)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ip4_address_t *address = address_arg;
  uword *p;
  pending_resolution_t *pr;

  pool_get (am->pending_resolutions, pr);

  pr->next_index = ~0;
  pr->node_index = node_index;
  pr->type_opaque = type_opaque;
  pr->data = data;
  pr->data_callback = 0;

  p = hash_get (am->pending_resolutions_by_address, address->as_u32);
  if (p)
    {
      /* Insert new resolution at the head of the list */
      pr->next_index = p[0];
      hash_unset (am->pending_resolutions_by_address, address->as_u32);
    }

  hash_set (am->pending_resolutions_by_address, address->as_u32,
	    pr - am->pending_resolutions);
}

int
vnet_add_del_ip4_arp_change_event (vnet_main_t * vnm,
				   void *data_callback,
				   u32 pid,
				   void *address_arg,
				   uword node_index,
				   uword type_opaque, uword data, int is_add)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ip4_address_t *address = address_arg;
  uword *p;
  pending_resolution_t *mc;
  void (*fp) (u32, u8 *) = data_callback;

  if (is_add)
    {
      pool_get (am->mac_changes, mc);

      mc->next_index = ~0;
      mc->node_index = node_index;
      mc->type_opaque = type_opaque;
      mc->data = data;
      mc->data_callback = data_callback;
      mc->pid = pid;

      p = hash_get (am->mac_changes_by_address, address->as_u32);
      if (p)
	{
	  /* Insert new resolution at the head of the list */
	  mc->next_index = p[0];
	  hash_unset (am->mac_changes_by_address, address->as_u32);
	}

      hash_set (am->mac_changes_by_address, address->as_u32,
		mc - am->mac_changes);
      return 0;
    }
  else
    {
      u32 index;
      pending_resolution_t *mc_last = 0;

      p = hash_get (am->mac_changes_by_address, address->as_u32);
      if (p == 0)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      index = p[0];

      while (index != (u32) ~ 0)
	{
	  mc = pool_elt_at_index (am->mac_changes, index);
	  if (mc->node_index == node_index &&
	      mc->type_opaque == type_opaque && mc->pid == pid)
	    {
	      /* Clients may need to clean up pool entries, too */
	      if (fp)
		(*fp) (mc->data, 0 /* no new mac addrs */ );
	      if (index == p[0])
		{
		  hash_unset (am->mac_changes_by_address, address->as_u32);
		  if (mc->next_index != ~0)
		    hash_set (am->mac_changes_by_address, address->as_u32,
			      mc->next_index);
		  pool_put (am->mac_changes, mc);
		  return 0;
		}
	      else
		{
		  ASSERT (mc_last);
		  mc_last->next_index = mc->next_index;
		  pool_put (am->mac_changes, mc);
		  return 0;
		}
	    }
	  mc_last = mc;
	  index = mc->next_index;
	}

      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
}

/* Either we drop the packet or we send a reply to the sender. */
typedef enum
{
  ARP_INPUT_NEXT_DROP,
  ARP_INPUT_NEXT_REPLY_TX,
  ARP_INPUT_N_NEXT,
} arp_input_next_t;

#define foreach_ethernet_arp_error					\
  _ (replies_sent, "ARP replies sent")					\
  _ (l2_type_not_ethernet, "L2 type not ethernet")			\
  _ (l3_type_not_ip4, "L3 type not IP4")				\
  _ (l3_src_address_not_local, "IP4 source address not local to subnet") \
  _ (l3_dst_address_not_local, "IP4 destination address not local to subnet") \
  _ (l3_src_address_is_local, "IP4 source address matches local interface") \
  _ (l3_src_address_learned, "ARP request IP4 source address learned")  \
  _ (replies_received, "ARP replies received")				\
  _ (opcode_not_request, "ARP opcode not request")                      \
  _ (proxy_arp_replies_sent, "Proxy ARP replies sent")			\
  _ (l2_address_mismatch, "ARP hw addr does not match L2 frame src addr") \
  _ (missing_interface_address, "ARP missing interface address") \
  _ (gratuitous_arp, "ARP probe or announcement dropped") \

typedef enum
{
#define _(sym,string) ETHERNET_ARP_ERROR_##sym,
  foreach_ethernet_arp_error
#undef _
    ETHERNET_ARP_N_ERROR,
} ethernet_arp_input_error_t;

/* get first interface address */
ip4_address_t *
ip4_interface_first_address (ip4_main_t * im, u32 sw_if_index,
			     ip_interface_address_t ** result_ia)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *result = 0;

  /* *INDENT-OFF* */
  foreach_ip_interface_address (lm, ia, sw_if_index,
				1 /* honor unnumbered */ ,
  ({
    ip4_address_t * a =
      ip_interface_address_get_address (lm, ia);
    result = a; break;
  }));
  /* *INDENT-ON* */

  if (result_ia)
    *result_ia = result ? ia : 0;
  return result;
}

static void
unset_random_arp_entry (void)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ethernet_arp_ip4_entry_t *e;
  vnet_main_t *vnm = vnet_get_main ();
  ethernet_arp_ip4_over_ethernet_address_t delme;
  u32 index;

  index = pool_next_index (am->ip4_entry_pool, am->arp_delete_rotor);
  am->arp_delete_rotor = index;

  /* Try again from elt 0, could happen if an intfc goes down */
  if (index == ~0)
    {
      index = pool_next_index (am->ip4_entry_pool, am->arp_delete_rotor);
      am->arp_delete_rotor = index;
    }

  /* Nothing left in the pool */
  if (index == ~0)
    return;

  e = pool_elt_at_index (am->ip4_entry_pool, index);

  clib_memcpy (&delme.ethernet, e->ethernet_address, 6);
  delme.ip4.as_u32 = e->key.ip4_address.as_u32;

  vnet_arp_unset_ip4_over_ethernet (vnm, e->key.sw_if_index,
				    e->key.fib_index, &delme);
}

static void
arp_unnumbered (vlib_buffer_t * p0,
		u32 pi0,
		ethernet_header_t * eth0, ip_interface_address_t * ifa0)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *vim = &vnm->interface_main;
  vnet_sw_interface_t *si;
  vnet_hw_interface_t *hi;
  u32 unnum_src_sw_if_index;
  u32 *broadcast_swifs = 0;
  u32 *buffers = 0;
  u32 n_alloc = 0;
  vlib_buffer_t *b0;
  int i;
  u8 dst_mac_address[6];
  i16 header_size;
  ethernet_arp_header_t *arp0;

  /* Save the dst mac address */
  clib_memcpy (dst_mac_address, eth0->dst_address, sizeof (dst_mac_address));

  /* Figure out which sw_if_index supplied the address */
  unnum_src_sw_if_index = ifa0->sw_if_index;

  /* Track down all users of the unnumbered source */
  /* *INDENT-OFF* */
  pool_foreach (si, vim->sw_interfaces,
  ({
    if (si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED &&
	(si->unnumbered_sw_if_index == unnum_src_sw_if_index))
      {
	vec_add1 (broadcast_swifs, si->sw_if_index);
      }
  }));
  /* *INDENT-ON* */

  ASSERT (vec_len (broadcast_swifs));

  /* Allocate buffering if we need it */
  if (vec_len (broadcast_swifs) > 1)
    {
      vec_validate (buffers, vec_len (broadcast_swifs) - 2);
      n_alloc = vlib_buffer_alloc (vm, buffers, vec_len (buffers));
      _vec_len (buffers) = n_alloc;
      for (i = 0; i < n_alloc; i++)
	{
	  b0 = vlib_get_buffer (vm, buffers[i]);

	  /* xerox (partially built) ARP pkt */
	  clib_memcpy (b0->data, p0->data,
		       p0->current_length + p0->current_data);
	  b0->current_data = p0->current_data;
	  b0->current_length = p0->current_length;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    vnet_buffer (p0)->sw_if_index[VLIB_RX];
	}
    }

  vec_insert (buffers, 1, 0);
  buffers[0] = pi0;

  for (i = 0; i < vec_len (buffers); i++)
    {
      b0 = vlib_get_buffer (vm, buffers[i]);
      arp0 = vlib_buffer_get_current (b0);

      hi = vnet_get_sup_hw_interface (vnm, broadcast_swifs[i]);
      si = vnet_get_sw_interface (vnm, broadcast_swifs[i]);

      /* For decoration, most likely */
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = hi->sw_if_index;

      /* Fix ARP pkt src address */
      clib_memcpy (arp0->ip4_over_ethernet[0].ethernet, hi->hw_address, 6);

      /* Build L2 encaps for this swif */
      header_size = sizeof (ethernet_header_t);
      if (si->sub.eth.flags.one_tag)
	header_size += 4;
      else if (si->sub.eth.flags.two_tags)
	header_size += 8;

      vlib_buffer_advance (b0, -header_size);
      eth0 = vlib_buffer_get_current (b0);

      if (si->sub.eth.flags.one_tag)
	{
	  ethernet_vlan_header_t *outer = (void *) (eth0 + 1);

	  eth0->type = si->sub.eth.flags.dot1ad ?
	    clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD) :
	    clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
	  outer->priority_cfi_and_id =
	    clib_host_to_net_u16 (si->sub.eth.outer_vlan_id);
	  outer->type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);

	}
      else if (si->sub.eth.flags.two_tags)
	{
	  ethernet_vlan_header_t *outer = (void *) (eth0 + 1);
	  ethernet_vlan_header_t *inner = (void *) (outer + 1);

	  eth0->type = si->sub.eth.flags.dot1ad ?
	    clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD) :
	    clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
	  outer->priority_cfi_and_id =
	    clib_host_to_net_u16 (si->sub.eth.outer_vlan_id);
	  outer->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
	  inner->priority_cfi_and_id =
	    clib_host_to_net_u16 (si->sub.eth.inner_vlan_id);
	  inner->type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);

	}
      else
	{
	  eth0->type = clib_host_to_net_u16 (ETHERNET_TYPE_ARP);
	}

      /* Restore the original dst address, set src address */
      clib_memcpy (eth0->dst_address, dst_mac_address,
		   sizeof (eth0->dst_address));
      clib_memcpy (eth0->src_address, hi->hw_address,
		   sizeof (eth0->src_address));

      /* Transmit replicas */
      if (i > 0)
	{
	  vlib_frame_t *f =
	    vlib_get_frame_to_node (vm, hi->output_node_index);
	  u32 *to_next = vlib_frame_vector_args (f);
	  to_next[0] = buffers[i];
	  f->n_vectors = 1;
	  vlib_put_frame_to_node (vm, hi->output_node_index, f);
	}
    }

  /* The regular path outputs the original pkt.. */
  vnet_buffer (p0)->sw_if_index[VLIB_TX] = broadcast_swifs[0];

  vec_free (broadcast_swifs);
  vec_free (buffers);
}

static uword
arp_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  vnet_main_t *vnm = vnet_get_main ();
  ip4_main_t *im4 = &ip4_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 n_replies_sent = 0, n_proxy_arp_replies_sent = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ethernet_arp_input_trace_t));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  vnet_hw_interface_t *hw_if0;
	  ethernet_arp_header_t *arp0;
	  ethernet_header_t *eth0;
	  ip_interface_address_t *ifa0;
	  ip_adjacency_t *adj0;
	  ip4_address_t *if_addr0;
	  ip4_address_t proxy_src;
	  u32 pi0, error0, next0, sw_if_index0;
	  u8 is_request0, src_is_local0, dst_is_local0, is_unnum0;
	  ethernet_proxy_arp_t *pa;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  arp0 = vlib_buffer_get_current (p0);

	  is_request0 = arp0->opcode
	    == clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request);

	  error0 = ETHERNET_ARP_ERROR_replies_sent;

	  error0 =
	    (arp0->l2_type !=
	     clib_net_to_host_u16 (ETHERNET_ARP_HARDWARE_TYPE_ethernet) ?
	     ETHERNET_ARP_ERROR_l2_type_not_ethernet : error0);
	  error0 =
	    (arp0->l3_type !=
	     clib_net_to_host_u16 (ETHERNET_TYPE_IP4) ?
	     ETHERNET_ARP_ERROR_l3_type_not_ip4 : error0);

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  if (error0)
	    goto drop1;

	  /* Check that IP address is local and matches incoming interface. */
	  if_addr0 =
	    ip4_interface_address_matching_destination (im4,
							&arp0->
							ip4_over_ethernet[1].
							ip4, sw_if_index0,
							&ifa0);
	  if (!if_addr0)
	    {
	      error0 = ETHERNET_ARP_ERROR_l3_dst_address_not_local;
	      goto drop1;
	    }

	  /* Honor unnumbered interface, if any */
	  is_unnum0 = sw_if_index0 != ifa0->sw_if_index;

	  /* Source must also be local to subnet of matching interface address. */
	  if (!ip4_destination_matches_interface
	      (im4, &arp0->ip4_over_ethernet[0].ip4, ifa0))
	    {
	      error0 = ETHERNET_ARP_ERROR_l3_src_address_not_local;
	      goto drop1;
	    }

	  /* Reject requests/replies with our local interface address. */
	  src_is_local0 =
	    if_addr0->as_u32 == arp0->ip4_over_ethernet[0].ip4.as_u32;
	  if (src_is_local0)
	    {
	      error0 = ETHERNET_ARP_ERROR_l3_src_address_is_local;
	      goto drop1;
	    }

	  dst_is_local0 =
	    if_addr0->as_u32 == arp0->ip4_over_ethernet[1].ip4.as_u32;

	  /* Fill in ethernet header. */
	  eth0 = ethernet_buffer_get_header (p0);

	  /* Trash ARP packets whose ARP-level source addresses do not
	     match their L2-frame-level source addresses */
	  if (memcmp (eth0->src_address, arp0->ip4_over_ethernet[0].ethernet,
		      sizeof (eth0->src_address)))
	    {
	      error0 = ETHERNET_ARP_ERROR_l2_address_mismatch;
	      goto drop2;
	    }

	  /* Learn or update sender's mapping only for requests or unicasts
	     that don't match local interface address. */
	  if (ethernet_address_cast (eth0->dst_address) ==
	      ETHERNET_ADDRESS_UNICAST || is_request0)
	    {
	      if (am->limit_arp_cache_size &&
		  pool_elts (am->ip4_entry_pool) >= am->limit_arp_cache_size)
		unset_random_arp_entry ();

	      vnet_arp_set_ip4_over_ethernet (vnm, sw_if_index0,
					      (u32) ~ 0 /* default fib */ ,
					      &arp0->ip4_over_ethernet[0],
					      0 /* is_static */ );
	      error0 = ETHERNET_ARP_ERROR_l3_src_address_learned;
	    }

	  /* Only send a reply for requests sent which match a local interface. */
	  if (!(is_request0 && dst_is_local0))
	    {
	      error0 =
		(arp0->opcode ==
		 clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply) ?
		 ETHERNET_ARP_ERROR_replies_received : error0);
	      goto drop1;
	    }

	  /* Send a reply. */
	send_reply:
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;
	  hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

	  /* Send reply back through input interface */
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;
	  next0 = ARP_INPUT_NEXT_REPLY_TX;

	  arp0->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);

	  arp0->ip4_over_ethernet[1] = arp0->ip4_over_ethernet[0];

	  clib_memcpy (arp0->ip4_over_ethernet[0].ethernet,
		       hw_if0->hw_address, 6);
	  clib_mem_unaligned (&arp0->ip4_over_ethernet[0].ip4.data_u32, u32) =
	    if_addr0->data_u32;

	  /* Hardware must be ethernet-like. */
	  ASSERT (vec_len (hw_if0->hw_address) == 6);

	  clib_memcpy (eth0->dst_address, eth0->src_address, 6);
	  clib_memcpy (eth0->src_address, hw_if0->hw_address, 6);

	  /* Figure out how much to rewind current data from adjacency. */
	  if (ifa0)
	    {
	      adj0 = ip_get_adjacency (&ip4_main.lookup_main,
				       ifa0->neighbor_probe_adj_index);
	      if (adj0->lookup_next_index != IP_LOOKUP_NEXT_ARP)
		{
		  error0 = ETHERNET_ARP_ERROR_missing_interface_address;
		  goto drop2;
		}
	      if (is_unnum0)
		arp_unnumbered (p0, pi0, eth0, ifa0);
	      else
		vlib_buffer_advance (p0, -adj0->rewrite_header.data_bytes);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);

	  n_replies_sent += 1;
	  continue;

	drop1:
	  if (0 == arp0->ip4_over_ethernet[0].ip4.as_u32 ||
	      (arp0->ip4_over_ethernet[0].ip4.as_u32 ==
	       arp0->ip4_over_ethernet[1].ip4.as_u32))
	    {
	      error0 = ETHERNET_ARP_ERROR_gratuitous_arp;
	      goto drop2;
	    }
	  /* See if proxy arp is configured for the address */
	  if (is_request0)
	    {
	      vnet_sw_interface_t *si;
	      u32 this_addr = clib_net_to_host_u32
		(arp0->ip4_over_ethernet[1].ip4.as_u32);
	      u32 fib_index0;

	      si = vnet_get_sw_interface (vnm, sw_if_index0);

	      if (!(si->flags & VNET_SW_INTERFACE_FLAG_PROXY_ARP))
		goto drop2;

	      fib_index0 = vec_elt (im4->fib_index_by_sw_if_index,
				    sw_if_index0);

	      vec_foreach (pa, am->proxy_arps)
	      {
		u32 lo_addr = clib_net_to_host_u32 (pa->lo_addr);
		u32 hi_addr = clib_net_to_host_u32 (pa->hi_addr);

		/* an ARP request hit in the proxy-arp table? */
		if ((this_addr >= lo_addr && this_addr <= hi_addr) &&
		    (fib_index0 == pa->fib_index))
		  {
		    eth0 = ethernet_buffer_get_header (p0);
		    proxy_src.as_u32 =
		      arp0->ip4_over_ethernet[1].ip4.data_u32;

		    /* 
		     * Rewind buffer, direct code above not to
		     * think too hard about it. 
		     * $$$ is the answer ever anything other than
		     * vlib_buffer_reset(..)?
		     */
		    ifa0 = 0;
		    if_addr0 = &proxy_src;
		    vlib_buffer_reset (p0);
		    n_proxy_arp_replies_sent++;
		    goto send_reply;
		  }
	      }
	    }

	drop2:

	  next0 = ARP_INPUT_NEXT_DROP;
	  p0->error = node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_error_count (vm, node->node_index,
		    ETHERNET_ARP_ERROR_replies_sent,
		    n_replies_sent - n_proxy_arp_replies_sent);

  vlib_error_count (vm, node->node_index,
		    ETHERNET_ARP_ERROR_proxy_arp_replies_sent,
		    n_proxy_arp_replies_sent);
  return frame->n_vectors;
}

static char *ethernet_arp_error_strings[] = {
#define _(sym,string) string,
  foreach_ethernet_arp_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (arp_input_node, static) =
{
  .function = arp_input,
  .name = "arp-input",
  .vector_size = sizeof (u32),
  .n_errors = ETHERNET_ARP_N_ERROR,
  .error_strings = ethernet_arp_error_strings,
  .n_next_nodes = ARP_INPUT_N_NEXT,
  .next_nodes = {
    [ARP_INPUT_NEXT_DROP] = "error-drop",
    [ARP_INPUT_NEXT_REPLY_TX] = "interface-output",
  },
  .format_buffer = format_ethernet_arp_header,
  .format_trace = format_ethernet_arp_input_trace,
};
/* *INDENT-ON* */

static int
ip4_arp_entry_sort (void *a1, void *a2)
{
  ethernet_arp_ip4_entry_t *e1 = a1;
  ethernet_arp_ip4_entry_t *e2 = a2;

  int cmp;
  vnet_main_t *vnm = vnet_get_main ();

  cmp = vnet_sw_interface_compare
    (vnm, e1->key.sw_if_index, e2->key.sw_if_index);
  if (!cmp)
    cmp = ip4_address_compare (&e1->key.ip4_address, &e2->key.ip4_address);
  return cmp;
}

static clib_error_t *
show_ip4_arp (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ethernet_arp_ip4_entry_t *e, *es;
  ethernet_proxy_arp_t *pa;
  clib_error_t *error = 0;
  u32 sw_if_index;

  /* Filter entries by interface if given. */
  sw_if_index = ~0;
  (void) unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index);

  es = 0;
  /* *INDENT-OFF* */
  pool_foreach (e, am->ip4_entry_pool,
  ({
    vec_add1 (es, e[0]);
  }));
  /* *INDENT-ON* */

  if (es)
    {
      vec_sort_with_function (es, ip4_arp_entry_sort);
      vlib_cli_output (vm, "%U", format_ethernet_arp_ip4_entry, vnm, 0);
      vec_foreach (e, es)
      {
	if (sw_if_index != ~0 && e->key.sw_if_index != sw_if_index)
	  continue;
	vlib_cli_output (vm, "%U", format_ethernet_arp_ip4_entry, vnm, e);
      }
      vec_free (es);
    }

  if (vec_len (am->proxy_arps))
    {
      vlib_cli_output (vm, "Proxy arps enabled for:");
      vec_foreach (pa, am->proxy_arps)
      {
	vlib_cli_output (vm, "Fib_index %d   %U - %U ",
			 pa->fib_index,
			 format_ip4_address, &pa->lo_addr,
			 format_ip4_address, &pa->hi_addr);
      }
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip4_arp_command, static) = {
  .path = "show ip arp",
  .function = show_ip4_arp,
  .short_help = "Show ARP table",
};
/* *INDENT-ON* */

typedef struct
{
  pg_edit_t l2_type, l3_type;
  pg_edit_t n_l2_address_bytes, n_l3_address_bytes;
  pg_edit_t opcode;
  struct
  {
    pg_edit_t ethernet;
    pg_edit_t ip4;
  } ip4_over_ethernet[2];
} pg_ethernet_arp_header_t;

static inline void
pg_ethernet_arp_header_init (pg_ethernet_arp_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, ethernet_arp_header_t, f);
  _(l2_type);
  _(l3_type);
  _(n_l2_address_bytes);
  _(n_l3_address_bytes);
  _(opcode);
  _(ip4_over_ethernet[0].ethernet);
  _(ip4_over_ethernet[0].ip4);
  _(ip4_over_ethernet[1].ethernet);
  _(ip4_over_ethernet[1].ip4);
#undef _
}

uword
unformat_pg_arp_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_ethernet_arp_header_t *p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (ethernet_arp_header_t),
			    &group_index);
  pg_ethernet_arp_header_init (p);

  /* Defaults. */
  pg_edit_set_fixed (&p->l2_type, ETHERNET_ARP_HARDWARE_TYPE_ethernet);
  pg_edit_set_fixed (&p->l3_type, ETHERNET_TYPE_IP4);
  pg_edit_set_fixed (&p->n_l2_address_bytes, 6);
  pg_edit_set_fixed (&p->n_l3_address_bytes, 4);

  if (!unformat (input, "%U: %U/%U -> %U/%U",
		 unformat_pg_edit,
		 unformat_ethernet_arp_opcode_net_byte_order, &p->opcode,
		 unformat_pg_edit,
		 unformat_ethernet_address, &p->ip4_over_ethernet[0].ethernet,
		 unformat_pg_edit,
		 unformat_ip4_address, &p->ip4_over_ethernet[0].ip4,
		 unformat_pg_edit,
		 unformat_ethernet_address, &p->ip4_over_ethernet[1].ethernet,
		 unformat_pg_edit,
		 unformat_ip4_address, &p->ip4_over_ethernet[1].ip4))
    {
      /* Free up any edits we may have added. */
      pg_free_edit_group (s);
      return 0;
    }
  return 1;
}

clib_error_t *
ip4_set_arp_limit (u32 arp_limit)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;

  am->limit_arp_cache_size = arp_limit;
  return 0;
}

static void
arp_ip4_entry_del_adj (ethernet_arp_ip4_entry_t * e, u32 adj_index)
{
  int done = 0;
  int i;

  while (!done)
    {
      vec_foreach_index (i, e->adjacencies)
	if (vec_elt (e->adjacencies, i) == adj_index)
	{
	  vec_del1 (e->adjacencies, i);
	  continue;
	}
      done = 1;
    }
}

static void
arp_ip4_entry_add_adj (ethernet_arp_ip4_entry_t * e, u32 adj_index)
{
  int i;
  vec_foreach_index (i, e->adjacencies)
    if (vec_elt (e->adjacencies, i) == adj_index)
    return;
  vec_add1 (e->adjacencies, adj_index);
}

static void
arp_add_del_adj_cb (struct ip_lookup_main_t *lm,
		    u32 adj_index, ip_adjacency_t * adj, u32 is_del)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ip4_main_t *im = &ip4_main;
  ethernet_arp_ip4_key_t k;
  ethernet_arp_ip4_entry_t *e = 0;
  uword *p;
  u32 ai;

  for (ai = adj->heap_handle; ai < adj->heap_handle + adj->n_adj; ai++)
    {
      adj = ip_get_adjacency (lm, ai);
      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP
	  && adj->arp.next_hop.ip4.as_u32)
	{
	  k.sw_if_index = adj->rewrite_header.sw_if_index;
	  k.ip4_address.as_u32 = adj->arp.next_hop.ip4.as_u32;
	  k.fib_index =
	    im->fib_index_by_sw_if_index[adj->rewrite_header.sw_if_index];
	  p = mhash_get (&am->ip4_entry_by_key, &k);
	  if (p)
	    e = pool_elt_at_index (am->ip4_entry_pool, p[0]);
	}
      else
	continue;

      if (is_del)
	{
	  if (!e)
	    clib_warning ("Adjacency contains unknown ARP next hop %U (del)",
			  format_ip46_address, &adj->arp.next_hop,
			  IP46_TYPE_IP4);
	  else
	    arp_ip4_entry_del_adj (e, adj->heap_handle);
	}
      else			/* add */
	{
	  if (!e)
	    clib_warning ("Adjacency contains unknown ARP next hop %U (add)",
			  format_ip46_address, &adj->arp.next_hop,
			  IP46_TYPE_IP4);
	  else
	    arp_ip4_entry_add_adj (e, adj->heap_handle);
	}
    }
}

static clib_error_t *
ethernet_arp_init (vlib_main_t * vm)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  pg_node_t *pn;
  clib_error_t *error;
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;

  if ((error = vlib_call_init_function (vm, ethernet_init)))
    return error;

  ethernet_register_input_type (vm, ETHERNET_TYPE_ARP, arp_input_node.index);

  pn = pg_get_node (arp_input_node.index);
  pn->unformat_edit = unformat_pg_arp_header;

  am->opcode_by_name = hash_create_string (0, sizeof (uword));
#define _(o) hash_set_mem (am->opcode_by_name, #o, ETHERNET_ARP_OPCODE_##o);
  foreach_ethernet_arp_opcode;
#undef _

  mhash_init (&am->ip4_entry_by_key,
	      /* value size */ sizeof (uword),
	      /* key size */ sizeof (ethernet_arp_ip4_key_t));

  /* $$$ configurable */
  am->limit_arp_cache_size = 50000;

  am->pending_resolutions_by_address = hash_create (0, sizeof (uword));
  am->mac_changes_by_address = hash_create (0, sizeof (uword));

  /* don't trace ARP error packets */
  {
    vlib_node_runtime_t *rt =
      vlib_node_get_runtime (vm, arp_input_node.index);

#define _(a,b)                                  \
    vnet_pcap_drop_trace_filter_add_del         \
        (rt->errors[ETHERNET_ARP_ERROR_##a],    \
         1 /* is_add */);
    foreach_ethernet_arp_error
#undef _
  }

  ip_register_add_del_adjacency_callback (lm, arp_add_del_adj_cb);

  return 0;
}

VLIB_INIT_FUNCTION (ethernet_arp_init);

int
vnet_arp_unset_ip4_over_ethernet (vnet_main_t * vnm,
				  u32 sw_if_index, u32 fib_index, void *a_arg)
{
  ethernet_arp_ip4_over_ethernet_address_t *a = a_arg;
  vnet_arp_set_ip4_over_ethernet_rpc_args_t args;

  args.sw_if_index = sw_if_index;
  args.fib_index = fib_index;
  args.is_remove = 1;
  clib_memcpy (&args.a, a, sizeof (*a));

  vl_api_rpc_call_main_thread (set_ip4_over_ethernet_rpc_callback,
			       (u8 *) & args, sizeof (args));
  return 0;
}

static inline int
vnet_arp_unset_ip4_over_ethernet_internal (vnet_main_t * vnm,
					   u32 sw_if_index,
					   u32 fib_index, void *a_arg)
{
  ethernet_arp_ip4_entry_t *e;
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ethernet_arp_ip4_over_ethernet_address_t *a = a_arg;
  ethernet_arp_ip4_key_t k;
  uword *p;
  ip4_add_del_route_args_t args;
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  u32 adj_index;
  ip_adjacency_t *adj;

  k.sw_if_index = sw_if_index;
  k.ip4_address = a->ip4;
  k.fib_index = fib_index;
  p = mhash_get (&am->ip4_entry_by_key, &k);
  if (!p)
    return -1;

  memset (&args, 0, sizeof (args));

  /* 
   * Make sure that the route actually exists before we try to delete it,
   * and make sure that it's a rewrite adjacency.
   *
   * If we point 1-N unnumbered interfaces at a loopback interface and 
   * shut down the loopback before shutting down 1-N unnumbered 
   * interfaces, the ARP cache will still have an entry, 
   * but the route will have disappeared.
   * 
   * See also ip4_del_interface_routes (...) 
   *            -> ip4_delete_matching_routes (...).
   */

  adj_index = ip4_fib_lookup_with_table
    (im, fib_index, &a->ip4, 1 /* disable default route */ );

  /* Miss adj? Forget it... */
  if (adj_index != lm->miss_adj_index)
    {
      adj = ip_get_adjacency (lm, adj_index);
      /* 
       * Stupid control-plane trick:
       * admin down an interface (removes arp routes from fib),
       * bring the interface back up (does not reinstall them)
       * then remove the arp cache entry (yuck). When that happens,
       * the adj we find here will be the interface subnet ARP adj.
       */
      if (adj->lookup_next_index == IP_LOOKUP_NEXT_REWRITE)
	{
	  args.table_index_or_table_id = fib_index;
	  args.flags = IP4_ROUTE_FLAG_FIB_INDEX | IP4_ROUTE_FLAG_DEL
	    | IP4_ROUTE_FLAG_NEIGHBOR;
	  args.dst_address = a->ip4;
	  args.dst_address_length = 32;
	  ip4_add_del_route (im, &args);
	  ip4_maybe_remap_adjacencies (im, fib_index, args.flags);
	}
    }

  e = pool_elt_at_index (am->ip4_entry_pool, p[0]);
  mhash_unset (&am->ip4_entry_by_key, &e->key, 0);
  pool_put (am->ip4_entry_pool, e);
  return 0;
}

static void
increment_ip4_and_mac_address (ethernet_arp_ip4_over_ethernet_address_t * a)
{
  u8 old;
  int i;

  for (i = 3; i >= 0; i--)
    {
      old = a->ip4.as_u8[i];
      a->ip4.as_u8[i] += 1;
      if (old < a->ip4.as_u8[i])
	break;
    }

  for (i = 5; i >= 0; i--)
    {
      old = a->ethernet[i];
      a->ethernet[i] += 1;
      if (old < a->ethernet[i])
	break;
    }
}

int
vnet_proxy_arp_add_del (ip4_address_t * lo_addr,
			ip4_address_t * hi_addr, u32 fib_index, int is_del)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ethernet_proxy_arp_t *pa;
  u32 found_at_index = ~0;

  vec_foreach (pa, am->proxy_arps)
  {
    if (pa->lo_addr == lo_addr->as_u32
	&& pa->hi_addr == hi_addr->as_u32 && pa->fib_index == fib_index)
      {
	found_at_index = pa - am->proxy_arps;
	break;
      }
  }

  if (found_at_index != ~0)
    {
      /* Delete, otherwise it's already in the table */
      if (is_del)
	vec_delete (am->proxy_arps, 1, found_at_index);
      return 0;
    }
  /* delete, no such entry */
  if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* add, not in table */
  vec_add2 (am->proxy_arps, pa, 1);
  pa->lo_addr = lo_addr->as_u32;
  pa->hi_addr = hi_addr->as_u32;
  pa->fib_index = fib_index;
  return 0;
}

/*
 * Remove any proxy arp entries asdociated with the 
 * specificed fib.
 */
int
vnet_proxy_arp_fib_reset (u32 fib_id)
{
  ip4_main_t *im = &ip4_main;
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ethernet_proxy_arp_t *pa;
  u32 *entries_to_delete = 0;
  u32 fib_index;
  uword *p;
  int i;

  p = hash_get (im->fib_index_by_table_id, fib_id);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  fib_index = p[0];

  vec_foreach (pa, am->proxy_arps)
  {
    if (pa->fib_index == fib_index)
      {
	vec_add1 (entries_to_delete, pa - am->proxy_arps);
      }
  }

  for (i = 0; i < vec_len (entries_to_delete); i++)
    {
      vec_delete (am->proxy_arps, 1, entries_to_delete[i]);
    }

  vec_free (entries_to_delete);

  return 0;
}

u32
vnet_arp_glean_add (u32 fib_index, void *next_hop_arg)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  ip4_address_t *next_hop = next_hop_arg;
  ip_adjacency_t add_adj, *adj;
  ip4_add_del_route_args_t args;
  ethernet_arp_ip4_entry_t *e;
  ethernet_arp_ip4_key_t k;
  u32 adj_index;

  adj_index = ip4_fib_lookup_with_table (im, fib_index, next_hop, 0);
  adj = ip_get_adjacency (lm, adj_index);

  if (!adj || adj->lookup_next_index != IP_LOOKUP_NEXT_ARP)
    return ~0;

  if (adj->arp.next_hop.ip4.as_u32 != 0)
    return adj_index;

  k.sw_if_index = adj->rewrite_header.sw_if_index;
  k.fib_index = fib_index;
  k.ip4_address.as_u32 = next_hop->as_u32;

  if (mhash_get (&am->ip4_entry_by_key, &k))
    return adj_index;

  pool_get (am->ip4_entry_pool, e);
  mhash_set (&am->ip4_entry_by_key, &k, e - am->ip4_entry_pool,
	     /* old value */ 0);
  e->key = k;
  e->cpu_time_last_updated = clib_cpu_time_now ();
  e->flags = ETHERNET_ARP_IP4_ENTRY_FLAG_GLEAN;

  memset (&args, 0, sizeof (args));
  clib_memcpy (&add_adj, adj, sizeof (add_adj));
  ip46_address_set_ip4 (&add_adj.arp.next_hop, next_hop);	/* install neighbor /32 route */
  args.table_index_or_table_id = fib_index;
  args.flags =
    IP4_ROUTE_FLAG_FIB_INDEX | IP4_ROUTE_FLAG_ADD | IP4_ROUTE_FLAG_NEIGHBOR;
  args.dst_address.as_u32 = next_hop->as_u32;
  args.dst_address_length = 32;
  args.adj_index = ~0;
  args.add_adj = &add_adj;
  args.n_add_adj = 1;
  ip4_add_del_route (im, &args);
  return ip4_fib_lookup_with_table (im, fib_index, next_hop, 0);
}

static clib_error_t *
ip_arp_add_del_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;
  ethernet_arp_ip4_over_ethernet_address_t lo_addr, hi_addr, addr;
  int addr_valid = 0;
  int is_del = 0;
  int count = 1;
  u32 fib_index = 0;
  u32 fib_id;
  int is_static = 0;
  int is_proxy = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* set ip arp TenGigE1/1/0/1 1.2.3.4 aa:bb:... or aabb.ccdd... */
      if (unformat (input, "%U %U %U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index,
		    unformat_ip4_address, &addr.ip4,
		    unformat_ethernet_address, &addr.ethernet))
	addr_valid = 1;

      else if (unformat (input, "delete") || unformat (input, "del"))
	is_del = 1;

      else if (unformat (input, "static"))
	is_static = 1;

      else if (unformat (input, "count %d", &count))
	;

      else if (unformat (input, "fib-id %d", &fib_id))
	{
	  ip4_main_t *im = &ip4_main;
	  uword *p = hash_get (im->fib_index_by_table_id, fib_id);
	  if (!p)
	    return clib_error_return (0, "fib ID %d doesn't exist\n", fib_id);
	  fib_index = p[0];
	}

      else if (unformat (input, "proxy %U - %U",
			 unformat_ip4_address, &lo_addr.ip4,
			 unformat_ip4_address, &hi_addr.ip4))
	is_proxy = 1;
      else
	break;
    }

  if (is_proxy)
    {
      (void) vnet_proxy_arp_add_del (&lo_addr.ip4, &hi_addr.ip4,
				     fib_index, is_del);
      return 0;
    }

  if (addr_valid)
    {
      int i;

      for (i = 0; i < count; i++)
	{
	  if (is_del == 0)
	    {
	      uword event_type, *event_data = 0;

	      /* Park the debug CLI until the arp entry is installed */
	      vnet_register_ip4_arp_resolution_event
		(vnm, &addr.ip4, vlib_current_process (vm),
		 1 /* type */ , 0 /* data */ );

	      vnet_arp_set_ip4_over_ethernet
		(vnm, sw_if_index, fib_index, &addr, is_static);

	      vlib_process_wait_for_event (vm);
	      event_type = vlib_process_get_events (vm, &event_data);
	      vec_reset_length (event_data);
	      if (event_type != 1)
		clib_warning ("event type %d unexpected", event_type);
	    }
	  else
	    vnet_arp_unset_ip4_over_ethernet
	      (vnm, sw_if_index, fib_index, &addr);

	  increment_ip4_and_mac_address (&addr);
	}
    }
  else
    {
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_arp_add_del_command, static) = {
  .path = "set ip arp",
  .short_help =
    "set ip arp [del] <intfc> <ip-address> <mac-address> [static] [count <count>] [fib-id <fib-id>] [proxy <lo-addr> - <hi-addr>]",
  .function = ip_arp_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_int_proxy_arp_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;
  vnet_sw_interface_t *si;
  int enable = 0;
  int intfc_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	intfc_set = 1;
      else if (unformat (input, "enable") || unformat (input, "on"))
	enable = 1;
      else if (unformat (input, "disable") || unformat (input, "off"))
	enable = 0;
      else
	break;
    }

  if (intfc_set == 0)
    return clib_error_return (0, "unknown input '%U'",
			      format_unformat_error, input);

  si = vnet_get_sw_interface (vnm, sw_if_index);
  ASSERT (si);
  if (enable)
    si->flags |= VNET_SW_INTERFACE_FLAG_PROXY_ARP;
  else
    si->flags &= ~VNET_SW_INTERFACE_FLAG_PROXY_ARP;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_int_proxy_enable_command, static) = {
  .path = "set interface proxy-arp",
  .short_help =
    "set interface proxy-arp <intfc> [enable|disable]",
  .function = set_int_proxy_arp_command_fn,
};
/* *INDENT-ON* */


/*
 * ARP Termination in a L2 Bridge Domain based on an
 * IP4 to MAC hash table mac_by_ip4 for each BD.
 */
typedef enum
{
  ARP_TERM_NEXT_L2_OUTPUT,
  ARP_TERM_NEXT_DROP,
  ARP_TERM_N_NEXT,
} arp_term_next_t;

u32 arp_term_next_node_index[32];

static uword
arp_term_l2bd (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  l2input_main_t *l2im = &l2input_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 n_replies_sent = 0;
  u16 last_bd_index = ~0;
  l2_bridge_domain_t *last_bd_config = 0;
  l2_input_config_t *cfg0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ethernet_header_t *eth0;
	  ethernet_arp_header_t *arp0;
	  u8 *l3h0;
	  u32 pi0, error0, next0, sw_if_index0;
	  u16 ethertype0;
	  u16 bd_index0;
	  u32 ip0;
	  u8 *macp0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  eth0 = vlib_buffer_get_current (p0);
	  l3h0 = (u8 *) eth0 + vnet_buffer (p0)->l2.l2_len;
	  ethertype0 = clib_net_to_host_u16 (*(u16 *) (l3h0 - 2));
	  arp0 = (ethernet_arp_header_t *) l3h0;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (p0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      u8 *t0 = vlib_add_trace (vm, node, p0,
				       sizeof (ethernet_arp_input_trace_t));
	      clib_memcpy (t0, l3h0, sizeof (ethernet_arp_input_trace_t));
	    }

	  if (PREDICT_FALSE ((ethertype0 != ETHERNET_TYPE_ARP) ||
			     (arp0->opcode !=
			      clib_host_to_net_u16
			      (ETHERNET_ARP_OPCODE_request))))
	    goto next_l2_feature;

	  error0 = ETHERNET_ARP_ERROR_replies_sent;
	  error0 =
	    (arp0->l2_type !=
	     clib_net_to_host_u16 (ETHERNET_ARP_HARDWARE_TYPE_ethernet) ?
	     ETHERNET_ARP_ERROR_l2_type_not_ethernet : error0);
	  error0 =
	    (arp0->l3_type !=
	     clib_net_to_host_u16 (ETHERNET_TYPE_IP4) ?
	     ETHERNET_ARP_ERROR_l3_type_not_ip4 : error0);

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  if (error0)
	    goto drop;

	  // Trash ARP packets whose ARP-level source addresses do not
	  // match their L2-frame-level source addresses */
	  if (PREDICT_FALSE
	      (memcmp
	       (eth0->src_address, arp0->ip4_over_ethernet[0].ethernet,
		sizeof (eth0->src_address))))
	    {
	      error0 = ETHERNET_ARP_ERROR_l2_address_mismatch;
	      goto drop;
	    }

	  // Check if anyone want ARP request events for L2 BDs
	  {
	    pending_resolution_t *mc;
	    ethernet_arp_main_t *am = &ethernet_arp_main;
	    uword *p = hash_get (am->mac_changes_by_address, 0);
	    if (p && (vnet_buffer (p0)->l2.shg == 0))
	      {			// Only SHG 0 interface which is more likely local
		u32 next_index = p[0];
		while (next_index != (u32) ~ 0)
		  {
		    int (*fp) (u32, u8 *, u32, u32);
		    int rv = 1;
		    mc = pool_elt_at_index (am->mac_changes, next_index);
		    fp = mc->data_callback;
		    // Call the callback, return 1 to suppress dup events */
		    if (fp)
		      rv = (*fp) (mc->data,
				  arp0->ip4_over_ethernet[0].ethernet,
				  sw_if_index0,
				  arp0->ip4_over_ethernet[0].ip4.as_u32);
		    // Signal the resolver process
		    if (rv == 0)
		      vlib_process_signal_event (vm, mc->node_index,
						 mc->type_opaque, mc->data);
		    next_index = mc->next_index;
		  }
	      }
	  }

	  // lookup BD mac_by_ip4 hash table for MAC entry
	  ip0 = arp0->ip4_over_ethernet[1].ip4.as_u32;
	  bd_index0 = vnet_buffer (p0)->l2.bd_index;
	  if (PREDICT_FALSE ((bd_index0 != last_bd_index)
			     || (last_bd_index == (u16) ~ 0)))
	    {
	      last_bd_index = bd_index0;
	      last_bd_config = vec_elt_at_index (l2im->bd_configs, bd_index0);
	    }
	  macp0 = (u8 *) hash_get (last_bd_config->mac_by_ip4, ip0);

	  if (PREDICT_FALSE (!macp0))
	    goto next_l2_feature;	// MAC not found 

	  // MAC found, send ARP reply -
	  // Convert ARP request packet to ARP reply
	  arp0->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);
	  arp0->ip4_over_ethernet[1] = arp0->ip4_over_ethernet[0];
	  arp0->ip4_over_ethernet[0].ip4.as_u32 = ip0;
	  clib_memcpy (arp0->ip4_over_ethernet[0].ethernet, macp0, 6);
	  clib_memcpy (eth0->dst_address, eth0->src_address, 6);
	  clib_memcpy (eth0->src_address, macp0, 6);
	  n_replies_sent += 1;

	  // For BVI, need to use l2-fwd node to send ARP reply as 
	  // l2-output node cannot output packet to BVI properly
	  cfg0 = vec_elt_at_index (l2im->configs, sw_if_index0);
	  if (PREDICT_FALSE (cfg0->bvi))
	    {
	      vnet_buffer (p0)->l2.feature_bitmap |= L2INPUT_FEAT_FWD;
	      vnet_buffer (p0)->sw_if_index[VLIB_RX] = 0;
	      goto next_l2_feature;
	    }

	  // Send ARP reply back out input interface through l2-output
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;
	  next0 = ARP_TERM_NEXT_L2_OUTPUT;
	  // Note that output to VXLAN tunnel will fail due to SHG which
	  // is probably desireable since ARP termination is not intended
	  // for ARP requests from other hosts. If output to VXLAN tunnel is
	  // required, however, can just clear the SHG in packet as follows:
	  //   vnet_buffer(p0)->l2.shg = 0;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	  continue;

	next_l2_feature:
	  {
	    u32 feature_bitmap0 =
	      vnet_buffer (p0)->l2.feature_bitmap & ~L2INPUT_FEAT_ARP_TERM;
	    vnet_buffer (p0)->l2.feature_bitmap = feature_bitmap0;
	    next0 = feat_bitmap_get_next_node_index (arp_term_next_node_index,
						     feature_bitmap0);
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					     n_left_to_next, pi0, next0);
	    continue;
	  }

	drop:
	  if (0 == arp0->ip4_over_ethernet[0].ip4.as_u32 ||
	      (arp0->ip4_over_ethernet[0].ip4.as_u32 ==
	       arp0->ip4_over_ethernet[1].ip4.as_u32))
	    {
	      error0 = ETHERNET_ARP_ERROR_gratuitous_arp;
	    }
	  next0 = ARP_TERM_NEXT_DROP;
	  p0->error = node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_error_count (vm, node->node_index,
		    ETHERNET_ARP_ERROR_replies_sent, n_replies_sent);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (arp_term_l2bd_node, static) = {
  .function = arp_term_l2bd,
  .name = "arp-term-l2bd",
  .vector_size = sizeof (u32),
  .n_errors = ETHERNET_ARP_N_ERROR,
  .error_strings = ethernet_arp_error_strings,
  .n_next_nodes = ARP_TERM_N_NEXT,
  .next_nodes = {
    [ARP_TERM_NEXT_L2_OUTPUT] = "l2-output",
    [ARP_TERM_NEXT_DROP] = "error-drop",
  },
  .format_buffer = format_ethernet_arp_header,
  .format_trace = format_ethernet_arp_input_trace,
};
/* *INDENT-ON* */

clib_error_t *
arp_term_init (vlib_main_t * vm)
{				// Initialize the feature next-node indexes 
  feat_bitmap_init_next_nodes (vm,
			       arp_term_l2bd_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       arp_term_next_node_index);
  return 0;
}

VLIB_INIT_FUNCTION (arp_term_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
