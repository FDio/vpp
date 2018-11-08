/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include "stats_to_be_deprecated.h"
#include <signal.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/udp/udp_encap.h>
#include <vnet/bier/bier_fmask.h>
#include <vnet/bier/bier_table.h>
#include <vnet/fib/fib_api.h>

#define STATS_DEBUG 0

stats_main_t stats_main;

#include <vnet/ip/ip.h>

#include <vpp/api/vpe_msg_enum.h>

#define f64_endian(a)
#define f64_print(a,b)

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

#define foreach_stats_msg						\
_(WANT_STATS, want_stats)						\
_(VNET_INTERFACE_SIMPLE_COUNTERS, vnet_interface_simple_counters)	\
_(WANT_INTERFACE_SIMPLE_STATS, want_interface_simple_stats)             \
_(VNET_INTERFACE_COMBINED_COUNTERS, vnet_interface_combined_counters)	\
_(WANT_INTERFACE_COMBINED_STATS, want_interface_combined_stats)         \
_(WANT_PER_INTERFACE_COMBINED_STATS, want_per_interface_combined_stats)	\
_(WANT_PER_INTERFACE_SIMPLE_STATS, want_per_interface_simple_stats)     \
_(VNET_IP4_FIB_COUNTERS, vnet_ip4_fib_counters)				\
_(WANT_IP4_FIB_STATS, want_ip4_fib_stats)                               \
_(VNET_IP6_FIB_COUNTERS, vnet_ip6_fib_counters)				\
_(WANT_IP6_FIB_STATS, want_ip6_fib_stats)                               \
_(WANT_IP4_MFIB_STATS, want_ip4_mfib_stats)                             \
_(WANT_IP6_MFIB_STATS, want_ip6_mfib_stats)                             \
_(VNET_IP4_NBR_COUNTERS, vnet_ip4_nbr_counters)				\
_(WANT_IP4_NBR_STATS, want_ip4_nbr_stats)                               \
_(VNET_IP6_NBR_COUNTERS, vnet_ip6_nbr_counters)                         \
_(WANT_IP6_NBR_STATS, want_ip6_nbr_stats)                               \
_(VNET_GET_SUMMARY_STATS, vnet_get_summary_stats)                       \
_(STATS_GET_POLLER_DELAY, stats_get_poller_delay)                       \
_(WANT_UDP_ENCAP_STATS, want_udp_encap_stats)                           \
_(WANT_BIER_NEIGHBOR_STATS, want_bier_neighbor_stats)

#define vl_msg_name_crc_list
#include <vpp/stats/stats.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_stats;
#undef _
}

/* These constants ensure msg sizes <= 1024, aka ring allocation */
#define SIMPLE_COUNTER_BATCH_SIZE	126
#define COMBINED_COUNTER_BATCH_SIZE	63
#define IP4_FIB_COUNTER_BATCH_SIZE	48
#define IP6_FIB_COUNTER_BATCH_SIZE	30
#define IP4_MFIB_COUNTER_BATCH_SIZE	24
#define IP6_MFIB_COUNTER_BATCH_SIZE	15
#define UDP_ENCAP_COUNTER_BATCH_SIZE	(1024 / sizeof(vl_api_udp_encap_counter_t))
#define BIER_NEIGHBOR_COUNTER_BATCH_SIZE (1024 / sizeof(vl_api_bier_neighbor_counter_t))

/* 5ms */
#define STATS_RELEASE_DELAY_NS (1000 * 1000 * 5)
/*                              ns/us  us/ms        */

u8 *
format_vnet_interface_combined_counters (u8 * s, va_list * args)
{
  stats_main_t *sm = &stats_main;
  vl_api_vnet_interface_combined_counters_t *mp =
    va_arg (*args, vl_api_vnet_interface_combined_counters_t *);

  char *counter_name;
  u32 count, sw_if_index;
  int i;
  count = ntohl (mp->count);
  sw_if_index = ntohl (mp->first_sw_if_index);

  vlib_counter_t *vp;
  u64 packets, bytes;
  vp = (vlib_counter_t *) mp->data;

  switch (mp->vnet_counter_type)
    {
    case VNET_INTERFACE_COUNTER_RX:
      counter_name = "rx";
      break;
    case VNET_INTERFACE_COUNTER_TX:
      counter_name = "tx";
      break;
    default:
      counter_name = "bogus";
      break;
    }
  for (i = 0; i < count; i++)
    {
      packets = clib_mem_unaligned (&vp->packets, u64);
      packets = clib_net_to_host_u64 (packets);
      bytes = clib_mem_unaligned (&vp->bytes, u64);
      bytes = clib_net_to_host_u64 (bytes);
      vp++;
      s = format (s, "%U.%s.packets %lld\n",
		  format_vnet_sw_if_index_name,
		  sm->vnet_main, sw_if_index, counter_name, packets);
      s = format (s, "%U.%s.bytes %lld\n",
		  format_vnet_sw_if_index_name,
		  sm->vnet_main, sw_if_index, counter_name, bytes);
      sw_if_index++;
    }
  return s;
}

u8 *
format_vnet_interface_simple_counters (u8 * s, va_list * args)
{
  stats_main_t *sm = &stats_main;
  vl_api_vnet_interface_simple_counters_t *mp =
    va_arg (*args, vl_api_vnet_interface_simple_counters_t *);
  char *counter_name;
  u32 count, sw_if_index;
  count = ntohl (mp->count);
  sw_if_index = ntohl (mp->first_sw_if_index);
  u64 *vp, v;
  vp = (u64 *) mp->data;
  int i;

  switch (mp->vnet_counter_type)
    {
    case VNET_INTERFACE_COUNTER_DROP:
      counter_name = "drop";
      break;
    case VNET_INTERFACE_COUNTER_PUNT:
      counter_name = "punt";
      break;
    case VNET_INTERFACE_COUNTER_IP4:
      counter_name = "ip4";
      break;
    case VNET_INTERFACE_COUNTER_IP6:
      counter_name = "ip6";
      break;
    case VNET_INTERFACE_COUNTER_RX_NO_BUF:
      counter_name = "rx-no-buff";
      break;
    case VNET_INTERFACE_COUNTER_RX_MISS:
      counter_name = "rx-miss";
      break;
    case VNET_INTERFACE_COUNTER_RX_ERROR:
      counter_name = "rx-error (fifo-full)";
      break;
    case VNET_INTERFACE_COUNTER_TX_ERROR:
      counter_name = "tx-error (fifo-full)";
      break;
    default:
      counter_name = "bogus";
      break;
    }
  for (i = 0; i < count; i++)
    {
      v = clib_mem_unaligned (vp, u64);
      v = clib_net_to_host_u64 (v);
      vp++;
      s = format (s, "%U.%s %lld\n", format_vnet_sw_if_index_name,
		  sm->vnet_main, sw_if_index, counter_name, v);
      sw_if_index++;
    }

  return s;
}

static void
dslock (stats_main_t * sm, int release_hint, int tag)
{
  u32 thread_index;
  data_structure_lock_t *l = sm->data_structure_lock;

  if (PREDICT_FALSE (l == 0))
    return;

  thread_index = vlib_get_thread_index ();
  if (l->lock && l->thread_index == thread_index)
    {
      l->count++;
      return;
    }

  if (release_hint)
    l->release_hint++;

  while (clib_atomic_test_and_set (&l->lock))
    /* zzzz */ ;
  l->tag = tag;
  l->thread_index = thread_index;
  l->count = 1;
}

void
stats_dslock_with_hint (int hint, int tag)
{
  stats_main_t *sm = &stats_main;
  dslock (sm, hint, tag);
}

static void
dsunlock (stats_main_t * sm)
{
  u32 thread_index;
  data_structure_lock_t *l = sm->data_structure_lock;

  if (PREDICT_FALSE (l == 0))
    return;

  thread_index = vlib_get_thread_index ();
  ASSERT (l->lock && l->thread_index == thread_index);
  l->count--;
  if (l->count == 0)
    {
      l->tag = -l->tag;
      l->release_hint = 0;
      CLIB_MEMORY_BARRIER ();
      l->lock = 0;
    }
}

void
stats_dsunlock (int hint, int tag)
{
  stats_main_t *sm = &stats_main;
  dsunlock (sm);
}

static vpe_client_registration_t *
get_client_for_stat (u32 reg, u32 item, u32 client_index)
{
  stats_main_t *sm = &stats_main;
  vpe_client_stats_registration_t *registration;
  uword *p;

  /* Is there anything listening for item in that reg */
  p = hash_get (sm->stats_registration_hash[reg], item);

  if (!p)
    return 0;			// Fail

  /* If there is, is our client_index one of them */
  registration = pool_elt_at_index (sm->stats_registrations[reg], p[0]);
  p = hash_get (registration->client_hash, client_index);

  if (!p)
    return 0;			// Fail

  return pool_elt_at_index (registration->clients, p[0]);

}

static int
set_client_for_stat (u32 reg, u32 item, vpe_client_registration_t * client)
{
  stats_main_t *sm = &stats_main;
  vpe_client_stats_registration_t *registration;
  vpe_client_registration_t *cr;
  uword *p;

  /* Is there anything listening for item in that reg */
  p = hash_get (sm->stats_registration_hash[reg], item);

  if (!p)
    {
      pool_get (sm->stats_registrations[reg], registration);
      registration->item = item;
      registration->client_hash = NULL;
      registration->clients = NULL;
      hash_set (sm->stats_registration_hash[reg], item,
		registration - sm->stats_registrations[reg]);
    }
  else
    {
      registration = pool_elt_at_index (sm->stats_registrations[reg], p[0]);
    }

  p = hash_get (registration->client_hash, client->client_index);

  if (!p)
    {
      pool_get (registration->clients, cr);
      cr->client_index = client->client_index;
      cr->client_pid = client->client_pid;
      hash_set (registration->client_hash, cr->client_index,
		cr - registration->clients);
    }

  return 1;			//At least one client is doing something ... poll
}

static void
clear_one_client (u32 reg_index, u32 reg, u32 item, u32 client_index)
{
  stats_main_t *sm = &stats_main;
  vpe_client_stats_registration_t *registration;
  vpe_client_registration_t *client;
  uword *p;

  registration = pool_elt_at_index (sm->stats_registrations[reg], reg_index);
  p = hash_get (registration->client_hash, client_index);

  if (p)
    {
      client = pool_elt_at_index (registration->clients, p[0]);
      hash_unset (registration->client_hash, client->client_index);
      pool_put (registration->clients, client);

      /* Now check if that was the last client for that item */
      if (0 == pool_elts (registration->clients))
	{
	  hash_unset (sm->stats_registration_hash[reg], item);
	  hash_free (registration->client_hash);
	  pool_free (registration->clients);
	  pool_put (sm->stats_registrations[reg], registration);
	}
    }
}

int
clear_client_for_stat (u32 reg, u32 item, u32 client_index)
{
  stats_main_t *sm = &stats_main;
  uword *p;
  int i, elts;

  /* Clear the client first */
  /* Is there anything listening for item in that reg */
  p = hash_get (sm->stats_registration_hash[reg], item);

  if (!p)
    goto exit;

  /* If there is, is our client_index one of them */
  clear_one_client (p[0], reg, item, client_index);

exit:
  elts = 0;
  /* Now check if that was the last item in any of the listened to stats */
  for (i = 0; i < STATS_REG_N_IDX; i++)
    {
      elts += pool_elts (sm->stats_registrations[i]);
    }
  return elts;
}

static int
clear_client_for_all_stats (u32 client_index)
{
  stats_main_t *sm = &stats_main;
  u32 reg_index, item, reg;
  int i, elts;

  /* *INDENT-OFF* */
  vec_foreach_index(reg, sm->stats_registration_hash)
    {
      hash_foreach(item, reg_index, sm->stats_registration_hash[reg],
      ({
        clear_one_client(reg_index, reg, item, client_index);
      }));
    }
  /* *INDENT-OFF* */

  elts = 0;
  /* Now check if that was the last item in any of the listened to stats */
  for (i = 0; i < STATS_REG_N_IDX; i++)
    {
      elts += pool_elts (sm->stats_registrations[i]);
    }
  return elts;
}

static clib_error_t *
want_stats_reaper (u32 client_index)
{
  stats_main_t *sm = &stats_main;

  sm->enable_poller = clear_client_for_all_stats (client_index);

  return (NULL);
}

VL_MSG_API_REAPER_FUNCTION (want_stats_reaper);


/*
 * Return a copy of the clients list.
 */
vpe_client_registration_t *
get_clients_for_stat (u32 reg, u32 item)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t *client, *clients = 0;
  vpe_client_stats_registration_t *registration;
  uword *p;

  /* Is there anything listening for item in that reg */
  p = hash_get (sm->stats_registration_hash[reg], item);

  if (!p)
    return 0;			// Fail

  /* If there is, is our client_index one of them */
  registration = pool_elt_at_index (sm->stats_registrations[reg], p[0]);

  vec_reset_length (clients);

  /* *INDENT-OFF* */
  pool_foreach (client, registration->clients,
  ({
    vec_add1 (clients, *client);}
  ));
  /* *INDENT-ON* */
  return clients;
}


static void
clear_client_reg (u32 ** registrations)
{
  /* When registrations[x] is a vector of pool indices
     here is a good place to clean up the pools
   */
#define stats_reg(n) vec_free(registrations[IDX_##n]);
#include <vpp/stats/stats.reg>
#undef stats_reg

  vec_free (registrations);
}

u32 **
init_client_reg (u32 ** registrations)
{

  /*
     Initialise the stats registrations for each
     type of stat a client can register for as well as
     a vector of "interested" indexes.
     Initially this is a u32 of either sw_if_index or fib_index
     but eventually this should migrate to a pool_index (u32)
     with a type specific pool that can include more complex things
     such as timing and structured events.
   */
  vec_validate (registrations, STATS_REG_N_IDX);
#define stats_reg(n) \
  vec_reset_length(registrations[IDX_##n]);
#include <vpp/stats/stats.reg>
#undef stats_reg

  /*
     When registrations[x] is a vector of pool indices, here
     is a good place to init the pools.
   */
  return registrations;
}

u32 **
enable_all_client_reg (u32 ** registrations)
{

  /*
     Enable all stats known by adding
     ~0 to the index vector. Eventually this
     should be deprecated.
   */
#define stats_reg(n)                            \
  vec_add1(registrations[IDX_##n], ~0);
#include <vpp/stats/stats.reg>
#undef stats_reg
  return registrations;
}

static void
do_simple_interface_counters (stats_main_t * sm)
{
  vl_api_vnet_interface_simple_counters_t *mp = 0;
  vnet_interface_main_t *im = sm->interface_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q = shmem_hdr->vl_input_queue;
  vlib_simple_counter_main_t *cm;
  u32 items_this_message = 0;
  u64 v, *vp = 0;
  int i, n_counts;

  /*
   * Prevent interface registration from expanding / moving the vectors...
   * That tends never to happen, so we can hold this lock for a while.
   */
  vnet_interface_counter_lock (im);

  vec_foreach (cm, im->sw_if_counters)
  {
    n_counts = vlib_simple_counter_n_counters (cm);
    for (i = 0; i < n_counts; i++)
      {
	if (mp == 0)
	  {
	    items_this_message = clib_min (SIMPLE_COUNTER_BATCH_SIZE,
					   n_counts - i);

	    mp = vl_msg_api_alloc_as_if_client
	      (sizeof (*mp) + items_this_message * sizeof (v));
	    mp->_vl_msg_id = ntohs (VL_API_VNET_INTERFACE_SIMPLE_COUNTERS);
	    mp->vnet_counter_type = cm - im->sw_if_counters;
	    mp->first_sw_if_index = htonl (i);
	    mp->count = 0;
	    vp = (u64 *) mp->data;
	  }
	v = vlib_get_simple_counter (cm, i);
	clib_mem_unaligned (vp, u64) = clib_host_to_net_u64 (v);
	vp++;
	mp->count++;
	if (mp->count == items_this_message)
	  {
	    mp->count = htonl (items_this_message);
	    /* Send to the main thread... */
	    vl_msg_api_send_shmem (q, (u8 *) & mp);
	    mp = 0;
	  }
      }
    ASSERT (mp == 0);
  }
  vnet_interface_counter_unlock (im);
}

void
handle_client_registration (vpe_client_registration_t * client, u32 stat,
			    u32 item, int enable_disable)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t *rp, _rp;

  rp = get_client_for_stat (stat, item, client->client_index);

  /* Disable case */
  if (enable_disable == 0)
    {
      if (!rp)			// No client to disable
	{
	  clib_warning ("pid %d: already disabled for stats...",
			client->client_pid);
	  return;
	}
      sm->enable_poller =
	clear_client_for_stat (stat, item, client->client_index);
      return;
    }
  /* Enable case */
  if (!rp)
    {
      rp = &_rp;
      rp->client_index = client->client_index;
      rp->client_pid = client->client_pid;
      sm->enable_poller = set_client_for_stat (stat, item, rp);
    }
}


/**********************************
 * ALL Interface Combined stats - to be deprecated
 **********************************/

/*
 * This API should be deprecated as _per_interface_ works with ~0 as sw_if_index.
 */
static void
  vl_api_want_interface_combined_stats_t_handler
  (vl_api_want_interface_combined_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_interface_combined_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  vl_api_registration_t *reg;
  u32 swif;

  swif = ~0;			//Using same mechanism as _per_interface_
  rp.client_index = mp->client_index;
  rp.client_pid = mp->pid;

  handle_client_registration (&rp, IDX_PER_INTERFACE_COMBINED_COUNTERS, swif,
			      mp->enable_disable);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      sm->enable_poller =
	clear_client_for_stat (IDX_PER_INTERFACE_COMBINED_COUNTERS, swif,
			       mp->client_index);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_INTERFACE_COMBINED_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_vnet_interface_combined_counters_t_handler
  (vl_api_vnet_interface_combined_counters_t * mp)
{
  vpe_client_registration_t *clients, client;
  stats_main_t *sm = &stats_main;
  vl_api_registration_t *reg, *reg_prev = NULL;
  vl_api_vnet_interface_combined_counters_t *mp_copy = NULL;
  u32 mp_size;
  int i;

  mp_size = sizeof (*mp) + (ntohl (mp->count) * sizeof (vlib_counter_t));

  clients =
    get_clients_for_stat (IDX_PER_INTERFACE_COMBINED_COUNTERS,
			  ~0 /*flag for all */ );

  for (i = 0; i < vec_len (clients); i++)
    {
      client = clients[i];
      reg = vl_api_client_index_to_registration (client.client_index);
      if (reg)
	{
	  if (reg_prev && vl_api_can_send_msg (reg_prev))
	    {
	      mp_copy = vl_msg_api_alloc_as_if_client (mp_size);
	      clib_memcpy (mp_copy, mp, mp_size);
	      vl_api_send_msg (reg_prev, (u8 *) mp);
	      mp = mp_copy;
	    }
	  reg_prev = reg;
	}
    }
  vec_free (clients);
#if STATS_DEBUG > 0
  fformat (stdout, "%U\n", format_vnet_combined_counters, mp);
#endif

  if (reg_prev && vl_api_can_send_msg (reg_prev))
    {
      vl_api_send_msg (reg_prev, (u8 *) mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
do_combined_interface_counters (stats_main_t * sm)
{
  vl_api_vnet_interface_combined_counters_t *mp = 0;
  vnet_interface_main_t *im = sm->interface_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q = shmem_hdr->vl_input_queue;
  vlib_combined_counter_main_t *cm;
  u32 items_this_message = 0;
  vlib_counter_t v, *vp = 0;
  int i, n_counts;

  vnet_interface_counter_lock (im);

  vec_foreach (cm, im->combined_sw_if_counters)
  {
    n_counts = vlib_combined_counter_n_counters (cm);
    for (i = 0; i < n_counts; i++)
      {
	if (mp == 0)
	  {
	    items_this_message = clib_min (COMBINED_COUNTER_BATCH_SIZE,
					   n_counts - i);

	    mp = vl_msg_api_alloc_as_if_client
	      (sizeof (*mp) + items_this_message * sizeof (v));
	    mp->_vl_msg_id = ntohs (VL_API_VNET_INTERFACE_COMBINED_COUNTERS);
	    mp->vnet_counter_type = cm - im->combined_sw_if_counters;
	    mp->first_sw_if_index = htonl (i);
	    mp->count = 0;
	    vp = (vlib_counter_t *) mp->data;
	  }
	vlib_get_combined_counter (cm, i, &v);
	clib_mem_unaligned (&vp->packets, u64)
	  = clib_host_to_net_u64 (v.packets);
	clib_mem_unaligned (&vp->bytes, u64) = clib_host_to_net_u64 (v.bytes);
	vp++;
	mp->count++;
	if (mp->count == items_this_message)
	  {
	    mp->count = htonl (items_this_message);
	    /* Send to the main thread... */
	    vl_msg_api_send_shmem (q, (u8 *) & mp);
	    mp = 0;
	  }
      }
    ASSERT (mp == 0);
  }
  vnet_interface_counter_unlock (im);
}

/**********************************
 * Per Interface Combined stats
 **********************************/

/* Request from client registering interfaces it wants */
static void
  vl_api_want_per_interface_combined_stats_t_handler
  (vl_api_want_per_interface_combined_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_per_interface_combined_stats_reply_t *rmp;
  vlib_combined_counter_main_t *cm;
  uword *p;
  i32 retval = 0;
  vl_api_registration_t *reg;
  u32 i, swif, num = 0;

  num = ntohl (mp->num);

  /*
   * Validate sw_if_indexes before registering
   */
  for (i = 0; i < num; i++)
    {
      swif = ntohl (mp->sw_ifs[i]);

      /*
       * Check its a real sw_if_index that the client is allowed to see
       */
      if (swif != ~0)
	{
	  if (pool_is_free_index (sm->interface_main->sw_interfaces, swif))
	    {
	      retval = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	      goto reply;
	    }
	}
    }

  for (i = 0; i < num; i++)
    {
      swif = ntohl (mp->sw_ifs[i]);

      rp.client_index = mp->client_index;
      rp.client_pid = mp->pid;
      handle_client_registration (&rp, IDX_PER_INTERFACE_COMBINED_COUNTERS,
				  swif, ntohl (mp->enable_disable));
    }

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      for (i = 0; i < num; i++)
	{
	  swif = ntohl (mp->sw_ifs[i]);

	  sm->enable_poller =
	    clear_client_for_stat (IDX_PER_INTERFACE_COMBINED_COUNTERS, swif,
				   mp->client_index);
	}
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_PER_INTERFACE_COMBINED_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* Per Interface Combined distribution to client */
static void
do_combined_per_interface_counters (stats_main_t * sm)
{
  vl_api_vnet_per_interface_combined_counters_t *mp = 0;
  vnet_interface_main_t *im = sm->interface_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  vl_api_registration_t *vl_reg;
  vlib_combined_counter_main_t *cm;
  vl_api_vnet_combined_counter_t *vp = 0;
  vlib_counter_t v;
  u32 i, j;
  vpe_client_stats_registration_t *reg;
  vpe_client_registration_t *client;
  u32 *sw_if_index = 0;

  vnet_interface_counter_lock (im);

  vec_reset_length (sm->regs_tmp);

  /* *INDENT-OFF* */
  pool_foreach (reg,
                sm->stats_registrations[IDX_PER_INTERFACE_COMBINED_COUNTERS],
		({ vec_add1 (sm->regs_tmp, reg); }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (sm->regs_tmp); i++)
    {
      reg = sm->regs_tmp[i];
      if (reg->item == ~0)
	{
	  vnet_interface_counter_unlock (im);
	  do_combined_interface_counters (sm);
	  vnet_interface_counter_lock (im);
	  continue;
	}
      vec_reset_length (sm->clients_tmp);

      /* *INDENT-OFF* */
      pool_foreach (client, reg->clients, ({ vec_add1 (sm->clients_tmp,
						      client);}));
      /* *INDENT-ON* */

      for (j = 0; j < vec_len (sm->clients_tmp); j++)
	{
	  client = sm->clients_tmp[j];

	  vl_reg = vl_api_client_index_to_registration (client->client_index);

	  //Client may have disconnected abrubtly, clean up so we don't poll nothing.
	  if (!vl_reg)
	    {
	      sm->enable_poller =
		clear_client_for_stat (IDX_PER_INTERFACE_COMBINED_COUNTERS,
				       reg->item, client->client_index);
	      continue;
	    }
	  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp) + sizeof (*vp));
	  clib_memset (mp, 0, sizeof (*mp));

	  mp->_vl_msg_id =
	    ntohs (VL_API_VNET_PER_INTERFACE_COMBINED_COUNTERS);

	  /*
	   * count will eventually be used to optimise the batching
	   * of per client messages for each stat. For now setting this to 1 then
	   * iterate. This will not affect API.
	   *
	   * FIXME instead of enqueueing here, this should be sent to a batch
	   * storer for per-client transmission. Each "mp" sent would be a single entry
	   * and if a client is listening to other sw_if_indexes for same, it would be
	   * appended to that *mp
	   *
	   *
	   * FIXME(s):
	   * - capturing the timestamp of the counters "when VPP knew them" is important.
	   * Less so is that the timing of the delivery to the control plane be in the same
	   * timescale.

	   * i.e. As long as the control plane can delta messages from VPP and work out
	   * velocity etc based on the timestamp, it can do so in a more "batch mode".

	   * It would be beneficial to keep a "per-client" message queue, and then
	   * batch all the stat messages for a client into one message, with
	   * discrete timestamps.

	   * Given this particular API is for "per interface" one assumes that the scale
	   * is less than the ~0 case, which the prior API is suited for.
	   */

	  /*
	   * 1 message per api call for now
	   */
	  mp->count = htonl (1);
	  mp->timestamp = htonl (vlib_time_now (sm->vlib_main));

	  vp = (vl_api_vnet_combined_counter_t *) mp->data;
	  vp->sw_if_index = htonl (reg->item);

	  im = &vnet_get_main ()->interface_main;

#define _(X, x)                  \
          cm = im->combined_sw_if_counters + X; \
          vlib_get_combined_counter (cm, reg->item, &v); \
          clib_mem_unaligned (&vp->x##_packets, u64) = \
            clib_host_to_net_u64 (v.packets); \
          clib_mem_unaligned (&vp->x##_bytes, u64) = \
            clib_host_to_net_u64 (v.bytes);


	  _(VNET_INTERFACE_COUNTER_RX, rx);
	  _(VNET_INTERFACE_COUNTER_TX, tx);
	  _(VNET_INTERFACE_COUNTER_RX_UNICAST, rx_unicast);
	  _(VNET_INTERFACE_COUNTER_TX_UNICAST, tx_unicast);
	  _(VNET_INTERFACE_COUNTER_RX_MULTICAST, rx_multicast);
	  _(VNET_INTERFACE_COUNTER_TX_MULTICAST, tx_multicast);
	  _(VNET_INTERFACE_COUNTER_RX_BROADCAST, rx_broadcast);
	  _(VNET_INTERFACE_COUNTER_TX_BROADCAST, tx_broadcast);

#undef _

	  vl_api_send_msg (vl_reg, (u8 *) mp);
	}
    }

  vnet_interface_counter_unlock (im);
}

/**********************************
 * Per Interface simple stats
 **********************************/

/* Request from client registering interfaces it wants */
static void
  vl_api_want_per_interface_simple_stats_t_handler
  (vl_api_want_per_interface_simple_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_per_interface_simple_stats_reply_t *rmp;
  vlib_simple_counter_main_t *cm;
  uword *p;
  i32 retval = 0;
  vl_api_registration_t *reg;
  u32 i, swif, num = 0;

  num = ntohl (mp->num);

  for (i = 0; i < num; i++)
    {
      swif = ntohl (mp->sw_ifs[i]);

      /* Check its a real sw_if_index that the client is allowed to see */
      if (swif != ~0)
	{
	  if (pool_is_free_index (sm->interface_main->sw_interfaces, swif))
	    {
	      retval = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	      goto reply;
	    }
	}
    }

  for (i = 0; i < num; i++)
    {
      swif = ntohl (mp->sw_ifs[i]);

      rp.client_index = mp->client_index;
      rp.client_pid = mp->pid;
      handle_client_registration (&rp, IDX_PER_INTERFACE_SIMPLE_COUNTERS,
				  swif, ntohl (mp->enable_disable));
    }

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);

  /* Client may have disconnected abruptly, clean up */
  if (!reg)
    {
      for (i = 0; i < num; i++)
	{
	  swif = ntohl (mp->sw_ifs[i]);
	  sm->enable_poller =
	    clear_client_for_stat (IDX_PER_INTERFACE_SIMPLE_COUNTERS, swif,
				   mp->client_index);
	}

      return;
    }


  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_PER_INTERFACE_SIMPLE_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* Per Interface Simple distribution to client */
static void
do_simple_per_interface_counters (stats_main_t * sm)
{
  vl_api_vnet_per_interface_simple_counters_t *mp = 0;
  vnet_interface_main_t *im = sm->interface_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  vl_api_registration_t *vl_reg;
  vlib_simple_counter_main_t *cm;
  u32 i, j, size;
  vpe_client_stats_registration_t *reg;
  vpe_client_registration_t *client;
  u32 timestamp, count;
  vl_api_vnet_simple_counter_t *vp = 0;
  counter_t v;

  vnet_interface_counter_lock (im);

  vec_reset_length (sm->regs_tmp);

  /* *INDENT-OFF* */
  pool_foreach (reg,
		sm->stats_registrations[IDX_PER_INTERFACE_SIMPLE_COUNTERS],
                ({ vec_add1 (sm->regs_tmp, reg); }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (sm->regs_tmp); i++)
    {
      reg = sm->regs_tmp[i];
      if (reg->item == ~0)
	{
	  vnet_interface_counter_unlock (im);
	  do_simple_interface_counters (sm);
	  vnet_interface_counter_lock (im);
	  continue;
	}
      vec_reset_length (sm->clients_tmp);

      /* *INDENT-OFF* */
      pool_foreach (client, reg->clients, ({ vec_add1 (sm->clients_tmp,
						      client);}));
      /* *INDENT-ON* */

      for (j = 0; j < vec_len (sm->clients_tmp); j++)
	{
	  client = sm->clients_tmp[j];
	  vl_reg = vl_api_client_index_to_registration (client->client_index);

	  /* Client may have disconnected abrubtly, clean up */
	  if (!vl_reg)
	    {
	      sm->enable_poller =
		clear_client_for_stat (IDX_PER_INTERFACE_SIMPLE_COUNTERS,
				       reg->item, client->client_index);
	      continue;
	    }

	  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp) + sizeof (*vp));
	  clib_memset (mp, 0, sizeof (*mp));
	  mp->_vl_msg_id = ntohs (VL_API_VNET_PER_INTERFACE_SIMPLE_COUNTERS);

	  /*
	   * count will eventually be used to optimise the batching
	   * of per client messages for each stat. For now setting this to 1 then
	   * iterate. This will not affect API.
	   *
	   * FIXME instead of enqueueing here, this should be sent to a batch
	   * storer for per-client transmission. Each "mp" sent would be a single entry
	   * and if a client is listening to other sw_if_indexes for same, it would be
	   * appended to that *mp
	   *
	   *
	   * FIXME(s):
	   * - capturing the timestamp of the counters "when VPP knew them" is important.
	   * Less so is that the timing of the delivery to the control plane be in the same
	   * timescale.

	   * i.e. As long as the control plane can delta messages from VPP and work out
	   * velocity etc based on the timestamp, it can do so in a more "batch mode".

	   * It would be beneficial to keep a "per-client" message queue, and then
	   * batch all the stat messages for a client into one message, with
	   * discrete timestamps.

	   * Given this particular API is for "per interface" one assumes that the scale
	   * is less than the ~0 case, which the prior API is suited for.
	   */

	  /*
	   * 1 message per api call for now
	   */
	  mp->count = htonl (1);
	  mp->timestamp = htonl (vlib_time_now (sm->vlib_main));
	  vp = (vl_api_vnet_simple_counter_t *) mp->data;

	  vp->sw_if_index = htonl (reg->item);

	  // VNET_INTERFACE_COUNTER_DROP
	  cm = im->sw_if_counters + VNET_INTERFACE_COUNTER_DROP;
	  v = vlib_get_simple_counter (cm, reg->item);
	  clib_mem_unaligned (&vp->drop, u64) = clib_host_to_net_u64 (v);

	  // VNET_INTERFACE_COUNTER_PUNT
	  cm = im->sw_if_counters + VNET_INTERFACE_COUNTER_PUNT;
	  v = vlib_get_simple_counter (cm, reg->item);
	  clib_mem_unaligned (&vp->punt, u64) = clib_host_to_net_u64 (v);

	  // VNET_INTERFACE_COUNTER_IP4
	  cm = im->sw_if_counters + VNET_INTERFACE_COUNTER_IP4;
	  v = vlib_get_simple_counter (cm, reg->item);
	  clib_mem_unaligned (&vp->rx_ip4, u64) = clib_host_to_net_u64 (v);

	  //VNET_INTERFACE_COUNTER_IP6
	  cm = im->sw_if_counters + VNET_INTERFACE_COUNTER_IP6;
	  v = vlib_get_simple_counter (cm, reg->item);
	  clib_mem_unaligned (&vp->rx_ip6, u64) = clib_host_to_net_u64 (v);

	  //VNET_INTERFACE_COUNTER_RX_NO_BUF
	  cm = im->sw_if_counters + VNET_INTERFACE_COUNTER_RX_NO_BUF;
	  v = vlib_get_simple_counter (cm, reg->item);
	  clib_mem_unaligned (&vp->rx_no_buffer, u64) =
	    clib_host_to_net_u64 (v);

	  //VNET_INTERFACE_COUNTER_RX_MISS
	  cm = im->sw_if_counters + VNET_INTERFACE_COUNTER_RX_MISS;
	  v = vlib_get_simple_counter (cm, reg->item);
	  clib_mem_unaligned (&vp->rx_miss, u64) = clib_host_to_net_u64 (v);

	  //VNET_INTERFACE_COUNTER_RX_ERROR
	  cm = im->sw_if_counters + VNET_INTERFACE_COUNTER_RX_ERROR;
	  v = vlib_get_simple_counter (cm, reg->item);
	  clib_mem_unaligned (&vp->rx_error, u64) = clib_host_to_net_u64 (v);

	  //VNET_INTERFACE_COUNTER_TX_ERROR
	  cm = im->sw_if_counters + VNET_INTERFACE_COUNTER_TX_ERROR;
	  v = vlib_get_simple_counter (cm, reg->item);
	  clib_mem_unaligned (&vp->tx_error, u64) = clib_host_to_net_u64 (v);

	  //VNET_INTERFACE_COUNTER_MPLS
	  cm = im->sw_if_counters + VNET_INTERFACE_COUNTER_MPLS;
	  v = vlib_get_simple_counter (cm, reg->item);
	  clib_mem_unaligned (&vp->rx_mpls, u64) = clib_host_to_net_u64 (v);

	  vl_api_send_msg (vl_reg, (u8 *) mp);
	}
    }

  vnet_interface_counter_unlock (im);
}

/**********************************
 * Per FIB IP4 stats
 **********************************/

static void
ip46_fib_stats_delay (stats_main_t * sm, u32 sec, u32 nsec)
{
  struct timespec _req, *req = &_req;
  struct timespec _rem, *rem = &_rem;

  req->tv_sec = sec;
  req->tv_nsec = nsec;
  while (1)
    {
      if (nanosleep (req, rem) == 0)
	break;
      *req = *rem;
      if (errno == EINTR)
	continue;
      clib_unix_warning ("nanosleep");
      break;
    }
}

/**
 * @brief The context passed when collecting adjacency counters
 */
typedef struct ip4_nbr_stats_ctx_t_
{
  /**
   * The SW IF index all these adjs belong to
   */
  u32 sw_if_index;

  /**
   * A vector of ip4 nbr counters
   */
  vl_api_ip4_nbr_counter_t *counters;
} ip4_nbr_stats_ctx_t;

static adj_walk_rc_t
ip4_nbr_stats_cb (adj_index_t ai, void *arg)
{
  vl_api_ip4_nbr_counter_t *vl_counter;
  vlib_counter_t adj_counter;
  ip4_nbr_stats_ctx_t *ctx;
  ip_adjacency_t *adj;

  ctx = arg;
  vlib_get_combined_counter (&adjacency_counters, ai, &adj_counter);

  if (0 != adj_counter.packets)
    {
      vec_add2 (ctx->counters, vl_counter, 1);
      adj = adj_get (ai);

      vl_counter->packets = clib_host_to_net_u64 (adj_counter.packets);
      vl_counter->bytes = clib_host_to_net_u64 (adj_counter.bytes);
      vl_counter->address = adj->sub_type.nbr.next_hop.ip4.as_u32;
      vl_counter->link_type = adj->ia_link;
    }
  return (ADJ_WALK_RC_CONTINUE);
}

#define MIN(x,y) (((x)<(y))?(x):(y))

static void
send_and_pause (stats_main_t * sm, svm_queue_t * q, u8 * mp)
{
  u8 pause = 0;

  svm_queue_lock (q);
  pause = svm_queue_is_full (q);

  vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
  svm_queue_unlock (q);
  dsunlock (sm);

  if (pause)
    ip46_fib_stats_delay (sm, 0 /* sec */ ,
			  STATS_RELEASE_DELAY_NS);
}

static void
ip4_nbr_ship (stats_main_t * sm, ip4_nbr_stats_ctx_t * ctx)
{
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q = shmem_hdr->vl_input_queue;
  vl_api_vnet_ip4_nbr_counters_t *mp = 0;
  int first = 0;

  /*
   * If the walk context has counters, which may be left over from the last
   * suspend, then we continue from there.
   */
  while (0 != vec_len (ctx->counters))
    {
      u32 n_items = MIN (vec_len (ctx->counters),
			 IP4_FIB_COUNTER_BATCH_SIZE);
      u8 pause = 0;

      dslock (sm, 0 /* release hint */ , 1 /* tag */ );

      mp = vl_msg_api_alloc_as_if_client (sizeof (*mp) +
					  (n_items *
					   sizeof
					   (vl_api_ip4_nbr_counter_t)));
      mp->_vl_msg_id = ntohs (VL_API_VNET_IP4_NBR_COUNTERS);
      mp->count = ntohl (n_items);
      mp->sw_if_index = ntohl (ctx->sw_if_index);
      mp->begin = first;
      first = 0;

      /*
       * copy the counters from the back of the context, then we can easily
       * 'erase' them by resetting the vector length.
       * The order we push the stats to the caller is not important.
       */
      clib_memcpy (mp->c,
		   &ctx->counters[vec_len (ctx->counters) - n_items],
		   n_items * sizeof (*ctx->counters));

      _vec_len (ctx->counters) = vec_len (ctx->counters) - n_items;

      /*
       * send to the shm q
       */
      send_and_pause (sm, q, (u8 *) & mp);
    }
}

static void
do_ip4_nbr_counters (stats_main_t * sm)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si;

  ip4_nbr_stats_ctx_t ctx = {
    .sw_if_index = 0,
    .counters = NULL,
  };

  /* *INDENT-OFF* */
  pool_foreach (si, im->sw_interfaces,
  ({
    /*
     * update the interface we are now concerned with
     */
    ctx.sw_if_index = si->sw_if_index;

    /*
     * we are about to walk another interface, so we shouldn't have any pending
     * stats to export.
     */
    ASSERT(ctx.counters == NULL);

    /*
     * visit each neighbour adjacency on the interface and collect
     * its current stats.
     * Because we hold the lock the walk is synchronous, so safe to routing
     * updates. It's limited in work by the number of adjacenies on an
     * interface, which is typically not huge.
     */
    dslock (sm, 0 /* release hint */ , 1 /* tag */ );
    adj_nbr_walk (si->sw_if_index,
                  FIB_PROTOCOL_IP4,
                  ip4_nbr_stats_cb,
                  &ctx);
    dsunlock (sm);

    /*
     * if this interface has some adjacencies with counters then ship them,
     * else continue to the next interface.
     */
    if (NULL != ctx.counters)
      {
        ip4_nbr_ship(sm, &ctx);
      }
  }));
  /* *INDENT-OFF* */
}

/**
 * @brief The context passed when collecting adjacency counters
 */
typedef struct ip6_nbr_stats_ctx_t_
{
  /**
   * The SW IF index all these adjs belong to
   */
  u32 sw_if_index;

  /**
   * A vector of ip6 nbr counters
   */
  vl_api_ip6_nbr_counter_t *counters;
} ip6_nbr_stats_ctx_t;

static adj_walk_rc_t
ip6_nbr_stats_cb (adj_index_t ai,
                  void *arg)
{
  vl_api_ip6_nbr_counter_t *vl_counter;
  vlib_counter_t adj_counter;
  ip6_nbr_stats_ctx_t *ctx;
  ip_adjacency_t *adj;

  ctx = arg;
  vlib_get_combined_counter(&adjacency_counters, ai, &adj_counter);

  if (0 != adj_counter.packets)
    {
      vec_add2(ctx->counters, vl_counter, 1);
      adj = adj_get(ai);

      vl_counter->packets = clib_host_to_net_u64(adj_counter.packets);
      vl_counter->bytes   = clib_host_to_net_u64(adj_counter.bytes);
      vl_counter->address[0] = adj->sub_type.nbr.next_hop.ip6.as_u64[0];
      vl_counter->address[1] = adj->sub_type.nbr.next_hop.ip6.as_u64[1];
      vl_counter->link_type = adj->ia_link;
    }
  return (ADJ_WALK_RC_CONTINUE);
}

#define MIN(x,y) (((x)<(y))?(x):(y))

static void
ip6_nbr_ship (stats_main_t * sm,
              ip6_nbr_stats_ctx_t *ctx)
{
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q = shmem_hdr->vl_input_queue;
  vl_api_vnet_ip6_nbr_counters_t *mp = 0;
  int first = 0;

  /*
   * If the walk context has counters, which may be left over from the last
   * suspend, then we continue from there.
   */
  while (0 != vec_len(ctx->counters))
    {
      u32 n_items = MIN (vec_len (ctx->counters),
			 IP6_FIB_COUNTER_BATCH_SIZE);
      u8 pause = 0;

      dslock (sm, 0 /* release hint */ , 1 /* tag */ );

      mp = vl_msg_api_alloc_as_if_client (sizeof (*mp) +
					  (n_items *
					   sizeof
					   (vl_api_ip6_nbr_counter_t)));
      mp->_vl_msg_id = ntohs (VL_API_VNET_IP6_NBR_COUNTERS);
      mp->count = ntohl (n_items);
      mp->sw_if_index = ntohl (ctx->sw_if_index);
      mp->begin = first;
      first = 0;

      /*
       * copy the counters from the back of the context, then we can easily
       * 'erase' them by resetting the vector length.
       * The order we push the stats to the caller is not important.
       */
      clib_memcpy (mp->c,
		   &ctx->counters[vec_len (ctx->counters) - n_items],
		   n_items * sizeof (*ctx->counters));

      _vec_len (ctx->counters) = vec_len (ctx->counters) - n_items;

      /*
       * send to the shm q
       */
      send_and_pause(sm, q, (u8 *) & mp);
    }
}

static void
do_ip6_nbr_counters (stats_main_t * sm)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si;

  ip6_nbr_stats_ctx_t ctx = {
    .sw_if_index = 0,
    .counters = NULL,
  };

  /* *INDENT-OFF* */
  pool_foreach (si, im->sw_interfaces,
  ({
    /*
     * update the interface we are now concerned with
     */
    ctx.sw_if_index = si->sw_if_index;

    /*
     * we are about to walk another interface, so we shouldn't have any pending
     * stats to export.
     */
    ASSERT(ctx.counters == NULL);

    /*
     * visit each neighbour adjacency on the interface and collect
     * its current stats.
     * Because we hold the lock the walk is synchronous, so safe to routing
     * updates. It's limited in work by the number of adjacenies on an
     * interface, which is typically not huge.
     */
    dslock (sm, 0 /* release hint */ , 1 /* tag */ );
    adj_nbr_walk (si->sw_if_index,
                  FIB_PROTOCOL_IP6,
                  ip6_nbr_stats_cb,
                  &ctx);
    dsunlock (sm);

    /*
     * if this interface has some adjacencies with counters then ship them,
     * else continue to the next interface.
     */
    if (NULL != ctx.counters)
      {
        ip6_nbr_ship(sm, &ctx);
      }
  }));
  /* *INDENT-OFF* */
}

static void
do_ip4_fib_counters (stats_main_t * sm)
{
  ip4_main_t *im4 = &ip4_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q = shmem_hdr->vl_input_queue;
  ip4_route_t *r;
  fib_table_t *fib;
  ip4_fib_t *v4_fib;
  do_ip46_fibs_t *do_fibs;
  vl_api_vnet_ip4_fib_counters_t *mp = 0;
  u32 items_this_message;
  vl_api_ip4_fib_counter_t *ctrp = 0;
  u32 start_at_fib_index = 0;
  int i, j, k;

  do_fibs = &sm->do_ip46_fibs;

again:
  vec_reset_length (do_fibs->fibs);
  /* *INDENT-OFF* */
  pool_foreach (fib, im4->fibs,
                ({vec_add1(do_fibs->fibs,fib);}));

  /* *INDENT-ON* */

  for (j = 0; j < vec_len (do_fibs->fibs); j++)
    {
      fib = do_fibs->fibs[j];
      /* We may have bailed out due to control-plane activity */
      while ((fib - im4->fibs) < start_at_fib_index)
	continue;

      v4_fib = pool_elt_at_index (im4->v4_fibs, fib->ft_index);

      if (mp == 0)
	{
	  items_this_message = IP4_FIB_COUNTER_BATCH_SIZE;
	  mp = vl_msg_api_alloc_as_if_client
	    (sizeof (*mp) +
	     items_this_message * sizeof (vl_api_ip4_fib_counter_t));
	  mp->_vl_msg_id = ntohs (VL_API_VNET_IP4_FIB_COUNTERS);
	  mp->count = 0;
	  mp->vrf_id = ntohl (fib->ft_table_id);
	  ctrp = (vl_api_ip4_fib_counter_t *) mp->c;
	}
      else
	{
	  /* happens if the last FIB was empty... */
	  ASSERT (mp->count == 0);
	  mp->vrf_id = ntohl (fib->ft_table_id);
	}

      dslock (sm, 0 /* release hint */ , 1 /* tag */ );

      vec_reset_length (do_fibs->ip4routes);
      vec_reset_length (do_fibs->results);

      for (i = 0; i < ARRAY_LEN (v4_fib->fib_entry_by_dst_address); i++)
	{
	  uword *hash = v4_fib->fib_entry_by_dst_address[i];
	  hash_pair_t *p;
	  ip4_route_t x;

	  vec_reset_length (do_fibs->pvec);

	  x.address_length = i;

	  hash_foreach_pair (p, hash, (
					{
					vec_add1 (do_fibs->pvec, p);}
			     ));
	  for (k = 0; k < vec_len (do_fibs->pvec); k++)
	    {
	      p = do_fibs->pvec[k];
	      x.address.data_u32 = p->key;
	      x.index = p->value[0];

	      vec_add1 (do_fibs->ip4routes, x);
	      if (sm->data_structure_lock->release_hint)
		{
		  start_at_fib_index = fib - im4->fibs;
		  dsunlock (sm);
		  ip46_fib_stats_delay (sm, 0 /* sec */ ,
					STATS_RELEASE_DELAY_NS);
		  mp->count = 0;
		  ctrp = (vl_api_ip4_fib_counter_t *) mp->c;
		  goto again;
		}
	    }
	}

      vec_foreach (r, do_fibs->ip4routes)
      {
	vlib_counter_t c;
	const dpo_id_t *dpo_id;
	u32 index;

	dpo_id = fib_entry_contribute_ip_forwarding (r->index);
	index = (u32) dpo_id->dpoi_index;

	vlib_get_combined_counter (&load_balance_main.lbm_to_counters,
				   index, &c);
	/*
	 * If it has actually
	 * seen at least one packet, send it.
	 */
	if (c.packets > 0)
	  {

	    /* already in net byte order */
	    ctrp->address = r->address.as_u32;
	    ctrp->address_length = r->address_length;
	    ctrp->packets = clib_host_to_net_u64 (c.packets);
	    ctrp->bytes = clib_host_to_net_u64 (c.bytes);
	    mp->count++;
	    ctrp++;

	    if (mp->count == items_this_message)
	      {
		mp->count = htonl (items_this_message);
		/*
		 * If the main thread's input queue is stuffed,
		 * drop the data structure lock (which the main thread
		 * may want), and take a pause.
		 */
		svm_queue_lock (q);
		if (svm_queue_is_full (q))
		  {
		    dsunlock (sm);
		    vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		    svm_queue_unlock (q);
		    mp = 0;
		    ip46_fib_stats_delay (sm, 0 /* sec */ ,
					  STATS_RELEASE_DELAY_NS);
		    goto again;
		  }
		vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		svm_queue_unlock (q);

		items_this_message = IP4_FIB_COUNTER_BATCH_SIZE;
		mp = vl_msg_api_alloc_as_if_client
		  (sizeof (*mp) +
		   items_this_message * sizeof (vl_api_ip4_fib_counter_t));
		mp->_vl_msg_id = ntohs (VL_API_VNET_IP4_FIB_COUNTERS);
		mp->count = 0;
		mp->vrf_id = ntohl (fib->ft_table_id);
		ctrp = (vl_api_ip4_fib_counter_t *) mp->c;
	      }
	  }			/* for each (mp or single) adj */
	if (sm->data_structure_lock->release_hint)
	  {
	    start_at_fib_index = fib - im4->fibs;
	    dsunlock (sm);
	    ip46_fib_stats_delay (sm, 0 /* sec */ , STATS_RELEASE_DELAY_NS);
	    mp->count = 0;
	    ctrp = (vl_api_ip4_fib_counter_t *) mp->c;
	    goto again;
	  }
      }				/* vec_foreach (routes) */

      dsunlock (sm);

      /* Flush any data from this fib */
      if (mp->count)
	{
	  mp->count = htonl (mp->count);
	  vl_msg_api_send_shmem (q, (u8 *) & mp);
	  mp = 0;
	}
    }

  /* If e.g. the last FIB had no reportable routes, free the buffer */
  if (mp)
    vl_msg_api_free (mp);
}

static int
mfib_table_stats_walk_cb (fib_node_index_t fei, void *ctx)
{
  stats_main_t *sm = ctx;
  do_ip46_fibs_t *do_fibs;
  mfib_entry_t *entry;

  do_fibs = &sm->do_ip46_fibs;
  entry = mfib_entry_get (fei);

  vec_add1 (do_fibs->mroutes, entry->mfe_prefix);

  return (1);
}

static void
do_ip4_mfib_counters (stats_main_t * sm)
{
  ip4_main_t *im4 = &ip4_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q = shmem_hdr->vl_input_queue;
  mfib_prefix_t *pfx;
  mfib_table_t *mfib;
  do_ip46_fibs_t *do_fibs;
  vl_api_vnet_ip4_mfib_counters_t *mp = 0;
  u32 items_this_message;
  vl_api_ip4_mfib_counter_t *ctrp = 0;
  u32 start_at_mfib_index = 0;
  int i, j, k;

  do_fibs = &sm->do_ip46_fibs;

  vec_reset_length (do_fibs->mfibs);
  /* *INDENT-OFF* */
  pool_foreach (mfib, im4->mfibs, ({vec_add1(do_fibs->mfibs, mfib);}));
  /* *INDENT-ON* */

  for (j = 0; j < vec_len (do_fibs->mfibs); j++)
    {
      mfib = do_fibs->mfibs[j];
      /* We may have bailed out due to control-plane activity */
      while ((mfib - im4->mfibs) < start_at_mfib_index)
	continue;

      if (mp == 0)
	{
	  items_this_message = IP4_MFIB_COUNTER_BATCH_SIZE;
	  mp = vl_msg_api_alloc_as_if_client
	    (sizeof (*mp) +
	     items_this_message * sizeof (vl_api_ip4_mfib_counter_t));
	  mp->_vl_msg_id = ntohs (VL_API_VNET_IP4_MFIB_COUNTERS);
	  mp->count = 0;
	  mp->vrf_id = ntohl (mfib->mft_table_id);
	  ctrp = (vl_api_ip4_mfib_counter_t *) mp->c;
	}
      else
	{
	  /* happens if the last MFIB was empty... */
	  ASSERT (mp->count == 0);
	  mp->vrf_id = ntohl (mfib->mft_table_id);
	}

      vec_reset_length (do_fibs->mroutes);

      /*
       * walk the table with table updates blocked
       */
      dslock (sm, 0 /* release hint */ , 1 /* tag */ );

      mfib_table_walk (mfib->mft_index,
		       FIB_PROTOCOL_IP4, mfib_table_stats_walk_cb, sm);
      dsunlock (sm);

      vec_foreach (pfx, do_fibs->mroutes)
      {
	const dpo_id_t *dpo_id;
	fib_node_index_t mfei;
	vlib_counter_t c;
	u32 index;

	/*
	 * re-lookup the entry, since we suspend during the collection
	 */
	mfei = mfib_table_lookup (mfib->mft_index, pfx);

	if (FIB_NODE_INDEX_INVALID == mfei)
	  continue;

	dpo_id = mfib_entry_contribute_ip_forwarding (mfei);
	index = (u32) dpo_id->dpoi_index;

	vlib_get_combined_counter (&replicate_main.repm_counters,
				   dpo_id->dpoi_index, &c);
	/*
	 * If it has seen at least one packet, send it.
	 */
	if (c.packets > 0)
	  {
	    /* already in net byte order */
	    memcpy (ctrp->group, &pfx->fp_grp_addr.ip4, 4);
	    memcpy (ctrp->source, &pfx->fp_src_addr.ip4, 4);
	    ctrp->group_length = pfx->fp_len;
	    ctrp->packets = clib_host_to_net_u64 (c.packets);
	    ctrp->bytes = clib_host_to_net_u64 (c.bytes);
	    mp->count++;
	    ctrp++;

	    if (mp->count == items_this_message)
	      {
		mp->count = htonl (items_this_message);
		/*
		 * If the main thread's input queue is stuffed,
		 * drop the data structure lock (which the main thread
		 * may want), and take a pause.
		 */
		svm_queue_lock (q);

		while (svm_queue_is_full (q))
		  {
		    svm_queue_unlock (q);
		    ip46_fib_stats_delay (sm, 0 /* sec */ ,
					  STATS_RELEASE_DELAY_NS);
		    svm_queue_lock (q);
		  }
		vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		svm_queue_unlock (q);

		items_this_message = IP4_MFIB_COUNTER_BATCH_SIZE;
		mp = vl_msg_api_alloc_as_if_client
		  (sizeof (*mp) +
		   items_this_message * sizeof (vl_api_ip4_mfib_counter_t));
		mp->_vl_msg_id = ntohs (VL_API_VNET_IP4_MFIB_COUNTERS);
		mp->count = 0;
		mp->vrf_id = ntohl (mfib->mft_table_id);
		ctrp = (vl_api_ip4_mfib_counter_t *) mp->c;
	      }
	  }
      }

      /* Flush any data from this mfib */
      if (mp->count)
	{
	  mp->count = htonl (mp->count);
	  vl_msg_api_send_shmem (q, (u8 *) & mp);
	  mp = 0;
	}
    }

  /* If e.g. the last FIB had no reportable routes, free the buffer */
  if (mp)
    vl_msg_api_free (mp);
}

static void
do_ip6_mfib_counters (stats_main_t * sm)
{
  ip6_main_t *im6 = &ip6_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q = shmem_hdr->vl_input_queue;
  mfib_prefix_t *pfx;
  mfib_table_t *mfib;
  do_ip46_fibs_t *do_fibs;
  vl_api_vnet_ip6_mfib_counters_t *mp = 0;
  u32 items_this_message;
  vl_api_ip6_mfib_counter_t *ctrp = 0;
  u32 start_at_mfib_index = 0;
  int i, j, k;

  do_fibs = &sm->do_ip46_fibs;

  vec_reset_length (do_fibs->mfibs);
  /* *INDENT-OFF* */
  pool_foreach (mfib, im6->mfibs, ({vec_add1(do_fibs->mfibs, mfib);}));
  /* *INDENT-ON* */

  for (j = 0; j < vec_len (do_fibs->mfibs); j++)
    {
      mfib = do_fibs->mfibs[j];
      /* We may have bailed out due to control-plane activity */
      while ((mfib - im6->mfibs) < start_at_mfib_index)
	continue;

      if (mp == 0)
	{
	  items_this_message = IP6_MFIB_COUNTER_BATCH_SIZE;
	  mp = vl_msg_api_alloc_as_if_client
	    (sizeof (*mp) +
	     items_this_message * sizeof (vl_api_ip6_mfib_counter_t));
	  mp->_vl_msg_id = ntohs (VL_API_VNET_IP6_MFIB_COUNTERS);
	  mp->count = 0;
	  mp->vrf_id = ntohl (mfib->mft_table_id);
	  ctrp = (vl_api_ip6_mfib_counter_t *) mp->c;
	}
      else
	{
	  /* happens if the last MFIB was empty... */
	  ASSERT (mp->count == 0);
	  mp->vrf_id = ntohl (mfib->mft_table_id);
	}

      vec_reset_length (do_fibs->mroutes);

      /*
       * walk the table with table updates blocked
       */
      dslock (sm, 0 /* release hint */ , 1 /* tag */ );

      mfib_table_walk (mfib->mft_index,
		       FIB_PROTOCOL_IP6, mfib_table_stats_walk_cb, sm);
      dsunlock (sm);

      vec_foreach (pfx, do_fibs->mroutes)
      {
	const dpo_id_t *dpo_id;
	fib_node_index_t mfei;
	vlib_counter_t c;
	u32 index;

	/*
	 * re-lookup the entry, since we suspend during the collection
	 */
	mfei = mfib_table_lookup (mfib->mft_index, pfx);

	if (FIB_NODE_INDEX_INVALID == mfei)
	  continue;

	dpo_id = mfib_entry_contribute_ip_forwarding (mfei);
	index = (u32) dpo_id->dpoi_index;

	vlib_get_combined_counter (&replicate_main.repm_counters,
				   dpo_id->dpoi_index, &c);
	/*
	 * If it has seen at least one packet, send it.
	 */
	if (c.packets > 0)
	  {
	    /* already in net byte order */
	    memcpy (ctrp->group, &pfx->fp_grp_addr.ip6, 16);
	    memcpy (ctrp->source, &pfx->fp_src_addr.ip6, 16);
	    ctrp->group_length = pfx->fp_len;
	    ctrp->packets = clib_host_to_net_u64 (c.packets);
	    ctrp->bytes = clib_host_to_net_u64 (c.bytes);
	    mp->count++;
	    ctrp++;

	    if (mp->count == items_this_message)
	      {
		mp->count = htonl (items_this_message);
		/*
		 * If the main thread's input queue is stuffed,
		 * drop the data structure lock (which the main thread
		 * may want), and take a pause.
		 */
		svm_queue_lock (q);

		while (svm_queue_is_full (q))
		  {
		    svm_queue_unlock (q);
		    ip46_fib_stats_delay (sm, 0 /* sec */ ,
					  STATS_RELEASE_DELAY_NS);
		    svm_queue_lock (q);
		  }
		vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		svm_queue_unlock (q);

		items_this_message = IP6_MFIB_COUNTER_BATCH_SIZE;
		mp = vl_msg_api_alloc_as_if_client
		  (sizeof (*mp) +
		   items_this_message * sizeof (vl_api_ip6_mfib_counter_t));
		mp->_vl_msg_id = ntohs (VL_API_VNET_IP6_MFIB_COUNTERS);
		mp->count = 0;
		mp->vrf_id = ntohl (mfib->mft_table_id);
		ctrp = (vl_api_ip6_mfib_counter_t *) mp->c;
	      }
	  }
      }

      /* Flush any data from this mfib */
      if (mp->count)
	{
	  mp->count = htonl (mp->count);
	  vl_msg_api_send_shmem (q, (u8 *) & mp);
	  mp = 0;
	}
    }

  /* If e.g. the last FIB had no reportable routes, free the buffer */
  if (mp)
    vl_msg_api_free (mp);
}

typedef struct
{
  u32 fib_index;
  ip6_route_t **routep;
  stats_main_t *sm;
} add_routes_in_fib_arg_t;

static void
add_routes_in_fib (BVT (clib_bihash_kv) * kvp, void *arg)
{
  add_routes_in_fib_arg_t *ap = arg;
  stats_main_t *sm = ap->sm;

  if (sm->data_structure_lock->release_hint)
    clib_longjmp (&sm->jmp_buf, 1);

  if (kvp->key[2] >> 32 == ap->fib_index)
    {
      ip6_address_t *addr;
      ip6_route_t *r;
      addr = (ip6_address_t *) kvp;
      vec_add2 (*ap->routep, r, 1);
      r->address = addr[0];
      r->address_length = kvp->key[2] & 0xFF;
      r->index = kvp->value;
    }
}

static void
do_ip6_fib_counters (stats_main_t * sm)
{
  ip6_main_t *im6 = &ip6_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q = shmem_hdr->vl_input_queue;
  ip6_route_t *r;
  fib_table_t *fib;
  do_ip46_fibs_t *do_fibs;
  vl_api_vnet_ip6_fib_counters_t *mp = 0;
  u32 items_this_message;
  vl_api_ip6_fib_counter_t *ctrp = 0;
  u32 start_at_fib_index = 0;
  BVT (clib_bihash) * h = &im6->ip6_table[IP6_FIB_TABLE_FWDING].ip6_hash;
  add_routes_in_fib_arg_t _a, *a = &_a;
  int i;

  do_fibs = &sm->do_ip46_fibs;
again:
  vec_reset_length (do_fibs->fibs);
  /* *INDENT-OFF* */
  pool_foreach (fib, im6->fibs,
                ({vec_add1(do_fibs->fibs,fib);}));
  /* *INDENT-ON* */


  for (i = 0; i < vec_len (do_fibs->fibs); i++)
    {
      fib = do_fibs->fibs[i];
      /* We may have bailed out due to control-plane activity */
      while ((fib - im6->fibs) < start_at_fib_index)
	continue;

      if (mp == 0)
	{
	  items_this_message = IP6_FIB_COUNTER_BATCH_SIZE;
	  mp = vl_msg_api_alloc_as_if_client
	    (sizeof (*mp) +
	     items_this_message * sizeof (vl_api_ip6_fib_counter_t));
	  mp->_vl_msg_id = ntohs (VL_API_VNET_IP6_FIB_COUNTERS);
	  mp->count = 0;
	  mp->vrf_id = ntohl (fib->ft_table_id);
	  ctrp = (vl_api_ip6_fib_counter_t *) mp->c;
	}

      dslock (sm, 0 /* release hint */ , 1 /* tag */ );

      vec_reset_length (do_fibs->ip6routes);
      vec_reset_length (do_fibs->results);

      a->fib_index = fib - im6->fibs;
      a->routep = &do_fibs->ip6routes;
      a->sm = sm;

      if (clib_setjmp (&sm->jmp_buf, 0) == 0)
	{
	  start_at_fib_index = fib - im6->fibs;
	  BV (clib_bihash_foreach_key_value_pair) (h, add_routes_in_fib, a);
	}
      else
	{
	  dsunlock (sm);
	  ip46_fib_stats_delay (sm, 0 /* sec */ ,
				STATS_RELEASE_DELAY_NS);
	  mp->count = 0;
	  ctrp = (vl_api_ip6_fib_counter_t *) mp->c;
	  goto again;
	}

      vec_foreach (r, do_fibs->ip6routes)
      {
	vlib_counter_t c;

	vlib_get_combined_counter (&load_balance_main.lbm_to_counters,
				   r->index, &c);
	/*
	 * If it has actually
	 * seen at least one packet, send it.
	 */
	if (c.packets > 0)
	  {
	    /* already in net byte order */
	    ctrp->address[0] = r->address.as_u64[0];
	    ctrp->address[1] = r->address.as_u64[1];
	    ctrp->address_length = (u8) r->address_length;
	    ctrp->packets = clib_host_to_net_u64 (c.packets);
	    ctrp->bytes = clib_host_to_net_u64 (c.bytes);
	    mp->count++;
	    ctrp++;

	    if (mp->count == items_this_message)
	      {
		mp->count = htonl (items_this_message);
		/*
		 * If the main thread's input queue is stuffed,
		 * drop the data structure lock (which the main thread
		 * may want), and take a pause.
		 */
		svm_queue_lock (q);
		if (svm_queue_is_full (q))
		  {
		    dsunlock (sm);
		    vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		    svm_queue_unlock (q);
		    mp = 0;
		    ip46_fib_stats_delay (sm, 0 /* sec */ ,
					  STATS_RELEASE_DELAY_NS);
		    goto again;
		  }
		vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		svm_queue_unlock (q);

		items_this_message = IP6_FIB_COUNTER_BATCH_SIZE;
		mp = vl_msg_api_alloc_as_if_client
		  (sizeof (*mp) +
		   items_this_message * sizeof (vl_api_ip6_fib_counter_t));
		mp->_vl_msg_id = ntohs (VL_API_VNET_IP6_FIB_COUNTERS);
		mp->count = 0;
		mp->vrf_id = ntohl (fib->ft_table_id);
		ctrp = (vl_api_ip6_fib_counter_t *) mp->c;
	      }
	  }

	if (sm->data_structure_lock->release_hint)
	  {
	    start_at_fib_index = fib - im6->fibs;
	    dsunlock (sm);
	    ip46_fib_stats_delay (sm, 0 /* sec */ , STATS_RELEASE_DELAY_NS);
	    mp->count = 0;
	    ctrp = (vl_api_ip6_fib_counter_t *) mp->c;
	    goto again;
	  }
      }				/* vec_foreach (routes) */

      dsunlock (sm);

      /* Flush any data from this fib */
      if (mp->count)
	{
	  mp->count = htonl (mp->count);
	  vl_msg_api_send_shmem (q, (u8 *) & mp);
	  mp = 0;
	}
    }

  /* If e.g. the last FIB had no reportable routes, free the buffer */
  if (mp)
    vl_msg_api_free (mp);
}

typedef struct udp_encap_stats_walk_t_
{
  vl_api_udp_encap_counter_t *stats;
} udp_encap_stats_walk_t;

static walk_rc_t
udp_encap_stats_walk_cb (index_t uei, void *arg)
{
  udp_encap_stats_walk_t *ctx = arg;
  vl_api_udp_encap_counter_t *stat;
  udp_encap_t *ue;

  vec_add2 (ctx->stats, stat, 1);

  udp_encap_get_stats (uei, &stat->packets, &stat->bytes);

  return (WALK_CONTINUE);
}

static void
udp_encap_ship (udp_encap_stats_walk_t * ctx)
{
  vl_api_vnet_udp_encap_counters_t *mp;
  vl_shmem_hdr_t *shmem_hdr;
  stats_main_t *sm;
  api_main_t *am;
  svm_queue_t *q;

  mp = NULL;
  sm = &stats_main;
  am = sm->api_main;
  shmem_hdr = am->shmem_hdr;
  q = shmem_hdr->vl_input_queue;

  /*
   * If the walk context has counters, which may be left over from the last
   * suspend, then we continue from there.
   */
  while (0 != vec_len (ctx->stats))
    {
      u32 n_items = MIN (vec_len (ctx->stats),
			 UDP_ENCAP_COUNTER_BATCH_SIZE);
      u8 pause = 0;

      dslock (sm, 0 /* release hint */ , 1 /* tag */ );

      mp = vl_msg_api_alloc_as_if_client (sizeof (*mp) +
					  (n_items *
					   sizeof
					   (vl_api_udp_encap_counter_t)));
      mp->_vl_msg_id = ntohs (VL_API_VNET_UDP_ENCAP_COUNTERS);
      mp->count = ntohl (n_items);

      /*
       * copy the counters from the back of the context, then we can easily
       * 'erase' them by resetting the vector length.
       * The order we push the stats to the caller is not important.
       */
      clib_memcpy (mp->c,
		   &ctx->stats[vec_len (ctx->stats) - n_items],
		   n_items * sizeof (*ctx->stats));

      _vec_len (ctx->stats) = vec_len (ctx->stats) - n_items;

      /*
       * send to the shm q
       */
      send_and_pause (sm, q, (u8 *) & mp);
    }
}

static void
do_udp_encap_counters (stats_main_t * sm)
{
  vl_api_udp_encap_counter_t *stat;

  udp_encap_stats_walk_t ctx = {
    .stats = NULL,
  };

  dslock (sm, 0 /* release hint */ , 1 /* tag */ );
  udp_encap_walk (udp_encap_stats_walk_cb, &ctx);
  dsunlock (sm);

  udp_encap_ship (&ctx);
}

typedef struct bier_neighbor_stats_walk_t_
{
  vl_api_bier_neighbor_counter_t *stats;
} bier_neighbor_stats_walk_t;

static walk_rc_t
bier_neighbor_stats_walk_cb (index_t bfmi, void *arg)
{
  bier_neighbor_stats_walk_t *ctx = arg;
  vl_api_bier_neighbor_counter_t *stat;
  fib_route_path_encode_t rpath;
  bier_table_id_t btid;

  vec_add2 (ctx->stats, stat, 1);

  bier_fmask_encode (bfmi, &btid, &rpath);

  stat->tbl_id.bt_set = btid.bti_set;
  stat->tbl_id.bt_sub_domain = btid.bti_sub_domain;
  stat->tbl_id.bt_hdr_len_id = btid.bti_hdr_len;
  fib_api_path_encode (&rpath, &stat->path);
  bier_fmask_get_stats (bfmi, &stat->packets, &stat->bytes);

  return (WALK_CONTINUE);
}

static void
bier_neighbor_ship (bier_neighbor_stats_walk_t * ctx)
{
  vl_api_vnet_bier_neighbor_counters_t *mp;
  vl_shmem_hdr_t *shmem_hdr;
  stats_main_t *sm;
  api_main_t *am;
  svm_queue_t *q;

  mp = NULL;
  sm = &stats_main;
  am = sm->api_main;
  shmem_hdr = am->shmem_hdr;
  q = shmem_hdr->vl_input_queue;

  /*
   * If the walk context has counters, which may be left over from the last
   * suspend, then we continue from there.
   */
  while (0 != vec_len (ctx->stats))
    {
      u32 n_items = MIN (vec_len (ctx->stats),
			 BIER_NEIGHBOR_COUNTER_BATCH_SIZE);
      u8 pause = 0;

      dslock (sm, 0 /* release hint */ , 1 /* tag */ );

      mp = vl_msg_api_alloc_as_if_client (sizeof (*mp) +
					  (n_items *
					   sizeof
					   (vl_api_bier_neighbor_counter_t)));
      mp->_vl_msg_id = ntohs (VL_API_VNET_BIER_NEIGHBOR_COUNTERS);
      mp->count = ntohl (n_items);

      /*
       * copy the counters from the back of the context, then we can easily
       * 'erase' them by resetting the vector length.
       * The order we push the stats to the caller is not important.
       */
      clib_memcpy (mp->c,
		   &ctx->stats[vec_len (ctx->stats) - n_items],
		   n_items * sizeof (*ctx->stats));

      _vec_len (ctx->stats) = vec_len (ctx->stats) - n_items;

      /*
       * send to the shm q
       */
      send_and_pause (sm, q, (u8 *) & mp);
    }
}

static void
do_bier_neighbor_counters (stats_main_t * sm)
{
  vl_api_bier_neighbor_counter_t *stat;

  bier_neighbor_stats_walk_t ctx = {
    .stats = NULL,
  };

  dslock (sm, 0 /* release hint */ , 1 /* tag */ );
  bier_fmask_db_walk (bier_neighbor_stats_walk_cb, &ctx);
  dsunlock (sm);

  bier_neighbor_ship (&ctx);
}

int
stats_set_poller_delay (u32 poller_delay_sec)
{
  stats_main_t *sm = &stats_main;
  if (!poller_delay_sec)
    {
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }
  else
    {
      sm->stats_poll_interval_in_seconds = poller_delay_sec;
      return 0;
    }
}

static clib_error_t *
stats_config (vlib_main_t * vm, unformat_input_t * input)
{
  stats_main_t *sm = &stats_main;
  u32 sec;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "interval %u", &sec))
	{
	  int rv = stats_set_poller_delay (sec);
	  if (rv)
	    {
	      return clib_error_return (0,
					"`stats_set_poller_delay' API call failed, rv=%d:%U",
					(int) rv, format_vnet_api_errno, rv);
	    }
	}
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }

  return 0;
}

/* stats { ... } configuration. */
/*?
 *
 * @cfgcmd{interval, &lt;seconds&gt;}
 * Configure stats poller delay to be @c seconds.
 *
?*/
VLIB_CONFIG_FUNCTION (stats_config, "stats");

static void
  vl_api_stats_get_poller_delay_t_handler
  (vl_api_stats_get_poller_delay_t * mp)
{
  stats_main_t *sm = &stats_main;
  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  vl_api_stats_get_poller_delay_reply_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_STATS_GET_POLLER_DELAY_REPLY);
  rmp->context = mp->context;
  rmp->retval = 0;
  rmp->delay = clib_host_to_net_u32 (sm->stats_poll_interval_in_seconds);

  vl_api_send_msg (reg, (u8 *) rmp);

}

static void
stats_thread_fn (void *arg)
{
  stats_main_t *sm = &stats_main;
  vlib_worker_thread_t *w = (vlib_worker_thread_t *) arg;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  /* stats thread wants no signals. */
  {
    sigset_t s;
    sigfillset (&s);
    pthread_sigmask (SIG_SETMASK, &s, 0);
  }

  clib_mem_set_heap (w->thread_mheap);

  if (vec_len (tm->thread_prefix))
    vlib_set_thread_name ((char *)
			  format (0, "%v_stats%c", tm->thread_prefix, '\0'));

  while (1)
    {
      ip46_fib_stats_delay (sm, sm->stats_poll_interval_in_seconds,
			    0 /* nsec */ );

      if (!(sm->enable_poller))
	continue;

      if (pool_elts
	  (sm->stats_registrations[IDX_PER_INTERFACE_COMBINED_COUNTERS]))
	do_combined_per_interface_counters (sm);

      if (pool_elts
	  (sm->stats_registrations[IDX_PER_INTERFACE_SIMPLE_COUNTERS]))
	do_simple_per_interface_counters (sm);

      if (pool_elts (sm->stats_registrations[IDX_IP4_FIB_COUNTERS]))
	do_ip4_fib_counters (sm);

      if (pool_elts (sm->stats_registrations[IDX_IP6_FIB_COUNTERS]))
	do_ip6_fib_counters (sm);

      if (pool_elts (sm->stats_registrations[IDX_IP4_MFIB_COUNTERS]))
	do_ip4_mfib_counters (sm);

      if (pool_elts (sm->stats_registrations[IDX_IP6_MFIB_COUNTERS]))
	do_ip6_mfib_counters (sm);

      if (pool_elts (sm->stats_registrations[IDX_IP4_NBR_COUNTERS]))
	do_ip4_nbr_counters (sm);

      if (pool_elts (sm->stats_registrations[IDX_IP6_NBR_COUNTERS]))
	do_ip6_nbr_counters (sm);

      if (pool_elts (sm->stats_registrations[IDX_BIER_NEIGHBOR_COUNTERS]))
	do_bier_neighbor_counters (sm);
    }
}

static void
  vl_api_vnet_interface_simple_counters_t_handler
  (vl_api_vnet_interface_simple_counters_t * mp)
{
  vpe_client_registration_t *clients, client;
  stats_main_t *sm = &stats_main;
  vl_api_registration_t *reg, *reg_prev = NULL;
  vl_api_vnet_interface_simple_counters_t *mp_copy = NULL;
  u32 mp_size;
  int i;

  mp_size = sizeof (*mp) + (ntohl (mp->count) * sizeof (u64));

  clients =
    get_clients_for_stat (IDX_PER_INTERFACE_SIMPLE_COUNTERS,
			  ~0 /*flag for all */ );

  for (i = 0; i < vec_len (clients); i++)
    {
      client = clients[i];
      reg = vl_api_client_index_to_registration (client.client_index);
      if (reg)
	{
	  if (reg_prev && vl_api_can_send_msg (reg_prev))
	    {
	      mp_copy = vl_msg_api_alloc_as_if_client (mp_size);
	      clib_memcpy (mp_copy, mp, mp_size);
	      vl_api_send_msg (reg_prev, (u8 *) mp);
	      mp = mp_copy;
	    }
	  reg_prev = reg;
	}
      else
	{
	  sm->enable_poller =
	    clear_client_for_stat (IDX_PER_INTERFACE_SIMPLE_COUNTERS, ~0,
				   client.client_index);
	  continue;
	}
    }
  vec_free (clients);

#if STATS_DEBUG > 0
  fformat (stdout, "%U\n", format_vnet_simple_counters, mp);
#endif

  if (reg_prev && vl_api_can_send_msg (reg_prev))
    {
      vl_api_send_msg (reg_prev, (u8 *) mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_vnet_ip4_fib_counters_t_handler (vl_api_vnet_ip4_fib_counters_t * mp)
{
  stats_main_t *sm = &stats_main;
  vl_api_registration_t *reg, *reg_prev = NULL;
  vl_api_vnet_ip4_fib_counters_t *mp_copy = NULL;
  u32 mp_size;
  vpe_client_registration_t *clients, client;
  int i;

  mp_size = sizeof (*mp_copy) +
    ntohl (mp->count) * sizeof (vl_api_ip4_fib_counter_t);

  clients =
    get_clients_for_stat (IDX_IP4_FIB_COUNTERS, ~0 /*flag for all */ );

  for (i = 0; i < vec_len (clients); i++)
    {
      client = clients[i];
      reg = vl_api_client_index_to_registration (client.client_index);
      if (reg)
	{
	  if (reg_prev && vl_api_can_send_msg (reg_prev))
	    {
	      mp_copy = vl_msg_api_alloc_as_if_client (mp_size);
	      clib_memcpy (mp_copy, mp, mp_size);
	      vl_api_send_msg (reg_prev, (u8 *) mp);
	      mp = mp_copy;
	    }
	  reg_prev = reg;
	}
      else
	{
	  sm->enable_poller = clear_client_for_stat (IDX_IP4_FIB_COUNTERS,
						     ~0, client.client_index);
	  continue;
	}
    }
  vec_free (clients);

  if (reg_prev && vl_api_can_send_msg (reg_prev))
    {
      vl_api_send_msg (reg_prev, (u8 *) mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_vnet_ip4_nbr_counters_t_handler (vl_api_vnet_ip4_nbr_counters_t * mp)
{
  stats_main_t *sm = &stats_main;
  vl_api_registration_t *reg, *reg_prev = NULL;
  vl_api_vnet_ip4_nbr_counters_t *mp_copy = NULL;
  u32 mp_size;
  vpe_client_registration_t *clients, client;
  int i;

  mp_size = sizeof (*mp_copy) +
    ntohl (mp->count) * sizeof (vl_api_ip4_nbr_counter_t);

  clients =
    get_clients_for_stat (IDX_IP4_NBR_COUNTERS, ~0 /*flag for all */ );

  for (i = 0; i < vec_len (clients); i++)
    {
      client = clients[i];
      reg = vl_api_client_index_to_registration (client.client_index);
      if (reg)
	{
	  if (reg_prev && vl_api_can_send_msg (reg_prev))
	    {
	      mp_copy = vl_msg_api_alloc_as_if_client (mp_size);
	      clib_memcpy (mp_copy, mp, mp_size);
	      vl_api_send_msg (reg_prev, (u8 *) mp);
	      mp = mp_copy;
	    }
	  reg_prev = reg;
	}
      else
	{
	  sm->enable_poller = clear_client_for_stat (IDX_IP4_NBR_COUNTERS,
						     ~0, client.client_index);
	  continue;
	}
    }
  vec_free (clients);

  /* *INDENT-ON* */
  if (reg_prev && vl_api_can_send_msg (reg_prev))
    {
      vl_api_send_msg (reg_prev, (u8 *) mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_vnet_ip6_fib_counters_t_handler (vl_api_vnet_ip6_fib_counters_t * mp)
{
  stats_main_t *sm = &stats_main;
  vl_api_registration_t *reg, *reg_prev = NULL;
  vl_api_vnet_ip6_fib_counters_t *mp_copy = NULL;
  u32 mp_size;
  vpe_client_registration_t *clients, client;
  int i;

  mp_size = sizeof (*mp_copy) +
    ntohl (mp->count) * sizeof (vl_api_ip6_fib_counter_t);

  clients =
    get_clients_for_stat (IDX_IP6_FIB_COUNTERS, ~0 /*flag for all */ );

  for (i = 0; i < vec_len (clients); i++)
    {
      client = clients[i];
      reg = vl_api_client_index_to_registration (client.client_index);
      if (reg)
	{
	  if (reg_prev && vl_api_can_send_msg (reg_prev))
	    {
	      mp_copy = vl_msg_api_alloc_as_if_client (mp_size);
	      clib_memcpy (mp_copy, mp, mp_size);
	      vl_api_send_msg (reg_prev, (u8 *) mp);
	      mp = mp_copy;
	    }
	  reg_prev = reg;
	}
      else
	{
	  sm->enable_poller = clear_client_for_stat (IDX_IP6_FIB_COUNTERS,
						     ~0, client.client_index);
	  continue;
	}
    }
  vec_free (clients);

  /* *INDENT-ON* */
  if (reg_prev && vl_api_can_send_msg (reg_prev))
    {
      vl_api_send_msg (reg_prev, (u8 *) mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_vnet_ip6_nbr_counters_t_handler (vl_api_vnet_ip6_nbr_counters_t * mp)
{
  stats_main_t *sm = &stats_main;
  vl_api_registration_t *reg, *reg_prev = NULL;
  vl_api_vnet_ip6_nbr_counters_t *mp_copy = NULL;
  u32 mp_size;
  vpe_client_registration_t *clients, client;
  int i;

  mp_size = sizeof (*mp_copy) +
    ntohl (mp->count) * sizeof (vl_api_ip6_nbr_counter_t);

  clients =
    get_clients_for_stat (IDX_IP6_NBR_COUNTERS, ~0 /*flag for all */ );

  for (i = 0; i < vec_len (clients); i++)
    {
      client = clients[i];
      reg = vl_api_client_index_to_registration (client.client_index);
      if (reg)
	{
	  if (reg_prev && vl_api_can_send_msg (reg_prev))
	    {
	      mp_copy = vl_msg_api_alloc_as_if_client (mp_size);
	      clib_memcpy (mp_copy, mp, mp_size);
	      vl_api_send_msg (reg_prev, (u8 *) mp);
	      mp = mp_copy;
	    }
	  reg_prev = reg;
	}
      else
	{
	  sm->enable_poller = clear_client_for_stat (IDX_IP6_NBR_COUNTERS,
						     ~0, client.client_index);
	  continue;
	}
    }
  vec_free (clients);

  /* *INDENT-ON* */
  if (reg_prev && vl_api_can_send_msg (reg_prev))
    {
      vl_api_send_msg (reg_prev, (u8 *) mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_want_udp_encap_stats_t_handler (vl_api_want_udp_encap_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_udp_encap_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  vl_api_registration_t *reg;
  u32 fib;

  fib = ~0;			//Using same mechanism as _per_interface_
  rp.client_index = mp->client_index;
  rp.client_pid = mp->pid;

  handle_client_registration (&rp, IDX_UDP_ENCAP_COUNTERS, fib, mp->enable);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);

  if (!reg)
    {
      sm->enable_poller = clear_client_for_stat (IDX_UDP_ENCAP_COUNTERS,
						 fib, mp->client_index);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_UDP_ENCAP_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_want_bier_neighbor_stats_t_handler (vl_api_want_bier_neighbor_stats_t *
					   mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_bier_neighbor_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  vl_api_registration_t *reg;
  u32 fib;

  fib = ~0;			//Using same mechanism as _per_interface_
  rp.client_index = mp->client_index;
  rp.client_pid = mp->pid;

  handle_client_registration (&rp, IDX_BIER_NEIGHBOR_COUNTERS, fib,
			      mp->enable);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);

  if (!reg)
    {
      sm->enable_poller = clear_client_for_stat (IDX_BIER_NEIGHBOR_COUNTERS,
						 fib, mp->client_index);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_BIER_NEIGHBOR_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_want_stats_t_handler (vl_api_want_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  u32 item;
  vl_api_registration_t *reg;

  item = ~0;			//"ALL THE THINGS IN THE THINGS
  rp.client_index = mp->client_index;
  rp.client_pid = mp->pid;

  handle_client_registration (&rp, IDX_PER_INTERFACE_SIMPLE_COUNTERS,
			      item, mp->enable_disable);

  handle_client_registration (&rp, IDX_PER_INTERFACE_COMBINED_COUNTERS,
			      item, mp->enable_disable);

  handle_client_registration (&rp, IDX_IP4_FIB_COUNTERS,
			      item, mp->enable_disable);

  handle_client_registration (&rp, IDX_IP4_NBR_COUNTERS,
			      item, mp->enable_disable);

  handle_client_registration (&rp, IDX_IP6_FIB_COUNTERS,
			      item, mp->enable_disable);

  handle_client_registration (&rp, IDX_IP6_NBR_COUNTERS,
			      item, mp->enable_disable);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_want_interface_simple_stats_t_handler
  (vl_api_want_interface_simple_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_interface_simple_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  u32 swif;
  vl_api_registration_t *reg;

  swif = ~0;			//Using same mechanism as _per_interface_
  rp.client_index = mp->client_index;
  rp.client_pid = mp->pid;

  handle_client_registration (&rp, IDX_PER_INTERFACE_SIMPLE_COUNTERS, swif,
			      mp->enable_disable);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);

  if (!reg)
    {
      sm->enable_poller =
	clear_client_for_stat (IDX_PER_INTERFACE_SIMPLE_COUNTERS, swif,
			       mp->client_index);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_INTERFACE_SIMPLE_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}


static void
vl_api_want_ip4_fib_stats_t_handler (vl_api_want_ip4_fib_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_ip4_fib_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  vl_api_registration_t *reg;
  u32 fib;

  fib = ~0;			//Using same mechanism as _per_interface_
  rp.client_index = mp->client_index;
  rp.client_pid = mp->pid;

  handle_client_registration (&rp, IDX_IP4_FIB_COUNTERS, fib,
			      mp->enable_disable);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);

  if (!reg)
    {
      sm->enable_poller = clear_client_for_stat (IDX_IP4_FIB_COUNTERS,
						 fib, mp->client_index);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_IP4_FIB_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_want_ip4_mfib_stats_t_handler (vl_api_want_ip4_mfib_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_ip4_mfib_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  vl_api_registration_t *reg;
  u32 mfib;

  mfib = ~0;			//Using same mechanism as _per_interface_
  rp.client_index = mp->client_index;
  rp.client_pid = mp->pid;

  handle_client_registration (&rp, IDX_IP4_MFIB_COUNTERS, mfib,
			      mp->enable_disable);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      sm->enable_poller = clear_client_for_stat (IDX_IP4_MFIB_COUNTERS,
						 mfib, mp->client_index);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_IP4_MFIB_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_want_ip6_fib_stats_t_handler (vl_api_want_ip6_fib_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_ip4_fib_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  vl_api_registration_t *reg;
  u32 fib;

  fib = ~0;			//Using same mechanism as _per_interface_
  rp.client_index = mp->client_index;
  rp.client_pid = mp->pid;

  handle_client_registration (&rp, IDX_IP6_FIB_COUNTERS, fib,
			      mp->enable_disable);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      sm->enable_poller = clear_client_for_stat (IDX_IP6_FIB_COUNTERS,
						 fib, mp->client_index);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_IP6_FIB_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_want_ip6_mfib_stats_t_handler (vl_api_want_ip6_mfib_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_registration_t rp;
  vl_api_want_ip4_mfib_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  vl_api_registration_t *reg;
  u32 mfib;

  mfib = ~0;			//Using same mechanism as _per_interface_
  rp.client_index = mp->client_index;
  rp.client_pid = mp->pid;

  handle_client_registration (&rp, IDX_IP6_MFIB_COUNTERS, mfib,
			      mp->enable_disable);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      sm->enable_poller = clear_client_for_stat (IDX_IP6_MFIB_COUNTERS,
						 mfib, mp->client_index);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_IP6_MFIB_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* FIXME - NBR stats broken - this will be fixed in subsequent patch */
static void
vl_api_want_ip4_nbr_stats_t_handler (vl_api_want_ip4_nbr_stats_t * mp)
{
}

static void
vl_api_want_ip6_nbr_stats_t_handler (vl_api_want_ip6_nbr_stats_t * mp)
{
}

static void
vl_api_vnet_get_summary_stats_t_handler (vl_api_vnet_get_summary_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vnet_interface_main_t *im = sm->interface_main;
  vl_api_vnet_get_summary_stats_reply_t *rmp;
  vlib_combined_counter_main_t *cm;
  vlib_counter_t v;
  vnet_interface_counter_type_t ct;
  int i, which;
  u64 total_pkts[VNET_N_COMBINED_INTERFACE_COUNTER];
  u64 total_bytes[VNET_N_COMBINED_INTERFACE_COUNTER];
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_VNET_GET_SUMMARY_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = 0;

  clib_memset (total_pkts, 0, sizeof (total_pkts));
  clib_memset (total_bytes, 0, sizeof (total_bytes));

  vnet_interface_counter_lock (im);

  vec_foreach (cm, im->combined_sw_if_counters)
  {
    which = cm - im->combined_sw_if_counters;

    for (i = 0; i < vlib_combined_counter_n_counters (cm); i++)
      {
	vlib_get_combined_counter (cm, i, &v);
	total_pkts[which] += v.packets;
	total_bytes[which] += v.bytes;
      }
  }
  vnet_interface_counter_unlock (im);

  foreach_rx_combined_interface_counter (ct)
  {
    rmp->total_pkts[ct] = clib_host_to_net_u64 (total_pkts[ct]);
    rmp->total_bytes[ct] = clib_host_to_net_u64 (total_bytes[ct]);
  }

  foreach_tx_combined_interface_counter (ct)
  {
    rmp->total_pkts[ct] = clib_host_to_net_u64 (total_pkts[ct]);
    rmp->total_bytes[ct] = clib_host_to_net_u64 (total_bytes[ct]);
  }
  rmp->vector_rate =
    clib_host_to_net_u64 (vlib_last_vector_length_per_node (sm->vlib_main));

  vl_api_send_msg (reg, (u8 *) rmp);
}

int
stats_memclnt_delete_callback (u32 client_index)
{
  vpe_client_stats_registration_t *rp;
  stats_main_t *sm = &stats_main;
  uword *p;

  // FIXME
  /* p = hash_get (sm->stats_registration_hash, client_index); */
  /* if (p) */
  /*   { */
  /*     rp = pool_elt_at_index (sm->stats_registrations, p[0]); */
  /*     pool_put (sm->stats_registrations, rp); */
  /*     hash_unset (sm->stats_registration_hash, client_index); */
  /*   } */

  return 0;
}

#define vl_api_vnet_interface_simple_counters_t_endian vl_noop_handler
#define vl_api_vnet_interface_simple_counters_t_print vl_noop_handler
#define vl_api_vnet_interface_combined_counters_t_endian vl_noop_handler
#define vl_api_vnet_interface_combined_counters_t_print vl_noop_handler
#define vl_api_vnet_ip4_fib_counters_t_endian vl_noop_handler
#define vl_api_vnet_ip4_fib_counters_t_print vl_noop_handler
#define vl_api_vnet_ip6_fib_counters_t_endian vl_noop_handler
#define vl_api_vnet_ip6_fib_counters_t_print vl_noop_handler
#define vl_api_vnet_ip4_nbr_counters_t_endian vl_noop_handler
#define vl_api_vnet_ip4_nbr_counters_t_print vl_noop_handler
#define vl_api_vnet_ip6_nbr_counters_t_endian vl_noop_handler
#define vl_api_vnet_ip6_nbr_counters_t_print vl_noop_handler

static clib_error_t *
stats_init (vlib_main_t * vm)
{
  stats_main_t *sm = &stats_main;
  api_main_t *am = &api_main;
  void *vlib_worker_thread_bootstrap_fn (void *arg);

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();
  sm->interface_main = &vnet_get_main ()->interface_main;
  sm->api_main = am;
  sm->stats_poll_interval_in_seconds = 10;
  sm->data_structure_lock =
    clib_mem_alloc_aligned (sizeof (data_structure_lock_t),
			    CLIB_CACHE_LINE_BYTES);
  clib_memset (sm->data_structure_lock, 0, sizeof (*sm->data_structure_lock));

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 0 /* do NOT trace! */);
  foreach_stats_msg;
#undef _

  /* tell the msg infra not to free these messages... */
  am->message_bounce[VL_API_VNET_INTERFACE_SIMPLE_COUNTERS] = 1;
  am->message_bounce[VL_API_VNET_INTERFACE_COMBINED_COUNTERS] = 1;
  am->message_bounce[VL_API_VNET_IP4_FIB_COUNTERS] = 1;
  am->message_bounce[VL_API_VNET_IP6_FIB_COUNTERS] = 1;
  am->message_bounce[VL_API_VNET_IP4_NBR_COUNTERS] = 1;
  am->message_bounce[VL_API_VNET_IP6_NBR_COUNTERS] = 1;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  vec_validate (sm->stats_registrations, STATS_REG_N_IDX);
  vec_validate (sm->stats_registration_hash, STATS_REG_N_IDX);
#define stats_reg(n)                            \
  sm->stats_registrations[IDX_##n] = 0; \
  sm->stats_registration_hash[IDX_##n] = 0;
#include <vpp/stats/stats.reg>
#undef stats_reg

  return 0;
}

VLIB_INIT_FUNCTION (stats_init);

/* *INDENT-OFF* */
VLIB_REGISTER_THREAD (stats_thread_reg, static) = {
  .name = "stats",
  .function = stats_thread_fn,
  .fixed_count = 1,
  .count = 1,
  .no_data_structure_clone = 1,
  .use_pthreads = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
