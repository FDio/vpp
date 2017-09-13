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
#include <vpp/stats/stats.h>
#include <signal.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/dpo/load_balance.h>

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
_(WANT_INTERFACE_SIMPLE_STATS, want_interface_simple_stats)	\
_(VNET_INTERFACE_COMBINED_COUNTERS, vnet_interface_combined_counters)	\
_(WANT_INTERFACE_COMBINED_STATS, want_interface_combined_stats)	\
_(VNET_IP4_FIB_COUNTERS, vnet_ip4_fib_counters)				\
_(WANT_IP4_FIB_STATS, want_ip4_fib_stats)            \
_(VNET_IP6_FIB_COUNTERS, vnet_ip6_fib_counters)				\
_(WANT_IP6_FIB_STATS, want_ip6_fib_stats)        \
_(VNET_IP4_NBR_COUNTERS, vnet_ip4_nbr_counters)				\
_(WANT_IP4_NBR_STATS, want_ip4_nbr_stats)            \
_(VNET_IP6_NBR_COUNTERS, vnet_ip6_nbr_counters) \
_(WANT_IP6_NBR_STATS, want_ip6_nbr_stats) \
_(VNET_GET_SUMMARY_STATS, vnet_get_summary_stats)


/* These constants ensure msg sizes <= 1024, aka ring allocation */
#define SIMPLE_COUNTER_BATCH_SIZE	126
#define COMBINED_COUNTER_BATCH_SIZE	63
#define IP4_FIB_COUNTER_BATCH_SIZE	48
#define IP6_FIB_COUNTER_BATCH_SIZE	30

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

void
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

  while (__sync_lock_test_and_set (&l->lock, 1))
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

void
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

static void
do_simple_interface_counters (stats_main_t * sm)
{
  vl_api_vnet_interface_simple_counters_t *mp = 0;
  vnet_interface_main_t *im = sm->interface_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  unix_shared_memory_queue_t *q = shmem_hdr->vl_input_queue;
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

static void
do_combined_interface_counters (stats_main_t * sm)
{
  vl_api_vnet_interface_combined_counters_t *mp = 0;
  vnet_interface_main_t *im = sm->interface_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  unix_shared_memory_queue_t *q = shmem_hdr->vl_input_queue;
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
ip4_nbr_ship (stats_main_t * sm, ip4_nbr_stats_ctx_t * ctx)
{
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  unix_shared_memory_queue_t *q = shmem_hdr->vl_input_queue;
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
      unix_shared_memory_queue_lock (q);
      pause = unix_shared_memory_queue_is_full (q);

      vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
      unix_shared_memory_queue_unlock (q);
      dsunlock (sm);

      if (pause)
	ip46_fib_stats_delay (sm, 0 /* sec */ ,
			      STATS_RELEASE_DELAY_NS);
    }
}

static void
do_ip4_nbrs (stats_main_t * sm)
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
  unix_shared_memory_queue_t *q = shmem_hdr->vl_input_queue;
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
      unix_shared_memory_queue_lock (q);
      pause = unix_shared_memory_queue_is_full (q);

      vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
      unix_shared_memory_queue_unlock (q);
      dsunlock (sm);

      if (pause)
        ip46_fib_stats_delay (sm, 0 /* sec */ ,
                              STATS_RELEASE_DELAY_NS);
    }
}

static void
do_ip6_nbrs (stats_main_t * sm)
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
do_ip4_fibs (stats_main_t * sm)
{
  ip4_main_t *im4 = &ip4_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  unix_shared_memory_queue_t *q = shmem_hdr->vl_input_queue;
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
		unix_shared_memory_queue_lock (q);
		if (unix_shared_memory_queue_is_full (q))
		  {
		    dsunlock (sm);
		    vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		    unix_shared_memory_queue_unlock (q);
		    mp = 0;
		    ip46_fib_stats_delay (sm, 0 /* sec */ ,
					  STATS_RELEASE_DELAY_NS);
		    goto again;
		  }
		vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		unix_shared_memory_queue_unlock (q);

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
do_ip6_fibs (stats_main_t * sm)
{
  ip6_main_t *im6 = &ip6_main;
  api_main_t *am = sm->api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  unix_shared_memory_queue_t *q = shmem_hdr->vl_input_queue;
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
		unix_shared_memory_queue_lock (q);
		if (unix_shared_memory_queue_is_full (q))
		  {
		    dsunlock (sm);
		    vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		    unix_shared_memory_queue_unlock (q);
		    mp = 0;
		    ip46_fib_stats_delay (sm, 0 /* sec */ ,
					  STATS_RELEASE_DELAY_NS);
		    goto again;
		  }
		vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);
		unix_shared_memory_queue_unlock (q);

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

  if (vec_len (tm->thread_prefix))
    vlib_set_thread_name ((char *)
			  format (0, "%v_stats%c", tm->thread_prefix, '\0'));

  clib_mem_set_heap (w->thread_mheap);

  while (1)
    {
      /* 10 second poll interval */
      ip46_fib_stats_delay (sm, 10 /* secs */ , 0 /* nsec */ );

      if (!(sm->enable_poller))
	continue;
      do_simple_interface_counters (sm);
      do_combined_interface_counters (sm);
      do_ip4_fibs (sm);
      do_ip6_fibs (sm);
      do_ip4_nbrs (sm);
      do_ip6_nbrs (sm);
    }
}

static void
  vl_api_vnet_interface_simple_counters_t_handler
  (vl_api_vnet_interface_simple_counters_t * mp)
{
  vpe_client_stats_registration_t *reg;
  stats_main_t *sm = &stats_main;
  unix_shared_memory_queue_t *q, *q_prev = NULL;
  vl_api_vnet_interface_simple_counters_t *mp_copy = NULL;
  u32 mp_size;
  int i;

  mp_size = sizeof (*mp) + (ntohl (mp->count) * sizeof (u64));

  /* *INDENT-OFF* */
  vec_reset_length(sm->regs);
  pool_foreach(reg, sm->stats_registrations,
	       ({
             vec_add1(sm->regs,reg);
	       }));
  /* *INDENT-ON* */
  for (i = 0; i < vec_len (sm->regs); i++)
    {
      reg = sm->regs[i];
      if (reg->stats_registrations & INTERFACE_SIMPLE_COUNTERS)
	{
	  q = vl_api_client_index_to_input_queue (reg->client.client_index);
	  if (q)
	    {
	      if (q_prev && (q_prev->cursize < q_prev->maxsize))
		{
		  mp_copy = vl_msg_api_alloc_as_if_client (mp_size);
		  clib_memcpy (mp_copy, mp, mp_size);
		  vl_msg_api_send_shmem (q_prev, (u8 *) & mp);
		  mp = mp_copy;
		}
	      q_prev = q;
	    }
	}
    }
#if STATS_DEBUG > 0
  fformat (stdout, "%U\n", format_vnet_simple_counters, mp);
#endif

  if (q_prev && (q_prev->cursize < q_prev->maxsize))
    {
      vl_msg_api_send_shmem (q_prev, (u8 *) & mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
  vl_api_vnet_interface_combined_counters_t_handler
  (vl_api_vnet_interface_combined_counters_t * mp)
{
  vpe_client_stats_registration_t *reg;
  stats_main_t *sm = &stats_main;
  unix_shared_memory_queue_t *q, *q_prev = NULL;
  vl_api_vnet_interface_combined_counters_t *mp_copy = NULL;
  u32 mp_size;

  mp_size = sizeof (*mp) + (ntohl (mp->count) * sizeof (vlib_counter_t));

  /* *INDENT-OFF* */
  pool_foreach(reg, sm->stats_registrations,
	       ({
             if (reg->stats_registrations & INTERFACE_COMBINED_COUNTERS)
               {
                 q = vl_api_client_index_to_input_queue (reg->client.client_index);
                 if (q)
                   {
                     if (q_prev && (q_prev->cursize < q_prev->maxsize))
                       {
                         mp_copy = vl_msg_api_alloc_as_if_client(mp_size);
                         clib_memcpy(mp_copy, mp, mp_size);
                         vl_msg_api_send_shmem (q_prev, (u8 *)&mp);
                         mp = mp_copy;
                       }
                     q_prev = q;
                   }
               }
	       }));
  /* *INDENT-ON* */

#if STATS_DEBUG > 0
  fformat (stdout, "%U\n", format_vnet_combined_counters, mp);
#endif

  if (q_prev && (q_prev->cursize < q_prev->maxsize))
    {
      vl_msg_api_send_shmem (q_prev, (u8 *) & mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_vnet_ip4_fib_counters_t_handler (vl_api_vnet_ip4_fib_counters_t * mp)
{
  vpe_client_stats_registration_t *reg;
  stats_main_t *sm = &stats_main;
  unix_shared_memory_queue_t *q, *q_prev = NULL;
  vl_api_vnet_ip4_fib_counters_t *mp_copy = NULL;
  u32 mp_size;

  mp_size = sizeof (*mp_copy) +
    ntohl (mp->count) * sizeof (vl_api_ip4_fib_counter_t);

  /* *INDENT-OFF* */
  pool_foreach(reg, sm->stats_registrations,
  ({
    if (reg->stats_registrations & IP4_FIB_COUNTERS)
      {
        q = vl_api_client_index_to_input_queue (reg->client.client_index);
        if (q)
          {
            if (q_prev && (q_prev->cursize < q_prev->maxsize))
              {
                mp_copy = vl_msg_api_alloc_as_if_client(mp_size);
                clib_memcpy(mp_copy, mp, mp_size);
                vl_msg_api_send_shmem (q_prev, (u8 *)&mp);
                mp = mp_copy;
              }
            q_prev = q;
          }
      }
  }));
  /* *INDENT-ON* */
  if (q_prev && (q_prev->cursize < q_prev->maxsize))
    {
      vl_msg_api_send_shmem (q_prev, (u8 *) & mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_vnet_ip4_nbr_counters_t_handler (vl_api_vnet_ip4_nbr_counters_t * mp)
{
  vpe_client_stats_registration_t *reg;
  stats_main_t *sm = &stats_main;
  unix_shared_memory_queue_t *q, *q_prev = NULL;
  vl_api_vnet_ip4_nbr_counters_t *mp_copy = NULL;
  u32 mp_size;

  mp_size = sizeof (*mp_copy) +
    ntohl (mp->count) * sizeof (vl_api_ip4_nbr_counter_t);

  /* *INDENT-OFF* */
  pool_foreach(reg, sm->stats_registrations,
  ({
    if (reg->stats_registrations & IP4_NBR_COUNTERS)
      {
        q = vl_api_client_index_to_input_queue (reg->client.client_index);
        if (q)
          {
            if (q_prev && (q_prev->cursize < q_prev->maxsize))
              {
                mp_copy = vl_msg_api_alloc_as_if_client(mp_size);
                clib_memcpy(mp_copy, mp, mp_size);
                vl_msg_api_send_shmem (q_prev, (u8 *)&mp);
                mp = mp_copy;
              }
            q_prev = q;
          }
      }
  }));
  /* *INDENT-ON* */
  if (q_prev && (q_prev->cursize < q_prev->maxsize))
    {
      vl_msg_api_send_shmem (q_prev, (u8 *) & mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_vnet_ip6_fib_counters_t_handler (vl_api_vnet_ip6_fib_counters_t * mp)
{
  vpe_client_stats_registration_t *reg;
  stats_main_t *sm = &stats_main;
  unix_shared_memory_queue_t *q, *q_prev = NULL;
  vl_api_vnet_ip6_fib_counters_t *mp_copy = NULL;
  u32 mp_size;

  mp_size = sizeof (*mp_copy) +
    ntohl (mp->count) * sizeof (vl_api_ip6_fib_counter_t);

  /* *INDENT-OFF* */
  pool_foreach(reg, sm->stats_registrations,
  ({
    if (reg->stats_registrations & IP6_FIB_COUNTERS)
      {
        q = vl_api_client_index_to_input_queue (reg->client.client_index);
        if (q)
          {
            if (q_prev && (q_prev->cursize < q_prev->maxsize))
              {
                mp_copy = vl_msg_api_alloc_as_if_client(mp_size);
                clib_memcpy(mp_copy, mp, mp_size);
                vl_msg_api_send_shmem (q_prev, (u8 *)&mp);
                mp = mp_copy;
              }
            q_prev = q;
          }
      }
      }));
  /* *INDENT-ON* */
  if (q_prev && (q_prev->cursize < q_prev->maxsize))
    {
      vl_msg_api_send_shmem (q_prev, (u8 *) & mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_vnet_ip6_nbr_counters_t_handler (vl_api_vnet_ip6_nbr_counters_t * mp)
{
  vpe_client_stats_registration_t *reg;
  stats_main_t *sm = &stats_main;
  unix_shared_memory_queue_t *q, *q_prev = NULL;
  vl_api_vnet_ip6_nbr_counters_t *mp_copy = NULL;
  u32 mp_size;

  mp_size = sizeof (*mp_copy) +
    ntohl (mp->count) * sizeof (vl_api_ip6_nbr_counter_t);

  /* *INDENT-OFF* */
  pool_foreach(reg, sm->stats_registrations,
  ({
    if (reg->stats_registrations & IP6_NBR_COUNTERS)
      {
        q = vl_api_client_index_to_input_queue (reg->client.client_index);
        if (q)
          {
            if (q_prev && (q_prev->cursize < q_prev->maxsize))
              {
                mp_copy = vl_msg_api_alloc_as_if_client(mp_size);
                clib_memcpy(mp_copy, mp, mp_size);
                vl_msg_api_send_shmem (q_prev, (u8 *)&mp);
                mp = mp_copy;
              }
            q_prev = q;
          }
      }
  }));
  /* *INDENT-ON* */
  if (q_prev && (q_prev->cursize < q_prev->maxsize))
    {
      vl_msg_api_send_shmem (q_prev, (u8 *) & mp);
    }
  else
    {
      vl_msg_api_free (mp);
    }
}

static void
vl_api_want_stats_t_handler (vl_api_want_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_stats_registration_t *rp;
  vl_api_want_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  unix_shared_memory_queue_t *q;

  p = hash_get (sm->stats_registration_hash, mp->client_index);
  if (p)
    {
      if (mp->enable_disable)
	{
	  clib_warning ("pid %d: already enabled...", mp->pid);
	  retval = -2;
	  goto reply;
	}
      else
	{
	  rp = pool_elt_at_index (sm->stats_registrations, p[0]);
	  pool_put (sm->stats_registrations, rp);
	  hash_unset (sm->stats_registration_hash, mp->client_index);
	  goto reply;
	}
    }
  if (mp->enable_disable == 0)
    {
      clib_warning ("pid %d: already disabled...", mp->pid);
      retval = -3;
      goto reply;
    }
  pool_get (sm->stats_registrations, rp);
  rp->client.client_index = mp->client_index;
  rp->client.client_pid = mp->pid;
  rp->stats_registrations |= INTERFACE_SIMPLE_COUNTERS;
  rp->stats_registrations |= INTERFACE_COMBINED_COUNTERS;
  rp->stats_registrations |= IP4_FIB_COUNTERS;
  rp->stats_registrations |= IP4_NBR_COUNTERS;
  rp->stats_registrations |= IP6_FIB_COUNTERS;
  rp->stats_registrations |= IP6_NBR_COUNTERS;

  hash_set (sm->stats_registration_hash, rp->client.client_index,
	    rp - sm->stats_registrations);

reply:
  if (pool_elts (sm->stats_registrations))
    sm->enable_poller = 1;
  else
    sm->enable_poller = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_want_interface_simple_stats_t_handler
  (vl_api_want_interface_simple_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_stats_registration_t *rp;
  vl_api_want_interface_simple_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  unix_shared_memory_queue_t *q;

  p = hash_get (sm->stats_registration_hash, mp->client_index);

  /* Disable case */
  if (mp->enable_disable == 0)
    {
      if (!p)			// No client to disable
	{
	  clib_warning ("pid %d: already disabled for stats...", mp->pid);
	  retval = 0;
	  goto reply;
	}

      rp = pool_elt_at_index (sm->stats_registrations, p[0]);
      if (!rp->stats_registrations & INTERFACE_SIMPLE_COUNTERS)	// Client but doesn't want this.
	{
	  clib_warning
	    ("pid %d: already disabled for interface simple stats...",
	     mp->pid);
	  retval = 0;
	  goto reply;
	}
      else
	{
	  rp->stats_registrations &= ~(INTERFACE_SIMPLE_COUNTERS);	// Clear flag
	  if (rp->stats_registrations == 0)	// Client isn't listening to anything else
	    {
	      pool_put (sm->stats_registrations, rp);
	      hash_unset (sm->stats_registration_hash, mp->client_index);
	    }
	  goto reply;
	}
    }
  /* Enable case */
  /* Get client from pool */
  if (p)
    rp = pool_elt_at_index (sm->stats_registrations, p[0]);

  if (!p || !rp)		// Doesn't exist, make a new entry
    {
      pool_get (sm->stats_registrations, rp);
      rp->client.client_index = mp->client_index;
      rp->client.client_pid = mp->pid;
    }
  rp->stats_registrations |= INTERFACE_SIMPLE_COUNTERS;
  hash_set (sm->stats_registration_hash, rp->client.client_index,
	    rp - sm->stats_registrations);

reply:
  if (pool_elts (sm->stats_registrations))	// Someone wants something, somewhere so enable globally for now.
    sm->enable_poller = 1;
  else
    sm->enable_poller = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_INTERFACE_SIMPLE_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_want_interface_combined_stats_t_handler
  (vl_api_want_interface_combined_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_stats_registration_t *rp;
  vl_api_want_interface_combined_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  unix_shared_memory_queue_t *q;

  p = hash_get (sm->stats_registration_hash, mp->client_index);

  /* Disable case */
  if (mp->enable_disable == 0)
    {
      if (!p)			// No client to disable
	{
	  clib_warning ("pid %d: already disabled for stats...", mp->pid);
	  retval = 0;
	  goto reply;
	}

      rp = pool_elt_at_index (sm->stats_registrations, p[0]);
      if (!(rp->stats_registrations & INTERFACE_COMBINED_COUNTERS))	// Client but doesn't want this.
	{
	  clib_warning
	    ("pid %d: already disabled for interface COMBINED stats...",
	     mp->pid);
	  retval = 0;
	  goto reply;
	}
      else
	{
	  rp->stats_registrations &= ~(INTERFACE_COMBINED_COUNTERS);	// Clear flag
	  if (rp->stats_registrations == 0)	// Client isn't listening to anything else
	    {
	      pool_put (sm->stats_registrations, rp);
	      hash_unset (sm->stats_registration_hash, mp->client_index);
	    }
	  goto reply;
	}
    }
  /* Enable case */
  /* Get client from pool */
  if (p)
    rp = pool_elt_at_index (sm->stats_registrations, p[0]);

  if (!p || !rp)		// Doesn't exist, make a new entry
    {
      pool_get (sm->stats_registrations, rp);
      rp->client.client_index = mp->client_index;
      rp->client.client_pid = mp->pid;
    }
  rp->stats_registrations |= INTERFACE_COMBINED_COUNTERS;
  hash_set (sm->stats_registration_hash, rp->client.client_index,
	    rp - sm->stats_registrations);

reply:
  if (pool_elts (sm->stats_registrations))	// Someone wants something, somewhere so enable globally for now.
    sm->enable_poller = 1;
  else
    sm->enable_poller = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_INTERFACE_COMBINED_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_want_ip4_fib_stats_t_handler (vl_api_want_ip4_fib_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_stats_registration_t *rp;
  vl_api_want_ip4_fib_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  unix_shared_memory_queue_t *q;

  p = hash_get (sm->stats_registration_hash, mp->client_index);

  /* Disable case */
  /*
     $$$ FIXME: need std return codes. Still undecided if enabling already
     enabled (and similar for disabled) is really a -'ve error condition or
     if 0 is sufficient
   */
  if (mp->enable_disable == 0)
    {
      if (!p)			// No client to disable
	{
	  clib_warning ("pid %d: already disabled for stats...", mp->pid);
	  retval = -3;
	  goto reply;
	}

      rp = pool_elt_at_index (sm->stats_registrations, p[0]);
      if (!(rp->stats_registrations & IP4_FIB_COUNTERS))	// Client but doesn't want this.
	{
	  clib_warning ("pid %d: already disabled for interface ip4 fib...",
			mp->pid);
	  retval = -2;
	  goto reply;
	}
      else
	{
	  rp->stats_registrations &= ~(IP4_FIB_COUNTERS);	// Clear flag
	  if (rp->stats_registrations == 0)	// Client isn't listening to anything else
	    {
	      pool_put (sm->stats_registrations, rp);
	      hash_unset (sm->stats_registration_hash, mp->client_index);
	    }
	  goto reply;
	}
    }
  /* Enable case */
  /* Get client from pool */
  if (p)
    rp = pool_elt_at_index (sm->stats_registrations, p[0]);

  if (!p || !rp)		// Doesn't exist, make a new entry
    {
      pool_get (sm->stats_registrations, rp);
      rp->client.client_index = mp->client_index;
      rp->client.client_pid = mp->pid;
    }
  rp->stats_registrations |= IP4_FIB_COUNTERS;
  hash_set (sm->stats_registration_hash, rp->client.client_index,
	    rp - sm->stats_registrations);

reply:
  if (pool_elts (sm->stats_registrations))	// Someone wants something, somewhere so enable globally for now.
    sm->enable_poller = 1;
  else
    sm->enable_poller = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_IP4_FIB_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_want_ip6_fib_stats_t_handler (vl_api_want_ip6_fib_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vpe_client_stats_registration_t *rp;
  vl_api_want_ip6_fib_stats_reply_t *rmp;
  uword *p;
  i32 retval = 0;
  unix_shared_memory_queue_t *q;

  p = hash_get (sm->stats_registration_hash, mp->client_index);

  /* Disable case */
  /*
     $$$ FIXME: need std return codes. Still undecided if enabling already
     enabled (and similar for disabled) is really a -'ve error condition or
     if 0 is sufficient
   */
  if (mp->enable_disable == 0)
    {
      if (!p)			// No client to disable
	{
	  clib_warning ("pid %d: already disabled for stats...", mp->pid);
	  retval = -3;
	  goto reply;
	}

      rp = pool_elt_at_index (sm->stats_registrations, p[0]);
      if (!(rp->stats_registrations & IP6_FIB_COUNTERS))	// Client but doesn't want this.
	{
	  clib_warning ("pid %d: already disabled for interface ip6 fib...",
			mp->pid);
	  retval = -2;
	  goto reply;
	}
      else
	{
	  rp->stats_registrations &= ~(IP6_FIB_COUNTERS);	// Clear flag
	  if (rp->stats_registrations == 0)	// Client isn't listening to anything else
	    {
	      pool_put (sm->stats_registrations, rp);
	      hash_unset (sm->stats_registration_hash, mp->client_index);
	    }
	  goto reply;
	}
    }
  /* Enable case */
  /* Get client from pool */
  if (p)
    rp = pool_elt_at_index (sm->stats_registrations, p[0]);

  if (!p || !rp)		// Doesn't exist, make a new entry
    {
      pool_get (sm->stats_registrations, rp);
      rp->client.client_index = mp->client_index;
      rp->client.client_pid = mp->pid;
    }
  rp->stats_registrations |= IP6_FIB_COUNTERS;
  hash_set (sm->stats_registration_hash, rp->client.client_index,
	    rp - sm->stats_registrations);

reply:
  if (pool_elts (sm->stats_registrations))	// Someone wants something, somewhere so enable globally for now.
    sm->enable_poller = 1;
  else
    sm->enable_poller = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_WANT_IP6_FIB_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = retval;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
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
  int i, which;
  u64 total_pkts[VLIB_N_RX_TX];
  u64 total_bytes[VLIB_N_RX_TX];

  unix_shared_memory_queue_t *q =
    vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_VNET_GET_SUMMARY_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = 0;

  memset (total_pkts, 0, sizeof (total_pkts));
  memset (total_bytes, 0, sizeof (total_bytes));

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

  rmp->total_pkts[VLIB_RX] = clib_host_to_net_u64 (total_pkts[VLIB_RX]);
  rmp->total_bytes[VLIB_RX] = clib_host_to_net_u64 (total_bytes[VLIB_RX]);
  rmp->total_pkts[VLIB_TX] = clib_host_to_net_u64 (total_pkts[VLIB_TX]);
  rmp->total_bytes[VLIB_TX] = clib_host_to_net_u64 (total_bytes[VLIB_TX]);
  rmp->vector_rate =
    clib_host_to_net_u64 (vlib_last_vector_length_per_node (sm->vlib_main));

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

int
stats_memclnt_delete_callback (u32 client_index)
{
  vpe_client_stats_registration_t *rp;
  stats_main_t *sm = &stats_main;
  uword *p;

  p = hash_get (sm->stats_registration_hash, client_index);
  if (p)
    {
      rp = pool_elt_at_index (sm->stats_registrations, p[0]);
      pool_put (sm->stats_registrations, rp);
      hash_unset (sm->stats_registration_hash, client_index);
    }

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
  memset (sm->data_structure_lock, 0, sizeof (*sm->data_structure_lock));

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
