/*
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>

#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <dpdk/device/dpdk.h>

#include <vlib/pci/pci.h>
#include <vlibmemory/api.h>
#include <vlibmemory/vl_memory_msg_enum.h>	/* enumerate all vlib messages */

#define vl_typedefs		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

#include <dpdk/device/dpdk_priv.h>

/***
 *
 * HQoS default configuration values
 *
 ***/

static dpdk_device_config_hqos_t hqos_params_default = {
  .hqos_thread_valid = 0,

  .swq_size = 4096,
  .burst_enq = 256,
  .burst_deq = 220,

  /*
   * Packet field to identify the subport.
   *
   * Default value: Since only one subport is defined by default (see below:
   *     n_subports_per_port = 1), the subport ID is hardcoded to 0.
   */
  .pktfield0_slabpos = 0,
  .pktfield0_slabmask = 0,

  /*
   * Packet field to identify the pipe.
   *
   * Default value: Assuming Ethernet/IPv4/UDP packets, UDP payload bits 12 .. 23
   */
  .pktfield1_slabpos = 40,
  .pktfield1_slabmask = 0x0000000FFF000000LLU,

  /* Packet field used as index into TC translation table to identify the traffic
   *     class and queue.
   *
   * Default value: Assuming Ethernet/IPv4 packets, IPv4 DSCP field
   */
  .pktfield2_slabpos = 8,
  .pktfield2_slabmask = 0x00000000000000FCLLU,
  .tc_table = {
	       0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	       0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	       0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	       0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	       },

  /* port */
  .port = {
	   .name = NULL,	/* Set at init */
	   .socket = 0,		/* Set at init */
	   .rate = 1250000000,	/* Assuming 10GbE port */
	   .mtu = 14 + 1500,	/* Assuming Ethernet/IPv4 pkt (Ethernet FCS not included) */
	   .frame_overhead = RTE_SCHED_FRAME_OVERHEAD_DEFAULT,
	   .n_subports_per_port = 1,
	   .n_pipes_per_subport = 4096,
	   .qsize = {64, 64, 64, 64},
	   .pipe_profiles = NULL,	/* Set at config */
	   .n_pipe_profiles = 1,

#ifdef RTE_SCHED_RED
	   .red_params = {
			  /* Traffic Class 0 Colors Green / Yellow / Red */
			  [0][0] = {.min_th = 48,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},
			  [0][1] = {.min_th = 40,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},
			  [0][2] = {.min_th = 32,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},

			  /* Traffic Class 1 - Colors Green / Yellow / Red */
			  [1][0] = {.min_th = 48,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},
			  [1][1] = {.min_th = 40,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},
			  [1][2] = {.min_th = 32,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},

			  /* Traffic Class 2 - Colors Green / Yellow / Red */
			  [2][0] = {.min_th = 48,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},
			  [2][1] = {.min_th = 40,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},
			  [2][2] = {.min_th = 32,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},

			  /* Traffic Class 3 - Colors Green / Yellow / Red */
			  [3][0] = {.min_th = 48,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},
			  [3][1] = {.min_th = 40,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9},
			  [3][2] = {.min_th = 32,.max_th = 64,.maxp_inv =
				    10,.wq_log2 = 9}
			  },
#endif /* RTE_SCHED_RED */
	   },
};

static struct rte_sched_subport_params hqos_subport_params_default = {
  .tb_rate = 1250000000,	/* 10GbE line rate (measured in bytes/second) */
  .tb_size = 1000000,
  .tc_rate = {1250000000, 1250000000, 1250000000, 1250000000},
  .tc_period = 10,
};

static struct rte_sched_pipe_params hqos_pipe_params_default = {
  .tb_rate = 305175,		/* 10GbE line rate divided by 4K pipes */
  .tb_size = 1000000,
  .tc_rate = {305175, 305175, 305175, 305175},
  .tc_period = 40,
#ifdef RTE_SCHED_SUBPORT_TC_OV
  .tc_ov_weight = 1,
#endif
  .wrr_weights = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
};

/***
 *
 * HQoS configuration
 *
 ***/

int
dpdk_hqos_validate_mask (u64 mask, u32 n)
{
  int count = __builtin_popcountll (mask);
  int pos_lead = sizeof (u64) * 8 - __builtin_clzll (mask);
  int pos_trail = __builtin_ctzll (mask);
  int count_expected = __builtin_popcount (n - 1);

  /* Handle the exceptions */
  if (n == 0)
    return -1;			/* Error */

  if ((mask == 0) && (n == 1))
    return 0;			/* OK */

  if (((mask == 0) && (n != 1)) || ((mask != 0) && (n == 1)))
    return -2;			/* Error */

  /* Check that mask is contiguous */
  if ((pos_lead - pos_trail) != count)
    return -3;			/* Error */

  /* Check that mask contains the expected number of bits set */
  if (count != count_expected)
    return -4;			/* Error */

  return 0;			/* OK */
}

void
dpdk_device_config_hqos_pipe_profile_default (dpdk_device_config_hqos_t *
					      hqos, u32 pipe_profile_id)
{
  memcpy (&hqos->pipe[pipe_profile_id], &hqos_pipe_params_default,
	  sizeof (hqos_pipe_params_default));
}

void
dpdk_device_config_hqos_default (dpdk_device_config_hqos_t * hqos)
{
  struct rte_sched_subport_params *subport_params;
  struct rte_sched_pipe_params *pipe_params;
  u32 *pipe_map;
  u32 i;

  memcpy (hqos, &hqos_params_default, sizeof (hqos_params_default));

  /* pipe */
  vec_add2 (hqos->pipe, pipe_params, hqos->port.n_pipe_profiles);

  for (i = 0; i < vec_len (hqos->pipe); i++)
    memcpy (&pipe_params[i],
	    &hqos_pipe_params_default, sizeof (hqos_pipe_params_default));

  hqos->port.pipe_profiles = hqos->pipe;

  /* subport */
  vec_add2 (hqos->subport, subport_params, hqos->port.n_subports_per_port);

  for (i = 0; i < vec_len (hqos->subport); i++)
    memcpy (&subport_params[i],
	    &hqos_subport_params_default,
	    sizeof (hqos_subport_params_default));

  /* pipe profile */
  vec_add2 (hqos->pipe_map,
	    pipe_map,
	    hqos->port.n_subports_per_port * hqos->port.n_pipes_per_subport);

  for (i = 0; i < vec_len (hqos->pipe_map); i++)
    pipe_map[i] = 0;
}

/***
 *
 * HQoS init
 *
 ***/

clib_error_t *
dpdk_port_setup_hqos (dpdk_device_t * xd, dpdk_device_config_hqos_t * hqos)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  char name[32];
  u32 subport_id, i;
  int rv;

  /* Detect the set of worker threads */
  int worker_thread_first = 0;
  int worker_thread_count = 0;

  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  vlib_thread_registration_t *tr =
    p ? (vlib_thread_registration_t *) p[0] : 0;

  if (tr && tr->count > 0)
    {
      worker_thread_first = tr->first_index;
      worker_thread_count = tr->count;
    }

  /* Allocate the per-thread device data array */
  vec_validate_aligned (xd->hqos_wt, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  memset (xd->hqos_wt, 0, tm->n_vlib_mains * sizeof (xd->hqos_wt[0]));

  vec_validate_aligned (xd->hqos_ht, 0, CLIB_CACHE_LINE_BYTES);
  memset (xd->hqos_ht, 0, sizeof (xd->hqos_ht[0]));

  /* Allocate space for one SWQ per worker thread in the I/O TX thread data structure */
  vec_validate (xd->hqos_ht->swq, worker_thread_count);

  /* SWQ */
  for (i = 0; i < worker_thread_count + 1; i++)
    {
      u32 swq_flags = RING_F_SP_ENQ | RING_F_SC_DEQ;

      snprintf (name, sizeof (name), "SWQ-worker%u-to-device%u", i,
		xd->device_index);
      xd->hqos_ht->swq[i] =
	rte_ring_create (name, hqos->swq_size, xd->cpu_socket, swq_flags);
      if (xd->hqos_ht->swq[i] == NULL)
	return clib_error_return (0,
				  "SWQ-worker%u-to-device%u: rte_ring_create err",
				  i, xd->device_index);
    }

  /*
   * HQoS
   */

  /* HQoS port */
  snprintf (name, sizeof (name), "HQoS%u", xd->device_index);
  hqos->port.name = strdup (name);
  if (hqos->port.name == NULL)
    return clib_error_return (0, "HQoS%u: strdup err", xd->device_index);

  hqos->port.socket = rte_eth_dev_socket_id (xd->device_index);
  if (hqos->port.socket == SOCKET_ID_ANY)
    hqos->port.socket = 0;

  xd->hqos_ht->hqos = rte_sched_port_config (&hqos->port);
  if (xd->hqos_ht->hqos == NULL)
    return clib_error_return (0, "HQoS%u: rte_sched_port_config err",
			      xd->device_index);

  /* HQoS subport */
  for (subport_id = 0; subport_id < hqos->port.n_subports_per_port;
       subport_id++)
    {
      u32 pipe_id;

      rv =
	rte_sched_subport_config (xd->hqos_ht->hqos, subport_id,
				  &hqos->subport[subport_id]);
      if (rv)
	return clib_error_return (0,
				  "HQoS%u subport %u: rte_sched_subport_config err (%d)",
				  xd->device_index, subport_id, rv);

      /* HQoS pipe */
      for (pipe_id = 0; pipe_id < hqos->port.n_pipes_per_subport; pipe_id++)
	{
	  u32 pos = subport_id * hqos->port.n_pipes_per_subport + pipe_id;
	  u32 profile_id = hqos->pipe_map[pos];

	  rv =
	    rte_sched_pipe_config (xd->hqos_ht->hqos, subport_id, pipe_id,
				   profile_id);
	  if (rv)
	    return clib_error_return (0,
				      "HQoS%u subport %u pipe %u: rte_sched_pipe_config err (%d)",
				      xd->device_index, subport_id, pipe_id,
				      rv);
	}
    }

  /* Set up per-thread device data for the I/O TX thread */
  xd->hqos_ht->hqos_burst_enq = hqos->burst_enq;
  xd->hqos_ht->hqos_burst_deq = hqos->burst_deq;
  vec_validate (xd->hqos_ht->pkts_enq, 2 * hqos->burst_enq - 1);
  vec_validate (xd->hqos_ht->pkts_deq, hqos->burst_deq - 1);
  xd->hqos_ht->pkts_enq_len = 0;
  xd->hqos_ht->swq_pos = 0;
  xd->hqos_ht->flush_count = 0;

  /* Set up per-thread device data for each worker thread */
  for (i = 0; i < worker_thread_count + 1; i++)
    {
      u32 tid;
      if (i)
	tid = worker_thread_first + (i - 1);
      else
	tid = i;

      xd->hqos_wt[tid].swq = xd->hqos_ht->swq[i];
      xd->hqos_wt[tid].hqos_field0_slabpos = hqos->pktfield0_slabpos;
      xd->hqos_wt[tid].hqos_field0_slabmask = hqos->pktfield0_slabmask;
      xd->hqos_wt[tid].hqos_field0_slabshr =
	__builtin_ctzll (hqos->pktfield0_slabmask);
      xd->hqos_wt[tid].hqos_field1_slabpos = hqos->pktfield1_slabpos;
      xd->hqos_wt[tid].hqos_field1_slabmask = hqos->pktfield1_slabmask;
      xd->hqos_wt[tid].hqos_field1_slabshr =
	__builtin_ctzll (hqos->pktfield1_slabmask);
      xd->hqos_wt[tid].hqos_field2_slabpos = hqos->pktfield2_slabpos;
      xd->hqos_wt[tid].hqos_field2_slabmask = hqos->pktfield2_slabmask;
      xd->hqos_wt[tid].hqos_field2_slabshr =
	__builtin_ctzll (hqos->pktfield2_slabmask);
      memcpy (xd->hqos_wt[tid].hqos_tc_table, hqos->tc_table,
	      sizeof (hqos->tc_table));
    }

  return 0;
}

/***
 *
 * HQoS run-time
 *
 ***/
/*
 * dpdk_hqos_thread - Contains the main loop of an HQoS thread.
 *
 * w
 *     Information for the current thread
 */
static_always_inline void
dpdk_hqos_thread_internal_hqos_dbg_bypass (vlib_main_t * vm)
{
  dpdk_main_t *dm = &dpdk_main;
  u32 thread_index = vm->thread_index;
  u32 dev_pos;

  dev_pos = 0;
  while (1)
    {
      vlib_worker_thread_barrier_check ();

      u32 n_devs = vec_len (dm->devices_by_hqos_cpu[thread_index]);
      if (dev_pos >= n_devs)
	dev_pos = 0;

      dpdk_device_and_queue_t *dq =
	vec_elt_at_index (dm->devices_by_hqos_cpu[thread_index], dev_pos);
      dpdk_device_t *xd = vec_elt_at_index (dm->devices, dq->device);

      dpdk_device_hqos_per_hqos_thread_t *hqos = xd->hqos_ht;
      u32 device_index = xd->device_index;
      u16 queue_id = dq->queue_id;

      struct rte_mbuf **pkts_enq = hqos->pkts_enq;
      u32 pkts_enq_len = hqos->pkts_enq_len;
      u32 swq_pos = hqos->swq_pos;
      u32 n_swq = vec_len (hqos->swq), i;
      u32 flush_count = hqos->flush_count;

      for (i = 0; i < n_swq; i++)
	{
	  /* Get current SWQ for this device */
	  struct rte_ring *swq = hqos->swq[swq_pos];

	  /* Read SWQ burst to packet buffer of this device */
	  pkts_enq_len += rte_ring_sc_dequeue_burst (swq,
						     (void **)
						     &pkts_enq[pkts_enq_len],
						     hqos->hqos_burst_enq, 0);

	  /* Get next SWQ for this device */
	  swq_pos++;
	  if (swq_pos >= n_swq)
	    swq_pos = 0;
	  hqos->swq_pos = swq_pos;

	  /* HWQ TX enqueue when burst available */
	  if (pkts_enq_len >= hqos->hqos_burst_enq)
	    {
	      u32 n_pkts = rte_eth_tx_burst (device_index,
					     (uint16_t) queue_id,
					     pkts_enq,
					     (uint16_t) pkts_enq_len);

	      for (; n_pkts < pkts_enq_len; n_pkts++)
		rte_pktmbuf_free (pkts_enq[n_pkts]);

	      pkts_enq_len = 0;
	      flush_count = 0;
	      break;
	    }
	}
      if (pkts_enq_len)
	{
	  flush_count++;
	  if (PREDICT_FALSE (flush_count == HQOS_FLUSH_COUNT_THRESHOLD))
	    {
	      rte_sched_port_enqueue (hqos->hqos, pkts_enq, pkts_enq_len);

	      pkts_enq_len = 0;
	      flush_count = 0;
	    }
	}
      hqos->pkts_enq_len = pkts_enq_len;
      hqos->flush_count = flush_count;

      /* Advance to next device */
      dev_pos++;
    }
}

static_always_inline void
dpdk_hqos_thread_internal (vlib_main_t * vm)
{
  dpdk_main_t *dm = &dpdk_main;
  u32 thread_index = vm->thread_index;
  u32 dev_pos;

  dev_pos = 0;
  while (1)
    {
      vlib_worker_thread_barrier_check ();

      u32 n_devs = vec_len (dm->devices_by_hqos_cpu[thread_index]);
      if (PREDICT_FALSE (n_devs == 0))
	{
	  dev_pos = 0;
	  continue;
	}
      if (dev_pos >= n_devs)
	dev_pos = 0;

      dpdk_device_and_queue_t *dq =
	vec_elt_at_index (dm->devices_by_hqos_cpu[thread_index], dev_pos);
      dpdk_device_t *xd = vec_elt_at_index (dm->devices, dq->device);

      dpdk_device_hqos_per_hqos_thread_t *hqos = xd->hqos_ht;
      u32 device_index = xd->device_index;
      u16 queue_id = dq->queue_id;

      struct rte_mbuf **pkts_enq = hqos->pkts_enq;
      struct rte_mbuf **pkts_deq = hqos->pkts_deq;
      u32 pkts_enq_len = hqos->pkts_enq_len;
      u32 swq_pos = hqos->swq_pos;
      u32 n_swq = vec_len (hqos->swq), i;
      u32 flush_count = hqos->flush_count;

      /*
       * SWQ dequeue and HQoS enqueue for current device
       */
      for (i = 0; i < n_swq; i++)
	{
	  /* Get current SWQ for this device */
	  struct rte_ring *swq = hqos->swq[swq_pos];

	  /* Read SWQ burst to packet buffer of this device */
	  pkts_enq_len += rte_ring_sc_dequeue_burst (swq,
						     (void **)
						     &pkts_enq[pkts_enq_len],
						     hqos->hqos_burst_enq, 0);

	  /* Get next SWQ for this device */
	  swq_pos++;
	  if (swq_pos >= n_swq)
	    swq_pos = 0;
	  hqos->swq_pos = swq_pos;

	  /* HQoS enqueue when burst available */
	  if (pkts_enq_len >= hqos->hqos_burst_enq)
	    {
	      rte_sched_port_enqueue (hqos->hqos, pkts_enq, pkts_enq_len);

	      pkts_enq_len = 0;
	      flush_count = 0;
	      break;
	    }
	}
      if (pkts_enq_len)
	{
	  flush_count++;
	  if (PREDICT_FALSE (flush_count == HQOS_FLUSH_COUNT_THRESHOLD))
	    {
	      rte_sched_port_enqueue (hqos->hqos, pkts_enq, pkts_enq_len);

	      pkts_enq_len = 0;
	      flush_count = 0;
	    }
	}
      hqos->pkts_enq_len = pkts_enq_len;
      hqos->flush_count = flush_count;

      /*
       * HQoS dequeue and HWQ TX enqueue for current device
       */
      {
	u32 pkts_deq_len, n_pkts;

	pkts_deq_len = rte_sched_port_dequeue (hqos->hqos,
					       pkts_deq,
					       hqos->hqos_burst_deq);

	for (n_pkts = 0; n_pkts < pkts_deq_len;)
	  n_pkts += rte_eth_tx_burst (device_index,
				      (uint16_t) queue_id,
				      &pkts_deq[n_pkts],
				      (uint16_t) (pkts_deq_len - n_pkts));
      }

      /* Advance to next device */
      dev_pos++;
    }
}

void
dpdk_hqos_thread (vlib_worker_thread_t * w)
{
  vlib_main_t *vm;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_main_t *dm = &dpdk_main;

  vm = vlib_get_main ();

  ASSERT (vm->thread_index == vlib_get_thread_index ());

  clib_time_init (&vm->clib_time);
  clib_mem_set_heap (w->thread_mheap);

  /* Wait until the dpdk init sequence is complete */
  while (tm->worker_thread_release == 0)
    vlib_worker_thread_barrier_check ();

  if (vec_len (dm->devices_by_hqos_cpu[vm->thread_index]) == 0)
    return
      clib_error
      ("current I/O TX thread does not have any devices assigned to it");

  if (DPDK_HQOS_DBG_BYPASS)
    dpdk_hqos_thread_internal_hqos_dbg_bypass (vm);
  else
    dpdk_hqos_thread_internal (vm);
}

void
dpdk_hqos_thread_fn (void *arg)
{
  vlib_worker_thread_t *w = (vlib_worker_thread_t *) arg;
  vlib_worker_thread_init (w);
  dpdk_hqos_thread (w);
}

/* *INDENT-OFF* */
VLIB_REGISTER_THREAD (hqos_thread_reg, static) =
{
  .name = "hqos-threads",
  .short_name = "hqos-threads",
  .function = dpdk_hqos_thread_fn,
};
/* *INDENT-ON* */

/*
 * HQoS run-time code to be called by the worker threads
 */
#define BITFIELD(byte_array, slab_pos, slab_mask, slab_shr)     \
({                                                              \
  u64 slab = *((u64 *) &byte_array[slab_pos]);                  \
  u64 val = (rte_be_to_cpu_64(slab) & slab_mask) >> slab_shr;   \
  val;                                                          \
})

#define RTE_SCHED_PORT_HIERARCHY(subport, pipe, traffic_class, queue, color) \
  ((((u64) (queue)) & 0x3) |                               \
  ((((u64) (traffic_class)) & 0x3) << 2) |                 \
  ((((u64) (color)) & 0x3) << 4) |                         \
  ((((u64) (subport)) & 0xFFFF) << 16) |                   \
  ((((u64) (pipe)) & 0xFFFFFFFF) << 32))

void
dpdk_hqos_metadata_set (dpdk_device_hqos_per_worker_thread_t * hqos,
			struct rte_mbuf **pkts, u32 n_pkts)
{
  u32 i;

  for (i = 0; i < (n_pkts & (~0x3)); i += 4)
    {
      struct rte_mbuf *pkt0 = pkts[i];
      struct rte_mbuf *pkt1 = pkts[i + 1];
      struct rte_mbuf *pkt2 = pkts[i + 2];
      struct rte_mbuf *pkt3 = pkts[i + 3];

      u8 *pkt0_data = rte_pktmbuf_mtod (pkt0, u8 *);
      u8 *pkt1_data = rte_pktmbuf_mtod (pkt1, u8 *);
      u8 *pkt2_data = rte_pktmbuf_mtod (pkt2, u8 *);
      u8 *pkt3_data = rte_pktmbuf_mtod (pkt3, u8 *);

      u64 pkt0_subport = BITFIELD (pkt0_data, hqos->hqos_field0_slabpos,
				   hqos->hqos_field0_slabmask,
				   hqos->hqos_field0_slabshr);
      u64 pkt0_pipe = BITFIELD (pkt0_data, hqos->hqos_field1_slabpos,
				hqos->hqos_field1_slabmask,
				hqos->hqos_field1_slabshr);
      u64 pkt0_dscp = BITFIELD (pkt0_data, hqos->hqos_field2_slabpos,
				hqos->hqos_field2_slabmask,
				hqos->hqos_field2_slabshr);
      u32 pkt0_tc = hqos->hqos_tc_table[pkt0_dscp & 0x3F] >> 2;
      u32 pkt0_tc_q = hqos->hqos_tc_table[pkt0_dscp & 0x3F] & 0x3;

      u64 pkt1_subport = BITFIELD (pkt1_data, hqos->hqos_field0_slabpos,
				   hqos->hqos_field0_slabmask,
				   hqos->hqos_field0_slabshr);
      u64 pkt1_pipe = BITFIELD (pkt1_data, hqos->hqos_field1_slabpos,
				hqos->hqos_field1_slabmask,
				hqos->hqos_field1_slabshr);
      u64 pkt1_dscp = BITFIELD (pkt1_data, hqos->hqos_field2_slabpos,
				hqos->hqos_field2_slabmask,
				hqos->hqos_field2_slabshr);
      u32 pkt1_tc = hqos->hqos_tc_table[pkt1_dscp & 0x3F] >> 2;
      u32 pkt1_tc_q = hqos->hqos_tc_table[pkt1_dscp & 0x3F] & 0x3;

      u64 pkt2_subport = BITFIELD (pkt2_data, hqos->hqos_field0_slabpos,
				   hqos->hqos_field0_slabmask,
				   hqos->hqos_field0_slabshr);
      u64 pkt2_pipe = BITFIELD (pkt2_data, hqos->hqos_field1_slabpos,
				hqos->hqos_field1_slabmask,
				hqos->hqos_field1_slabshr);
      u64 pkt2_dscp = BITFIELD (pkt2_data, hqos->hqos_field2_slabpos,
				hqos->hqos_field2_slabmask,
				hqos->hqos_field2_slabshr);
      u32 pkt2_tc = hqos->hqos_tc_table[pkt2_dscp & 0x3F] >> 2;
      u32 pkt2_tc_q = hqos->hqos_tc_table[pkt2_dscp & 0x3F] & 0x3;

      u64 pkt3_subport = BITFIELD (pkt3_data, hqos->hqos_field0_slabpos,
				   hqos->hqos_field0_slabmask,
				   hqos->hqos_field0_slabshr);
      u64 pkt3_pipe = BITFIELD (pkt3_data, hqos->hqos_field1_slabpos,
				hqos->hqos_field1_slabmask,
				hqos->hqos_field1_slabshr);
      u64 pkt3_dscp = BITFIELD (pkt3_data, hqos->hqos_field2_slabpos,
				hqos->hqos_field2_slabmask,
				hqos->hqos_field2_slabshr);
      u32 pkt3_tc = hqos->hqos_tc_table[pkt3_dscp & 0x3F] >> 2;
      u32 pkt3_tc_q = hqos->hqos_tc_table[pkt3_dscp & 0x3F] & 0x3;

      u64 pkt0_sched = RTE_SCHED_PORT_HIERARCHY (pkt0_subport,
						 pkt0_pipe,
						 pkt0_tc,
						 pkt0_tc_q,
						 0);
      u64 pkt1_sched = RTE_SCHED_PORT_HIERARCHY (pkt1_subport,
						 pkt1_pipe,
						 pkt1_tc,
						 pkt1_tc_q,
						 0);
      u64 pkt2_sched = RTE_SCHED_PORT_HIERARCHY (pkt2_subport,
						 pkt2_pipe,
						 pkt2_tc,
						 pkt2_tc_q,
						 0);
      u64 pkt3_sched = RTE_SCHED_PORT_HIERARCHY (pkt3_subport,
						 pkt3_pipe,
						 pkt3_tc,
						 pkt3_tc_q,
						 0);

      pkt0->hash.sched.lo = pkt0_sched & 0xFFFFFFFF;
      pkt0->hash.sched.hi = pkt0_sched >> 32;
      pkt1->hash.sched.lo = pkt1_sched & 0xFFFFFFFF;
      pkt1->hash.sched.hi = pkt1_sched >> 32;
      pkt2->hash.sched.lo = pkt2_sched & 0xFFFFFFFF;
      pkt2->hash.sched.hi = pkt2_sched >> 32;
      pkt3->hash.sched.lo = pkt3_sched & 0xFFFFFFFF;
      pkt3->hash.sched.hi = pkt3_sched >> 32;
    }

  for (; i < n_pkts; i++)
    {
      struct rte_mbuf *pkt = pkts[i];

      u8 *pkt_data = rte_pktmbuf_mtod (pkt, u8 *);

      u64 pkt_subport = BITFIELD (pkt_data, hqos->hqos_field0_slabpos,
				  hqos->hqos_field0_slabmask,
				  hqos->hqos_field0_slabshr);
      u64 pkt_pipe = BITFIELD (pkt_data, hqos->hqos_field1_slabpos,
			       hqos->hqos_field1_slabmask,
			       hqos->hqos_field1_slabshr);
      u64 pkt_dscp = BITFIELD (pkt_data, hqos->hqos_field2_slabpos,
			       hqos->hqos_field2_slabmask,
			       hqos->hqos_field2_slabshr);
      u32 pkt_tc = hqos->hqos_tc_table[pkt_dscp & 0x3F] >> 2;
      u32 pkt_tc_q = hqos->hqos_tc_table[pkt_dscp & 0x3F] & 0x3;

      u64 pkt_sched = RTE_SCHED_PORT_HIERARCHY (pkt_subport,
						pkt_pipe,
						pkt_tc,
						pkt_tc_q,
						0);

      pkt->hash.sched.lo = pkt_sched & 0xFFFFFFFF;
      pkt->hash.sched.hi = pkt_sched >> 32;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
