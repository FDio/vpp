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
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>

#include <vnet/devices/dpdk/dpdk.h>

#include <vlibmemory/api.h>
#include <vlibmemory/vl_memory_msg_enum.h> /* enumerate all vlib messages */

#define vl_typedefs             /* define message structures */
#include <vlibmemory/vl_memory_api_h.h> 
#undef vl_typedefs

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h> 
#undef vl_printfun


/*
 * dpdk_iotx_thread - Contains the main loop of an IO TX thread.
 *
 * w
 *     Information for the current thread
 */
static_always_inline void
dpdk_iotx_thread_internal_hqos_dbg_bypass (vlib_main_t *vm)
{
  dpdk_main_t * dm = &dpdk_main;
  u32 cpu_index = vm->cpu_index;
  u32 n_devs = vec_len(dm->devices_by_iotx_cpu[cpu_index]);
  u32 dev_pos;

  dpdk_device_hqos_per_iotx_thread_t **iotx_device_hqos = NULL;
  u32 *iotx_device_index = NULL;
  u16 *iotx_device_queue_id = NULL;

  vec_validate(iotx_device_hqos, n_devs - 1);
  vec_validate(iotx_device_index, n_devs - 1);
  vec_validate(iotx_device_queue_id, n_devs - 1);

  for (dev_pos = 0; dev_pos < n_devs; dev_pos++) {
    dpdk_device_and_queue_t *dq = vec_elt_at_index(dm->devices_by_iotx_cpu[cpu_index], dev_pos);
    dpdk_device_t *xd = vec_elt_at_index(dm->devices, dq->device);
    dpdk_device_hqos_per_iotx_thread_t *hqos = &xd->hqos[cpu_index].iotx;

    iotx_device_hqos[dev_pos] = hqos;
    iotx_device_index[dev_pos] = xd->device_index;
    iotx_device_queue_id[dev_pos] = dq->queue_id;
  }

  dev_pos = 0;
  while (1) {
    vlib_worker_thread_barrier_check();

    dpdk_device_hqos_per_iotx_thread_t *hqos = iotx_device_hqos[dev_pos];
    u32 device_index = iotx_device_index[dev_pos];
    u16 queue_id = iotx_device_queue_id[dev_pos];

    struct rte_mbuf **pkts_enq = hqos->pkts_enq;
    u32 pkts_enq_len = hqos->pkts_enq_len;
    u32 swq_pos = hqos->swq_pos;
    u32 n_swq = vec_len(hqos->swq), i;

    for (i = 0; i < n_swq; i++) {
      /* Get current SWQ for this device */
      struct rte_ring *swq = hqos->swq[swq_pos];

      /* Read SWQ burst to packet buffer of this device */
      pkts_enq_len += rte_ring_sc_dequeue_burst(swq,
        (void **) &pkts_enq[pkts_enq_len],
        hqos->hqos_burst_enq);

      /* Get next SWQ for this device */
      swq_pos ++;
      if (swq_pos >= n_swq)
        swq_pos = 0;
      hqos->swq_pos = swq_pos;

      /* HWQ TX enqueue when burst available */
      if (pkts_enq_len >= hqos->hqos_burst_enq) {
        u32 n_pkts = rte_eth_tx_burst(device_index,
          (uint16_t) queue_id,
          pkts_enq,
          (uint16_t) pkts_enq_len);

        for ( ; n_pkts < pkts_enq_len; n_pkts++)
          rte_pktmbuf_free(pkts_enq[n_pkts]);

        pkts_enq_len = 0;
        break;
      }
    }
    hqos->pkts_enq_len = pkts_enq_len;

    /* Advance to next device */
    dev_pos++;
    if (dev_pos >= n_devs)
      dev_pos = 0;
  }
}

static_always_inline void
dpdk_iotx_thread_internal (vlib_main_t *vm)
{
  dpdk_main_t * dm = &dpdk_main;
  u32 cpu_index = vm->cpu_index;
  u32 n_devs = vec_len(dm->devices_by_iotx_cpu[cpu_index]);
  u32 dev_pos;

  dpdk_device_hqos_per_iotx_thread_t **iotx_device_hqos = NULL;
  u32 *iotx_device_index = NULL;
  u16 *iotx_device_queue_id = NULL;

  vec_validate(iotx_device_hqos, n_devs - 1);
  vec_validate(iotx_device_index, n_devs - 1);
  vec_validate(iotx_device_queue_id, n_devs - 1);

  for (dev_pos = 0; dev_pos < n_devs; dev_pos++) {
    dpdk_device_and_queue_t *dq = vec_elt_at_index(dm->devices_by_iotx_cpu[cpu_index], dev_pos);
    dpdk_device_t *xd = vec_elt_at_index(dm->devices, dq->device);
    dpdk_device_hqos_per_iotx_thread_t *hqos = &xd->hqos[cpu_index].iotx;

    iotx_device_hqos[dev_pos] = hqos;
    iotx_device_index[dev_pos] = xd->device_index;
    iotx_device_queue_id[dev_pos] = dq->queue_id;
  }

  dev_pos = 0;
  while (1) {
    vlib_worker_thread_barrier_check();

    dpdk_device_hqos_per_iotx_thread_t *hqos = iotx_device_hqos[dev_pos];
    u32 device_index = iotx_device_index[dev_pos];
    u16 queue_id = iotx_device_queue_id[dev_pos];

    struct rte_mbuf **pkts_enq = hqos->pkts_enq;
    struct rte_mbuf **pkts_deq = hqos->pkts_deq;
    u32 pkts_enq_len = hqos->pkts_enq_len;
    u32 swq_pos = hqos->swq_pos;
    u32 n_swq = vec_len(hqos->swq), i;

    /*
     * SWQ dequeue and HQoS enqueue for current device
     */
    for (i = 0; i < n_swq; i++) {
      /* Get current SWQ for this device */
      struct rte_ring *swq = hqos->swq[swq_pos];

      /* Read SWQ burst to packet buffer of this device */
      pkts_enq_len += rte_ring_sc_dequeue_burst(swq,
        (void **) &pkts_enq[pkts_enq_len],
        hqos->hqos_burst_enq);

      /* Get next SWQ for this device */
      swq_pos ++;
      if (swq_pos >= n_swq)
        swq_pos = 0;
      hqos->swq_pos = swq_pos;

      /* HQoS enqueue when burst available */
      if (pkts_enq_len >= hqos->hqos_burst_enq) {
        rte_sched_port_enqueue(hqos->hqos,
          pkts_enq,
          pkts_enq_len);

        pkts_enq_len = 0;
        break;
      }
    }
    hqos->pkts_enq_len = pkts_enq_len;

    /*
     * HQoS dequeue and HWQ TX enqueue for current device
     */
    {
      u32 pkts_deq_len, n_pkts;

      pkts_deq_len = rte_sched_port_dequeue(hqos->hqos,
        pkts_deq,
        hqos->hqos_burst_deq);

      for (n_pkts = 0; n_pkts < pkts_deq_len; )
        n_pkts += rte_eth_tx_burst(device_index,
          (uint16_t) queue_id,
          &pkts_deq[n_pkts],
          (uint16_t) (pkts_deq_len - n_pkts));
    }

    /* Advance to next device */
    dev_pos++;
    if (dev_pos >= n_devs)
      dev_pos = 0;
  }
}

void dpdk_iotx_thread (vlib_worker_thread_t * w)
{
  vlib_main_t *vm;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_main_t * dm = &dpdk_main;
  dpdk_config_main_t *conf = &dpdk_config_main;

  vm = vlib_get_main();

  ASSERT(vm->cpu_index == os_get_cpu_number());

  clib_time_init (&vm->clib_time);
  clib_mem_set_heap (w->thread_mheap);

  /* Wait until the dpdk init sequence is complete */
  while (tm->worker_thread_release == 0)
    vlib_worker_thread_barrier_check ();

  if (vec_len(dm->devices_by_iotx_cpu[vm->cpu_index]) == 0)
    return clib_error ("current I/O TX thread does not have any devices assigned to it");

  if (conf->hqos_dbg_bypass)
    dpdk_iotx_thread_internal_hqos_dbg_bypass(vm);
  else
    dpdk_iotx_thread_internal(vm);
}

void dpdk_iotx_thread_fn (void * arg)
{
  vlib_worker_thread_t *w = (vlib_worker_thread_t *) arg;
  vlib_worker_thread_init (w);
  dpdk_iotx_thread (w);
}

VLIB_REGISTER_THREAD (iotx_thread_reg, static) = {
  .name = "iotx",
  .short_name = "iotx",
  .function = dpdk_iotx_thread_fn,
};
