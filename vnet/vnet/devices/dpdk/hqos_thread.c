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
  u32 dev_pos;

  dev_pos = 0;
  while (1) {
    vlib_worker_thread_barrier_check();

    u32 n_devs = vec_len(dm->devices_by_iotx_cpu[cpu_index]);
    if (dev_pos >= n_devs)
      dev_pos = 0;

    dpdk_device_and_queue_t *dq = vec_elt_at_index(dm->devices_by_iotx_cpu[cpu_index], dev_pos);
    dpdk_device_t *xd = vec_elt_at_index(dm->devices, dq->device);

    dpdk_device_hqos_per_iotx_thread_t *hqos = xd->hqos_iotx;
    u32 device_index = xd->device_index;
    u16 queue_id = dq->queue_id;

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
  }
}

static_always_inline void
dpdk_iotx_thread_internal (vlib_main_t *vm)
{
  dpdk_main_t * dm = &dpdk_main;
  u32 cpu_index = vm->cpu_index;
  u32 dev_pos;

  dev_pos = 0;
  while (1) {
    vlib_worker_thread_barrier_check();

    u32 n_devs = vec_len(dm->devices_by_iotx_cpu[cpu_index]);
    if (PREDICT_FALSE(n_devs == 0)) {
      dev_pos = 0;
      continue;
    }
    if (dev_pos >= n_devs)
      dev_pos = 0;

    dpdk_device_and_queue_t *dq = vec_elt_at_index(dm->devices_by_iotx_cpu[cpu_index], dev_pos);
    dpdk_device_t *xd = vec_elt_at_index(dm->devices, dq->device);

    dpdk_device_hqos_per_iotx_thread_t *hqos = xd->hqos_iotx;
    u32 device_index = xd->device_index;
    u16 queue_id = dq->queue_id;

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
dpdk_hqos_metadata_set(dpdk_device_hqos_per_worker_thread_t *hqos, struct rte_mbuf **pkts, u32 n_pkts)
{
  u32 i;

  for (i = 0; i < (n_pkts & (~0x3)); i += 4) {
    struct rte_mbuf *pkt0 = pkts[i];
    struct rte_mbuf *pkt1 = pkts[i + 1];
    struct rte_mbuf *pkt2 = pkts[i + 2];
    struct rte_mbuf *pkt3 = pkts[i + 3];

    u8 *pkt0_data = rte_pktmbuf_mtod(pkt0, u8 *);
    u8 *pkt1_data = rte_pktmbuf_mtod(pkt1, u8 *);
    u8 *pkt2_data = rte_pktmbuf_mtod(pkt2, u8 *);
    u8 *pkt3_data = rte_pktmbuf_mtod(pkt3, u8 *);

    u64 pkt0_subport = BITFIELD(pkt0_data, hqos->hqos_field0_slabpos, hqos->hqos_field0_slabmask, hqos->hqos_field0_slabshr);
    u64 pkt0_pipe = BITFIELD(pkt0_data, hqos->hqos_field1_slabpos, hqos->hqos_field1_slabmask, hqos->hqos_field1_slabshr);
    u64 pkt0_dscp = BITFIELD(pkt0_data, hqos->hqos_field2_slabpos, hqos->hqos_field2_slabmask, hqos->hqos_field2_slabshr);
    u32 pkt0_tc = hqos->hqos_tc_table[pkt0_dscp & 0x3F] >> 2;
    u32 pkt0_tc_q = hqos->hqos_tc_table[pkt0_dscp & 0x3F] & 0x3;

    u64 pkt1_subport = BITFIELD(pkt1_data, hqos->hqos_field0_slabpos, hqos->hqos_field0_slabmask, hqos->hqos_field0_slabshr);
    u64 pkt1_pipe = BITFIELD(pkt1_data, hqos->hqos_field1_slabpos, hqos->hqos_field1_slabmask, hqos->hqos_field1_slabshr);
    u64 pkt1_dscp = BITFIELD(pkt1_data, hqos->hqos_field2_slabpos, hqos->hqos_field2_slabmask, hqos->hqos_field2_slabshr);
    u32 pkt1_tc = hqos->hqos_tc_table[pkt1_dscp & 0x3F] >> 2;
    u32 pkt1_tc_q = hqos->hqos_tc_table[pkt1_dscp & 0x3F] & 0x3;

    u64 pkt2_subport = BITFIELD(pkt2_data, hqos->hqos_field0_slabpos, hqos->hqos_field0_slabmask, hqos->hqos_field0_slabshr);
    u64 pkt2_pipe = BITFIELD(pkt2_data, hqos->hqos_field1_slabpos, hqos->hqos_field1_slabmask, hqos->hqos_field1_slabshr);
    u64 pkt2_dscp = BITFIELD(pkt2_data, hqos->hqos_field2_slabpos, hqos->hqos_field2_slabmask, hqos->hqos_field2_slabshr);
    u32 pkt2_tc = hqos->hqos_tc_table[pkt2_dscp & 0x3F] >> 2;
    u32 pkt2_tc_q = hqos->hqos_tc_table[pkt2_dscp & 0x3F] & 0x3;

    u64 pkt3_subport = BITFIELD(pkt3_data, hqos->hqos_field0_slabpos, hqos->hqos_field0_slabmask, hqos->hqos_field0_slabshr);
    u64 pkt3_pipe = BITFIELD(pkt3_data, hqos->hqos_field1_slabpos, hqos->hqos_field1_slabmask, hqos->hqos_field1_slabshr);
    u64 pkt3_dscp = BITFIELD(pkt3_data, hqos->hqos_field2_slabpos, hqos->hqos_field2_slabmask, hqos->hqos_field2_slabshr);
    u32 pkt3_tc = hqos->hqos_tc_table[pkt3_dscp & 0x3F] >> 2;
    u32 pkt3_tc_q = hqos->hqos_tc_table[pkt3_dscp & 0x3F] & 0x3;

    u64 pkt0_sched = RTE_SCHED_PORT_HIERARCHY(pkt0_subport,
      pkt0_pipe,
      pkt0_tc,
      pkt0_tc_q,
      0);
    u64 pkt1_sched = RTE_SCHED_PORT_HIERARCHY(pkt1_subport,
      pkt1_pipe,
      pkt1_tc,
      pkt1_tc_q,
      0);
    u64 pkt2_sched = RTE_SCHED_PORT_HIERARCHY(pkt2_subport,
      pkt2_pipe,
      pkt2_tc,
      pkt2_tc_q,
      0);
    u64 pkt3_sched = RTE_SCHED_PORT_HIERARCHY(pkt3_subport,
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

  for ( ; i < n_pkts; i++) {
    struct rte_mbuf *pkt = pkts[i];

    u8 *pkt_data = rte_pktmbuf_mtod(pkt, u8 *);

    u64 pkt_subport = BITFIELD(pkt_data, hqos->hqos_field0_slabpos, hqos->hqos_field0_slabmask, hqos->hqos_field0_slabshr);
    u64 pkt_pipe = BITFIELD(pkt_data, hqos->hqos_field1_slabpos, hqos->hqos_field1_slabmask, hqos->hqos_field1_slabshr);
    u64 pkt_dscp = BITFIELD(pkt_data, hqos->hqos_field2_slabpos, hqos->hqos_field2_slabmask, hqos->hqos_field2_slabshr);
    u32 pkt_tc = hqos->hqos_tc_table[pkt_dscp & 0x3F] >> 2;
    u32 pkt_tc_q = hqos->hqos_tc_table[pkt_dscp & 0x3F] & 0x3;

    u64 pkt_sched = RTE_SCHED_PORT_HIERARCHY(pkt_subport,
      pkt_pipe,
      pkt_tc,
      pkt_tc_q,
      0);

    pkt->hash.sched.lo = pkt_sched & 0xFFFFFFFF;
    pkt->hash.sched.hi = pkt_sched >> 32;
  }
}
