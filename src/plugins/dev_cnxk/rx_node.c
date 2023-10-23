/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <dev_cnxk/cnxk.h>

typedef struct
{
  u64 wdata;
  u32 cached_pkts;
  int64_t *cq_status;
  u32 qmask;
} cnxk_fprq_t;

static_always_inline u32
cnxk_cqe_cached_pkts_get (cnxk_fprq_t *fprq, u16 req_pkts)
{
  u64 npkts, head, tail, reg;

  if (PREDICT_FALSE (fprq->cached_pkts < req_pkts))
    {
      reg = roc_atomic64_add_sync (fprq->wdata, fprq->cq_status);
      if (reg &
	  (BIT_ULL (NIX_CQ_OP_STAT_OP_ERR) | BIT_ULL (NIX_CQ_OP_STAT_CQ_ERR)))
	return 0;

      tail = reg & 0xFFFFF;
      head = (reg >> 20) & 0xFFFFF;

      if (tail < head)
	npkts = tail - head + fprq->qmask + 1;
      else
	npkts = tail - head;

      fprq->cached_pkts = npkts;
    }

  return clib_min (fprq->cached_pkts, req_pkts);
}

static_always_inline uword
cnxk_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, vnet_dev_port_t *port,
			  vnet_dev_rx_queue_t *rxq, int with_flows)
{
  cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  cnxk_fprq_t fprq = {
    .qmask = rxq->size - 1,
    .wdata = crq->cq.wdata,
    .cq_status = crq->cq.status,
  };
  static __thread u32 last_rv = ~0;

  u32 rv = cnxk_cqe_cached_pkts_get (&fprq, 8);

  if (rv != last_rv)
    {
      fformat (stderr, "%u: rv %u\n", vm->thread_index, rv);
      last_rv = rv;
    }
  return 0;
}

VNET_DEV_NODE_FN (cnxk_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_port_t *port = rxq->port;
      n_rx += cnxk_device_input_inline (vm, node, frame, port, rxq, 0);
    }

  return n_rx;
}
