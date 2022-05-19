.. _dma_plugin:

.. toctree::

DMA plugin
==========

Overview
--------
This plugin utilize platform DMA accelerators like CBDMA/DSA for streaming
data movement. Modern DMA accelerators has high memory bandwidth and benefit
cross-numa traffic. Accelerator like DSA has the capability to do IO page
fault recovery, it will save IOMMU setup for the memory which not pinned.

Terminology & Usage
-------------------

A ``backend`` is the abstract of resource which inherited from DMA device,
it support necessary operations for DMA offloading like configuration, DMA
request and result query.

A ``config`` is the abstract of application DMA capability. Application can
request a config instance through DMA node. DMA node will check the
requirements of application and bind suitable backend with it.

Enable DSA work queue:
----------------------

.. code-block:: console
  # configure 1 groups, each with one engine
  accel-config config-engine dsa0/engine0.0 --group-id=0

  # configure 1 queues, putting each in a different group, so each
  # is backed by a single engine
  accel-config config-wq dsa0/wq0.0 --group-id=0 --type=user  \
    --priority=10 --max-batch-size=1024 --mode=dedicated -b 1 -a 0 --name=vpp1

DMA transfer:
-------------

In this sample, application will request DMA capability which can hold
a batch contained maximum 256 transfers and total 16 in-flight batch
from DMA node. If config_index value is not negative, mean resource has
been allocated and DMA engine is ready for serve.

.. code-block:: console

  typedef struct {
    ...
    int config_index;
    vlib_dma_transfer_t iov[256];
    u32 n_transfers;
    ...
  } wrk_t;

  vlib_dma_config_args_t args;
  args->max_transfers = 256;
  args->max_transfer_size = 16;
  args->cpu_fallback = 1;
  args->barrier_before_last = 0;
  args->cb = dma_completion_cb;
  wrk_t->config_index = vlib_dma_config (vm, &args);

  while (has_buffer && wrk_t->config_index > 0) {
    wrk->iov[wrk->n_transfers].dst = dst;
    wrk->iov[wrk->n_transfers].src = src;
    wrk->iov[wrk->n_transfers].size = size;
    n_transfers ++;
  }
  vlib_dma_transfer (vm, wrk->config_index, wrk->iov, wrk->n_transfers, 0);
