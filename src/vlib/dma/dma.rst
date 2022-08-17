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
a batch contained maximum 256 transfers and each transfer hold maximum 4K bytes
from DMA node. If config_index value is not negative, mean resource has
been allocated and DMA engine is ready for serve.

.. code-block:: console
  void dma_completion_cb (vlib_main_t *vm, vlib_dma_batch_t *b);

  vlib_dma_config_args_t args;
  args->max_transfers = 256;
  args->max_transfer_size = 4096;
  args->cpu_fallback = 1;
  args->barrier_before_last = 1;
  args->cb = dma_completion_cb;
  u32 config_index = vlib_dma_config (vm, &args);
  if (config_index < 0)
    return;

  u8 *dst[n_transfers];
  u8 *src[n_transfers];
  u32 i = 0, size = 4096;

  vlib_dma_batch_t *b;
  b = vlib_dma_batch_new (vm, config_index);
  while (wrk_t->config_index >= 0 && n_transfers) {
    vlib_dma_batch_add (vm, b, dst[i], src[i], size);
    n_transfers --;
    i ++;
  }
  vlib_dma_batch_submit (vm, config_index);
