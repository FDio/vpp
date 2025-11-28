/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015-2025 Cisco and/or its affiliates.
 */
#pragma once

static_always_inline void
tap_kick (vlib_main_t *vm, vnet_virtio_vring_t *vring, tap_if_t *tif)
{
  u64 x = 1;
  int __clib_unused r;

  r = write (vring->kick_fd, &x, sizeof (x));
}

static_always_inline u8
tap_txq_is_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    return (vring->tx_is_scheduled);
  return 1;
}

static_always_inline void
tap_txq_set_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    vring->tx_is_scheduled = 1;
}

static_always_inline void
tap_txq_clear_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    vring->tx_is_scheduled = 0;
}
