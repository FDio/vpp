/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* defs.h: VLIB generic C definitions */

#ifndef included_vlib_defs_h
#define included_vlib_defs_h

/* Receive or transmit. */
typedef enum
{
  VLIB_RX,
  VLIB_TX,
  VLIB_N_RX_TX = 2,		/* Used to size arrays. */
} vlib_rx_or_tx_t;


#define vlib_foreach_rx_tx(v) for (v = 0; v < VLIB_N_RX_TX; v++)

/* alias the rx/tx to 'direction' */
typedef vlib_rx_or_tx_t vlib_dir_t;

#define VLIB_N_DIR VLIB_N_RX_TX
#define FOREACH_VLIB_DIR(_dir) \
  for (_dir = VLIB_RX; _dir <= VLIB_TX; _dir++)

/* Read/write. */
typedef enum
{
  VLIB_READ,
  VLIB_WRITE,
} vlib_read_or_write_t;

/* Up/down. */
typedef enum
{
  VLIB_DOWN = 0,
  VLIB_UP = 1,
} vlib_up_or_down_t;

/* Enable/disable. */
typedef enum
{
  VLIB_DISABLE = 0,
  VLIB_ENABLE = 1,
} vlib_enable_or_disable_t;

#endif /* included_vlib_defs_h */
