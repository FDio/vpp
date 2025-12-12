/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef included_vlib_counter_types_h
#define included_vlib_counter_types_h

#include <stdint.h>

/** 64bit counters */
typedef uint64_t counter_t;

/** Combined counter to hold both packets and byte differences.
 */
typedef struct
{
  counter_t packets;			/**< packet counter */
  counter_t bytes;			/**< byte counter  */
} vlib_counter_t;

#endif
