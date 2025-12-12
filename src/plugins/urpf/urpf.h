/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __URPF_H__
#define __URPF_H__

#include <vnet/ip/ip_types.h>

#define foreach_urpf_mode                                                     \
  _ (OFF, "off")                                                              \
  _ (LOOSE, "loose")                                                          \
  _ (STRICT, "strict")

typedef enum urpf_mode_t_
{
#define _(a,b) URPF_MODE_##a,
  foreach_urpf_mode
#undef _
} __clib_packed urpf_mode_t;

#define URPF_N_MODES (URPF_MODE_STRICT+1)

typedef struct
{
  index_t urpf;
  u32 fib_index;
} urpf_trace_t;

u8 *format_urpf_trace (u8 *s, va_list *va);
u8 *format_urpf_mode (u8 *s, va_list *a);
uword unformat_urpf_mode (unformat_input_t *input, va_list *args);

typedef struct
{
  urpf_mode_t mode;
  u32 fib_index;
  u8 fib_index_is_custom;
} urpf_data_t;

extern urpf_data_t *urpf_cfgs[N_AF][VLIB_N_DIR];

int urpf_update (urpf_mode_t mode, u32 sw_if_index, ip_address_family_t af,
		 vlib_dir_t dir, u32 table_id);

#endif
