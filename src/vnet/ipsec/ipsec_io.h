/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef __IPSEC_IO_H__
#define __IPSEC_IO_H__

#define foreach_ipsec_output_next  \
  _ (DROP, "error-drop")

#define _(v, s) IPSEC_OUTPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_output_next
#undef _
    IPSEC_OUTPUT_N_NEXT,
} ipsec_output_next_t;

#define foreach_ipsec_input_next   \
  _ (PUNT, "punt-dispatch")        \
  _ (DROP, "error-drop")

typedef enum
{
#define _(v, s) IPSEC_INPUT_NEXT_##v,
  foreach_ipsec_input_next
#undef _
    IPSEC_INPUT_N_NEXT,
} ipsec_input_next_t;


typedef struct
{
  u32 spd_index;
} ip4_ipsec_config_t;

typedef struct
{
  u32 spd_index;
} ip6_ipsec_config_t;

#endif /* __IPSEC_IO_H__ */
