// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vcdp/service.h>
#include <vcdp/vcdp.h>
#include <vppinfra/format_table.h>
#include <vcdp/timer.h>
#include <vcdp/timer_lru.h>



u8 *
format_vcdp_bitmap(u8 *s, va_list *args)
{
  u32 bmp = va_arg(*args, u32);
  vcdp_service_main_t *sm = &vcdp_service_main;
  int i;
  for (i = 0; i < vec_len(sm->services); i++)
    if (bmp & sm->services[i]->service_mask[0])
      s = format(s, "%s,", sm->services[i]->node_name);
  return s;
}



uword
unformat_vcdp_service(unformat_input_t *input, va_list *args)
{
  vcdp_service_main_t *sm = &vcdp_service_main;
  u32 *result = va_arg(*args, u32 *);
  int i;
  for (i = 0; i < vec_len(sm->services); i++) {
    vcdp_service_registration_t *reg = vec_elt_at_index(sm->services, i)[0];
    if (unformat(input, reg->node_name)) {
      *result = reg->index_in_bitmap[0];
      return 1;
    }
  }
  return 0;
}

uword
unformat_vcdp_service_bitmap(unformat_input_t *input, va_list *args)
{
  u32 *result = va_arg(*args, u32 *);
  int i = -1;
  u32 bitmap = 0;
  while (unformat_user(input, unformat_vcdp_service, &i))
    bitmap |= 1 << i;
  if (i > -1) {
    *result = bitmap;
    return 1;
  }
  return 0;
}

u8 *
format_vcdp_tenant_stats(u8 *s, va_list *args)
{
  vcdp_main_t *vcdp = va_arg(*args, vcdp_main_t *);
  u32 tenant_idx = va_arg(*args, u32);
#define _(NAME, VALUE, STR)                                                                                            \
  s = format(s, "\t%s: %lu", STR, vlib_get_simple_counter(&vcdp->tenant_simple_ctr[VALUE], tenant_idx));
  foreach_vcdp_tenant_simple_counter
#undef _
    vlib_counter_t counter;
#define _(NAME, VALUE, STR)                                                                                            \
  vlib_get_combined_counter(&vcdp->tenant_combined_ctr[VALUE], tenant_idx, &counter);                                  \
  s = format(s, "\t%s: %lu packets, %lu bytes", STR, counter.packets, counter.bytes);
  foreach_vcdp_tenant_combined_counter
#undef _

  return s;
}

