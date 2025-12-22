/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __IPSEC_FUNCS_H__
#define __IPSEC_FUNCS_H__

#include <vlib/vlib.h>
#include <vnet/ipsec/ipsec.h>

always_inline ipsec_sa_t *
ipsec_sa_get (u32 sa_index)
{
  ASSERT (!pool_is_free_index (ipsec_main.sa_pool, sa_index));
  return (pool_elt_at_index (ipsec_main.sa_pool, sa_index));
}

static_always_inline ipsec_sa_outb_rt_t *
ipsec_sa_get_outb_rt_by_index (u32 sa_index)
{
  return ipsec_main.outb_sa_runtimes[sa_index];
}

static_always_inline ipsec_sa_inb_rt_t *
ipsec_sa_get_inb_rt_by_index (u32 sa_index)
{
  return ipsec_main.inb_sa_runtimes[sa_index];
}

static_always_inline ipsec_sa_outb_rt_t *
ipsec_sa_get_outb_rt (ipsec_sa_t *sa)
{
  return ipsec_sa_get_outb_rt_by_index (sa - ipsec_main.sa_pool);
}

static_always_inline ipsec_sa_inb_rt_t *
ipsec_sa_get_inb_rt (ipsec_sa_t *sa)
{
  return ipsec_sa_get_inb_rt_by_index (sa - ipsec_main.sa_pool);
}

#endif /* __IPSEC_FUNCS_H__ */
