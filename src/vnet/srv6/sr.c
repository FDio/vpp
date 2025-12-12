/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2013 Cisco and/or its affiliates.
 */

/* sr.c: ipv6 segment routing */

/**
 * @file
 * @brief Segment Routing initialization
 *
 */

#include <vnet/vnet.h>
#include <vnet/srv6/sr.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/replicate_dpo.h>

ip6_sr_main_t sr_main;

/**
 * @brief no-op lock function.
 * The lifetime of the SR entry is managed by the control plane
 */
void
sr_dpo_lock (dpo_id_t * dpo)
{
}

/**
 * @brief no-op unlock function.
 * The lifetime of the SR entry is managed by the control plane
 */
void
sr_dpo_unlock (dpo_id_t * dpo)
{
}
