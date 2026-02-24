/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __FLOW_ACTIONS_H__
#define __FLOW_ACTIONS_H__

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <dpdk/device/dpdk.h>

#define FOREACH_FLOW_ACTION(_actions, _action)                                                     \
  (_action) = &(_actions)[0];                                                                      \
  for (int _it = 0; (_action)->type != RTE_FLOW_ACTION_TYPE_END; (_action) = &(_actions)[++_it])

static inline void
dpdk_flow_convert_rss_types (u64 type, u64 *dpdk_rss_type)
{
#define BIT_IS_SET(v, b) ((v) & (u64) 1 << (b))

  *dpdk_rss_type = 0;

#undef _
#define _(n, f, s)                                                                                 \
  if (n != -1 && BIT_IS_SET (type, n))                                                             \
    *dpdk_rss_type |= f;

  foreach_dpdk_rss_hf
#undef _
    return;
}

/** Maximum number of queue indices in struct rte_flow_action_rss. */
#define ACTION_RSS_QUEUE_NUM 128

static inline void
dpdk_flow_convert_rss_queues (u32 queue_index, u32 queue_num, struct rte_flow_action_rss *rss)
{
  u16 *queues = clib_mem_alloc (sizeof (*queues) * ACTION_RSS_QUEUE_NUM);
  int i;

  for (i = 0; i < queue_num; i++)
    queues[i] = queue_index++;

  rss->queue_num = queue_num;
  rss->queue = queues;

  return;
}

static inline enum rte_eth_hash_function
dpdk_flow_convert_rss_func (vnet_rss_function_t func)
{
  enum rte_eth_hash_function rss_func;

  switch (func)
    {
    case VNET_RSS_FUNC_DEFAULT:
      rss_func = RTE_ETH_HASH_FUNCTION_DEFAULT;
      break;
    case VNET_RSS_FUNC_TOEPLITZ:
      rss_func = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
      break;
    case VNET_RSS_FUNC_SIMPLE_XOR:
      rss_func = RTE_ETH_HASH_FUNCTION_SIMPLE_XOR;
      break;
    case VNET_RSS_FUNC_SYMMETRIC_TOEPLITZ:
      rss_func = RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ;
      break;
    default:
      rss_func = RTE_ETH_HASH_FUNCTION_MAX;
      break;
    }

  return rss_func;
}

/*
 * Specialized action fill functions for async flow path.
 */

static void
dpdk_fill_action_drop (vnet_flow_t *f, struct rte_flow_action *action)
{
  action->type = RTE_FLOW_ACTION_TYPE_DROP;
  action->conf = NULL;
}

static void
dpdk_fill_action_queue (vnet_flow_t *f, struct rte_flow_action *action)
{
  static struct rte_flow_action_queue conf;
  conf.index = f->redirect_queue;
  action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
  action->conf = &conf;
}

static void
dpdk_fill_action_passthru (vnet_flow_t *f, struct rte_flow_action *action)
{
  action->type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
  action->conf = NULL;
}

/* Async path - validation done at template creation, no error return needed */
static void
dpdk_fill_action_rss (vnet_flow_t *f, struct rte_flow_action *action)
{
  static struct rte_flow_action_rss conf;

  dpdk_flow_convert_rss_types (f->rss_types, &conf.types);
  if (f->queue_num)
    dpdk_flow_convert_rss_queues (f->queue_index, f->queue_num, &conf);
  conf.func = dpdk_flow_convert_rss_func (f->rss_fun);

  action->type = RTE_FLOW_ACTION_TYPE_RSS;
  action->conf = &conf;
}

/* Sync path - returns error if RSS function is invalid */
static int
dpdk_fill_action_rss_validated (vnet_flow_t *f, struct rte_flow_action *action)
{
  static struct rte_flow_action_rss conf;

  dpdk_flow_convert_rss_types (f->rss_types, &conf.types);
  if (f->queue_num)
    dpdk_flow_convert_rss_queues (f->queue_index, f->queue_num, &conf);

  conf.func = dpdk_flow_convert_rss_func (f->rss_fun);
  if (conf.func == RTE_ETH_HASH_FUNCTION_MAX)
    return -1;

  action->type = RTE_FLOW_ACTION_TYPE_RSS;
  action->conf = &conf;
  return 0;
}

static void
dpdk_fill_action_mark (vnet_flow_t *f, struct rte_flow_action *action)
{
  static struct rte_flow_action_mark conf;
  conf.id = f->mark_flow_id;
  action->type = RTE_FLOW_ACTION_TYPE_MARK;
  action->conf = &conf;
}

static void
dpdk_fill_action_mark_with_id (vnet_flow_t *f, struct rte_flow_action *action, u32 mark_id)
{
  static struct rte_flow_action_mark conf;
  conf.id = mark_id;
  action->type = RTE_FLOW_ACTION_TYPE_MARK;
  action->conf = &conf;
}

static void
dpdk_fill_action_end (vnet_flow_t *f, struct rte_flow_action *action)
{
  action->type = RTE_FLOW_ACTION_TYPE_END;
}

#endif /* __FLOW_ACTIONS_H__ */
