/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __FIB_WALK_H__
#define __FIB_WALK_H__

#include <vnet/fib/fib_node.h>

/**
 * @brief Walk priorities.
 * Strict priorities. All walks a priority n are completed before n+1 is started.
 * Increasing numerical value implies decreasing priority.
 */
typedef enum fib_walk_priority_t_
{
    FIB_WALK_PRIORITY_HIGH = 0,
    FIB_WALK_PRIORITY_LOW  = 1,
} fib_walk_priority_t;

#define FIB_WALK_PRIORITY_NUM ((fib_walk_priority_t)(FIB_WALK_PRIORITY_LOW+1))

#define FIB_WALK_PRIORITIES {           \
    [FIB_WALK_PRIORITY_HIGH] = "high",  \
    [FIB_WALK_PRIORITY_LOW]  = "low",   \
}

#define FOR_EACH_FIB_WALK_PRIORITY(_prio)         \
    for ((_prio) = FIB_WALK_PRIORITY_HIGH;        \
         (_prio) < FIB_WALK_PRIORITY_NUM;         \
         (_prio)++)

extern void fib_walk_module_init(void);

extern void fib_walk_async(fib_node_type_t parent_type,
                           fib_node_index_t parent_index,
                           fib_walk_priority_t prio,
                           fib_node_back_walk_ctx_t *ctx);

extern void fib_walk_sync(fib_node_type_t parent_type,
                          fib_node_index_t parent_index,
                          fib_node_back_walk_ctx_t *ctx);

extern u8* format_fib_walk_priority(u8 *s, va_list *ap);

extern void fib_walk_process_enable(void);
extern void fib_walk_process_disable(void);

#endif

