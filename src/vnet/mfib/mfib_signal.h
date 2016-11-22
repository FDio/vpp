/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MFIB_SIGNAL_H__
#define __MFIB_SIGNAL_H__

#include <vlib/vlib.h>
#include <vnet/mfib/mfib_types.h>
#include <vnet/mfib/mfib_itf.h>
#include <vnet/mfib/mfib_entry.h>

#define MFIB_SIGNAL_BUFFER_SIZE 255

/**
 * A pair of indicies, for the entry and interface resp.
 */
typedef struct mfib_signal_t_
{
    fib_node_index_t mfs_entry;
    index_t mfs_itf;

    /**
     * @brief A buffer copied from the DP plane that triggered the signal
     */
    u8 mfs_buffer[MFIB_SIGNAL_BUFFER_SIZE];

    u8 mfs_buffer_len;
} mfib_signal_t;


extern void mfib_signal_push(const mfib_entry_t *mfe,
                             mfib_itf_t *mfi,
                             vlib_buffer_t *b0);
extern void mfib_signal_remove_itf(const mfib_itf_t *mfi);

extern void mfib_signal_module_init(void);

struct _unix_shared_memory_queue;

extern void vl_mfib_signal_send_one(struct _unix_shared_memory_queue *q,
                                    u32 context,
                                    const mfib_signal_t *mfs);
extern int mfib_signal_send_one(struct _unix_shared_memory_queue *q,
                                u32 context);

#endif

