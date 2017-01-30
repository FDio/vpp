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


#include <vnet/vnet.h>
#include <vnet/mfib/mfib_signal.h>
#include <vppinfra/dlist.h>

/**
 * @brief Pool of signals
 */
static mfib_signal_t *mfib_signal_pool;

/**
 * @brief pool of dlist elements
 */
static dlist_elt_t *mfib_signal_dlist_pool;

/**
 * the list/set of interfaces with signals pending
 */
typedef struct mfib_signal_q_t_
{
    /**
     * the dlist indext that is the head of the list
     */
    u32 mip_head;

    /**
     * Spin lock to protect the list
     */
    int mip_lock;
} mfib_signal_q_t;

/**
 * @brief The pending queue of signals to deliver to the control plane
 */
static mfib_signal_q_t mfib_signal_pending ;

static void
mfib_signal_list_init (void)
{
    dlist_elt_t *head;
    u32 hi;

    pool_get(mfib_signal_dlist_pool, head);
    hi = head - mfib_signal_dlist_pool;

    mfib_signal_pending.mip_head = hi;
    clib_dlist_init(mfib_signal_dlist_pool, hi);
}

void
mfib_signal_module_init (void)
{
    mfib_signal_list_init();
}

static inline void
mfib_signal_lock_aquire (void)
{
    while (__sync_lock_test_and_set (&mfib_signal_pending.mip_lock, 1))
        ;
}

static inline void
mfib_signal_lock_release (void)
{
    mfib_signal_pending.mip_lock = 0;
}

#define MFIB_SIGNAL_CRITICAL_SECTION(_body) \
{                                           \
    mfib_signal_lock_aquire();              \
    do {                                    \
        _body;                              \
    } while (0);                            \
    mfib_signal_lock_release();             \
}

int
mfib_signal_send_one (struct _unix_shared_memory_queue *q,
                      u32 context)
{
    u32 li, si;

    /*
     * with the lock held, pop a signal from the q.
     */
    MFIB_SIGNAL_CRITICAL_SECTION(
    ({
        li = clib_dlist_remove_head(mfib_signal_dlist_pool,
                                    mfib_signal_pending.mip_head);
    }));

    if (~0 != li)
    {
        mfib_signal_t *mfs;
        mfib_itf_t *mfi;
        dlist_elt_t *elt;

        elt = pool_elt_at_index(mfib_signal_dlist_pool, li);
        si = elt->value;

        mfs = pool_elt_at_index(mfib_signal_pool, si);
        mfi = mfib_itf_get(mfs->mfs_itf);
        mfi->mfi_si = INDEX_INVALID;
        __sync_fetch_and_and(&mfi->mfi_flags,
                             ~MFIB_ITF_FLAG_SIGNAL_PRESENT);


        vl_mfib_signal_send_one(q, context, mfs);

        /*
         * with the lock held, return the resoruces of the signals posted
         */
        MFIB_SIGNAL_CRITICAL_SECTION(
        ({
            pool_put_index(mfib_signal_pool, si);
            pool_put_index(mfib_signal_dlist_pool, li);
        }));

        return (1);
    }
    return (0);
}

void
mfib_signal_push (const mfib_entry_t *mfe,
                  mfib_itf_t *mfi,
                  vlib_buffer_t *b0)
{
    mfib_signal_t *mfs;
    dlist_elt_t *elt;
    u32 si, li;

    MFIB_SIGNAL_CRITICAL_SECTION(
    ({
        pool_get(mfib_signal_pool, mfs);
        pool_get(mfib_signal_dlist_pool, elt);

        si = mfs - mfib_signal_pool;
        li = elt - mfib_signal_dlist_pool;

        elt->value = si;
        mfi->mfi_si = li;

        clib_dlist_addhead(mfib_signal_dlist_pool,
                           mfib_signal_pending.mip_head,
                           li);
    }));

    mfs->mfs_entry = mfib_entry_get_index(mfe);
    mfs->mfs_itf = mfib_itf_get_index(mfi);

    if (NULL != b0)
    {
        mfs->mfs_buffer_len = b0->current_length;
        memcpy(mfs->mfs_buffer,
               vlib_buffer_get_current(b0),
               (mfs->mfs_buffer_len > MFIB_SIGNAL_BUFFER_SIZE ?
                MFIB_SIGNAL_BUFFER_SIZE :
                mfs->mfs_buffer_len));
    }
    else
    {
        mfs->mfs_buffer_len = 0;
    }
}

void
mfib_signal_remove_itf (const mfib_itf_t *mfi)
{
    u32 li;

    /*
     * lock the queue to prevent further additions while we fiddle.
     */
    li = mfi->mfi_si;

    if (INDEX_INVALID != li)
    {
        /*
         * it's in the pending q
         */
        MFIB_SIGNAL_CRITICAL_SECTION(
        ({
            dlist_elt_t *elt;

            /*
             * with the lock held;
             *  - remove the signal from the pending list
             *  - free up the signal and list entry obejcts
             */
            clib_dlist_remove(mfib_signal_dlist_pool, li);

            elt = pool_elt_at_index(mfib_signal_dlist_pool, li);
            pool_put_index(mfib_signal_pool, elt->value);
            pool_put(mfib_signal_dlist_pool, elt);
        }));
    }
}
