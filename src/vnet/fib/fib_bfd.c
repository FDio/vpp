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

#include <vnet/bfd/bfd_main.h>

#include <vnet/fib/fib_entry_delegate.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_walk.h>

static fib_bfd_state_t
fib_bfd_bfd_state_to_fib (bfd_state_e bstate)
{
    switch (bstate)
    {
    case BFD_STATE_up:
        return (FIB_BFD_STATE_UP);
    case BFD_STATE_down:
    case BFD_STATE_admin_down:
    case BFD_STATE_init:
        return (FIB_BFD_STATE_DOWN);
    }
    return (FIB_BFD_STATE_DOWN);
}

static void
fib_bfd_update_walk (fib_node_index_t fei)
{
    /*
     * initiate a backwalk of dependent children
     * to notify of the state change of this entry.
     */
    fib_node_back_walk_ctx_t ctx = {
        .fnbw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE,
    };
    fib_walk_sync(FIB_NODE_TYPE_ENTRY, fei, &ctx);
}

/**
 * @brief Callback function registered with BFD module to receive notifications
 * of the CRUD of BFD sessions
 * would be static but for the fact it's called from the unit-tests
 */
void
fib_bfd_notify (bfd_listen_event_e event,
                const bfd_session_t *session)
{
    fib_entry_delegate_t *fed;
    const bfd_udp_key_t *key;
    fib_node_index_t fei;

    if (BFD_HOP_TYPE_MULTI != session->hop_type)
    {
        /*
         * multi-hop BFD sessions attach directly to the FIB entry
         * single-hop adj to the associate adjacency.
         */
        return;
    }

    key = &session->udp.key;

    fib_prefix_t pfx = {
        .fp_addr = key->peer_addr,
        .fp_proto = (ip46_address_is_ip4 (&key->peer_addr) ?
                     FIB_PROTOCOL_IP4:
                     FIB_PROTOCOL_IP6),
        .fp_len = (ip46_address_is_ip4 (&key->peer_addr) ?
                   32:
                   128),
    };

    /*
     * get the FIB entry
     */
    fei = fib_table_lookup_exact_match(key->fib_index, &pfx);

    switch (event)
    {
    case BFD_LISTEN_EVENT_CREATE:
        /*
         * The creation of a new session
         */
        if ((FIB_NODE_INDEX_INVALID != fei) &&
            (fed = fib_entry_delegate_get(fib_entry_get(fei),
                                          FIB_ENTRY_DELEGATE_BFD)))
        {
            /*
             * already got state for this entry
             */
        }
        else
        {
            /*
             * source and lock the entry. add the delegate
             */
            fei = fib_table_entry_special_add(key->fib_index,
                                              &pfx,
                                              FIB_SOURCE_RR,
                                              FIB_ENTRY_FLAG_NONE);
            fib_entry_lock(fei);

            fed = fib_entry_delegate_find_or_add(fib_entry_get(fei),
                                                 FIB_ENTRY_DELEGATE_BFD);

            /*
             * pretend the session is up and skip the walk.
             * If we set it down then we get traffic loss on new children.
             * if we walk then we lose traffic for existing children. Wait
             * for the first BFD UP/DOWN before we let the session's state
             * influence forwarding.
             */
            fed->fd_bfd_state = FIB_BFD_STATE_UP;
        }
        break;

    case BFD_LISTEN_EVENT_UPDATE:
        /*
         * state change up/dowm and
         */
        ASSERT(FIB_NODE_INDEX_INVALID != fei);

        fed = fib_entry_delegate_get(fib_entry_get(fei),
                                     FIB_ENTRY_DELEGATE_BFD);

        if (NULL != fed)
        {
            fed->fd_bfd_state = fib_bfd_bfd_state_to_fib(session->local_state);
            fib_bfd_update_walk(fei);
        }
        /*
         * else
         *   no BFD state
         */
        break;

    case BFD_LISTEN_EVENT_DELETE:
        /*
         * session has been removed.
         */
        if (FIB_NODE_INDEX_INVALID == fei)
        {
            /*
             * no FIB entry
             */
        }
        else if (fib_entry_delegate_get(fib_entry_get(fei),
                                        FIB_ENTRY_DELEGATE_BFD))
        {
            /*
             * has an associated BFD tracking delegate
             * usource the entry and remove the BFD tracking deletgate
             */
            fib_entry_delegate_remove(fib_entry_get(fei),
                                      FIB_ENTRY_DELEGATE_BFD);
            fib_bfd_update_walk(fei);

            fib_table_entry_special_remove(key->fib_index,
                                           &pfx,
                                           FIB_SOURCE_RR);
            fib_entry_unlock(fei);
        }
        /*
         * else
         * no BFD associated state
         */
        break;
    }
}

static clib_error_t *
fib_bfd_main_init (vlib_main_t * vm)
{
    clib_error_t * error = NULL;

    if ((error = vlib_call_init_function (vm, bfd_main_init)))
        return (error);

    bfd_register_listener(fib_bfd_notify);

    return (error);
}

VLIB_INIT_FUNCTION (fib_bfd_main_init);
