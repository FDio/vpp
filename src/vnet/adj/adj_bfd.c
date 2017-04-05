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

#include <vnet/adj/adj_delegate.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/fib/fib_walk.h>

static adj_bfd_state_t
adj_bfd_bfd_state_to_fib (bfd_state_e bstate)
{
    switch (bstate)
    {
    case BFD_STATE_up:
        return (ADJ_BFD_STATE_UP);
    case BFD_STATE_down:
    case BFD_STATE_admin_down:
    case BFD_STATE_init:
        return (ADJ_BFD_STATE_DOWN);
    }
    return (ADJ_BFD_STATE_DOWN);
}

static void
adj_bfd_update_walk (adj_index_t ai)
{
    /*
     * initiate a backwalk of dependent children
     * to notify of the state change of this adj.
     */
    fib_node_back_walk_ctx_t ctx = {
        .fnbw_reason = FIB_NODE_BW_REASON_FLAG_ADJ_UPDATE,
    };
    fib_walk_sync(FIB_NODE_TYPE_ADJ, ai, &ctx);
}

/**
 * @brief Callback function registered with BFD module to receive notifications
 * of the CRUD of BFD sessions
 * would be static but for the fact it's called from the unit-tests
 */
void
adj_bfd_notify (bfd_listen_event_e event,
                const bfd_session_t *session)
{
    const bfd_udp_key_t *key;
    fib_protocol_t fproto;
    adj_delegate_t *aed;
    adj_index_t ai;

    if (BFD_HOP_TYPE_SINGLE != session->hop_type)
    {
        /*
         * multi-hop BFD sessions attach directly to the FIB entry
         * single-hop adj to the associate adjacency.
         */
        return;
    }

    key = &session->udp.key;

    fproto = (ip46_address_is_ip4 (&key->peer_addr) ?
              FIB_PROTOCOL_IP4:
              FIB_PROTOCOL_IP6);

    /*
     * find the adj that corresponds to the BFD session.
     */
    ai = adj_nbr_add_or_lock(fproto,
                             fib_proto_to_link(fproto),
                             &key->peer_addr,
                             key->sw_if_index);

    switch (event)
    {
    case BFD_LISTEN_EVENT_CREATE:
        /*
         * The creation of a new session
         */
        if ((ADJ_INDEX_INVALID != ai) &&
            (aed = adj_delegate_get(adj_get(ai),
                                    ADJ_DELEGATE_BFD)))
        {
            /*
             * already got state for this adj
             */
        }
        else
        {
            /*
             * lock the adj. add the delegate.
             * Lockinging the adj prevents it being removed and thus maintains
             * the BFD derived states
             */
            adj_lock(ai);

            aed = adj_delegate_find_or_add(adj_get(ai), ADJ_DELEGATE_BFD);

            /*
             * pretend the session is up and skip the walk.
             * If we set it down then we get traffic loss on new children.
             * if we walk then we lose traffic for existing children. Wait
             * for the first BFD UP/DOWN before we let the session's state
             * influence forwarding.
             */
            aed->ad_bfd_state = ADJ_BFD_STATE_UP;
            aed->ad_bfd_index = session->bs_idx;
        }
        break;

    case BFD_LISTEN_EVENT_UPDATE:
        /*
         * state change up/dowm and
         */
        aed = adj_delegate_get(adj_get(ai), ADJ_DELEGATE_BFD);

        if (NULL != aed)
        {
            aed->ad_bfd_state = adj_bfd_bfd_state_to_fib(session->local_state);
            adj_bfd_update_walk(ai);
        }
        /*
         * else
         *   not an adj with BFD state
         */
        break;

    case BFD_LISTEN_EVENT_DELETE:
        /*
         * session has been removed.
         */

        if (adj_delegate_get(adj_get(ai), ADJ_DELEGATE_BFD))
        {
            /*
             * has an associated BFD tracking delegate
             * remove the BFD tracking deletgate, update children, then
             * unlock the adj
             */
            adj_delegate_remove(adj_get(ai), ADJ_DELEGATE_BFD);

            adj_bfd_update_walk(ai);
            adj_unlock(ai);
        }
        /*
         * else
         *  no BFD associated state
         */
        break;
    }

    /*
     * unlock match of the add-or-lock at the start
     */
    adj_unlock(ai);
}

static clib_error_t *
adj_bfd_main_init (vlib_main_t * vm)
{
    clib_error_t * error = NULL;

    if ((error = vlib_call_init_function (vm, bfd_main_init)))
        return (error);

    bfd_register_listener(adj_bfd_notify);

    return (error);
}

VLIB_INIT_FUNCTION (adj_bfd_main_init);
