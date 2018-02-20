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

/**
 * Distillation of the BFD session states into a go/no-go for using
 * the associated tracked adjacency
 */
typedef enum adj_bfd_state_t_
{
    ADJ_BFD_STATE_DOWN,
    ADJ_BFD_STATE_UP,
} adj_bfd_state_t;

/**
 * BFD delegate daa
 */
typedef struct adj_bfd_delegate_t_
{
    /**
     * BFD session state
     */
    adj_bfd_state_t abd_state;

    /**
     * BFD session index
     */
    u32 abd_index;
} adj_bfd_delegate_t;

/**
 * Pool of delegates
*/
static adj_bfd_delegate_t *abd_pool;

static inline adj_bfd_delegate_t*
adj_bfd_from_base (adj_delegate_t *ad)
{
    if (NULL != ad)
    {
        return (pool_elt_at_index(abd_pool, ad->ad_index));
    }
    return (NULL);
}

static inline const adj_bfd_delegate_t*
adj_bfd_from_const_base (const adj_delegate_t *ad)
{
    if (NULL != ad)
    {
        return (pool_elt_at_index(abd_pool, ad->ad_index));
    }
    return (NULL);
}

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
    adj_bfd_delegate_t *abd;
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

            /*
             * allocate and init a new delegate struct
             */
            pool_get(abd_pool, abd);

            /*
             * pretend the session is up and skip the walk.
             * If we set it down then we get traffic loss on new children.
             * if we walk then we lose traffic for existing children. Wait
             * for the first BFD UP/DOWN before we let the session's state
             * influence forwarding.
             */
            abd->abd_state = ADJ_BFD_STATE_UP;
            abd->abd_index = session->bs_idx;

            adj_delegate_add(adj_get(ai), ADJ_DELEGATE_BFD, abd - abd_pool);
        }
        break;

    case BFD_LISTEN_EVENT_UPDATE:
        /*
         * state change up/dowm and
         */
        abd = adj_bfd_from_base(adj_delegate_get(adj_get(ai), ADJ_DELEGATE_BFD));

        if (NULL != abd)
        {
            abd->abd_state = adj_bfd_bfd_state_to_fib(session->local_state);
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
        abd = adj_bfd_from_base(adj_delegate_get(adj_get(ai), ADJ_DELEGATE_BFD));

        if (NULL != abd)
        {
            /*
             * has an associated BFD tracking delegate
             * remove the BFD tracking deletgate, update children, then
             * unlock the adj
             */
            adj_delegate_remove(ai, ADJ_DELEGATE_BFD);
            pool_put(abd_pool, abd);

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

int
adj_bfd_is_up (adj_index_t ai)
{
    const adj_bfd_delegate_t *abd;

    abd = adj_bfd_from_base(adj_delegate_get(adj_get(ai), ADJ_DELEGATE_BFD));

    if (NULL == abd)
    {
        /*
         * no BFD tracking - resolved
         */
        return (!0);
    }
    else
    {
        /*
         * defer to the state of the BFD tracking
         */
        return (ADJ_BFD_STATE_UP == abd->abd_state);
    }
}

/**
 * Print a delegate that represents BFD tracking
 */
static u8 *
adj_delegate_fmt_bfd (const adj_delegate_t *aed, u8 *s)
{
    const adj_bfd_delegate_t *abd = adj_bfd_from_const_base(aed);

    s = format(s, "BFD:[state:%d index:%d]",
               abd->abd_state,
               abd->abd_index);

    return (s);
}

const static adj_delegate_vft_t adj_delegate_vft = {
  .adv_format = adj_delegate_fmt_bfd,
};

static clib_error_t *
adj_bfd_main_init (vlib_main_t * vm)
{
    clib_error_t * error = NULL;

    if ((error = vlib_call_init_function (vm, bfd_main_init)))
        return (error);

    bfd_register_listener(adj_bfd_notify);

    adj_delegate_register_type (ADJ_DELEGATE_BFD, &adj_delegate_vft);

    return (error);
}

VLIB_INIT_FUNCTION (adj_bfd_main_init);
