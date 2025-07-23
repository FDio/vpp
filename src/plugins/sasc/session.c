// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <sasc/service.h>
#include <vppinfra/bihash_40_8.h>
#include <sasc/sasc_funcs.h>
#include <sasc/lookup/lookup_inlines.h>
#include <sasc/sasc.api_enum.h>
#include "session.h"
#include "format.h"
#include "counter.h"

/*
 * Create a static SASC session. (No timer)
 */
void sasc_set_service_chain(sasc_tenant_t *tenant, u8 proto, u32 *bitmaps);
void sasc_set_session_service_chain(sasc_tenant_t *tenant, sasc_session_t *session, u8 proto);

static inline sasc_session_t *
sasc_session_from_lookup_value(sasc_main_t *sasc, u64 value, u32 *thread_index, u32 *session_index) {
    // Figure out if this is local or remote thread
    *thread_index = sasc_thread_index_from_lookup(value);
    /* known flow which belongs to this thread */
    u32 flow_index = value & (~(u32)0);
    *session_index = sasc_session_from_flow_index(flow_index);
    return sasc_session_at_index_check(sasc, *session_index);
}

static int
sasc_session_add_del_key(sasc_session_key_t *k, int is_add, u64 value, u64 *h) {
    sasc_main_t *sasc = &sasc_main;
    clib_bihash_kv_40_8_t kv;

    clib_memcpy(&kv.key, k, 40);
    kv.value = value;
    *h = clib_bihash_hash_40_8(&kv);
    return clib_bihash_add_del_with_hash_40_8(&sasc->session_hash, &kv, *h, is_add);
}

sasc_session_t *
sasc_create_session(u16 tenant_idx, sasc_session_key_t *primary, sasc_session_key_t *secondary, bool is_static,
                    u32 *flow_index) {
    sasc_main_t *sasc = &sasc_main;
    u32 thread_index = vlib_get_thread_index();
    sasc_tenant_t *tenant = sasc_tenant_at_index(sasc, tenant_idx);
    if (!tenant) {
        sasc_log_err("Unknown tenant %d", tenant_idx);
        return 0;
    }

    // Validate keys
    if (!primary || (secondary && memcmp(primary, secondary, sizeof(*primary)) == 0)) {
        sasc_log_err("Invalid key combination");
        return 0;
    }

    // Check if session already exists (check both forward and reverse keys)
    u64 h;
    clib_bihash_kv_40_8_t kv;
    u32 session_index;
    sasc_session_t *session = 0;

    // Check forward key
    clib_memcpy(&kv.key, primary, sizeof(*primary));
    if (!clib_bihash_search_inline_40_8(&sasc->session_hash, &kv)) {
        session = sasc_session_from_lookup_value(sasc, kv.value, &thread_index, &session_index);
        if (session) {
            *flow_index = kv.value & (~(u32)0);
            return session;
        }
    }

    // Check reverse key (for reply packets)
    if (secondary) {
        clib_memcpy(&kv.key, secondary, sizeof(*secondary));
        if (!clib_bihash_search_inline_40_8(&sasc->session_hash, &kv)) {
            session = sasc_session_from_lookup_value(sasc, kv.value, &thread_index, &session_index);
            if (session) {
                // For reply packets, we need to use the reverse flow index
                *flow_index = (kv.value & (~(u32)0)) | 0x1;
                return session;
            }
        }
    }

    // Check pool availability
    if (pool_free_elts(sasc->sessions) == 0) {
        sasc_log_err("No free sessions available");
        return 0;
    }

    // Allocate session
    pool_get(sasc->sessions, session);
    u16 version = session->session_version;
    clib_memset(session, 0, sizeof(*session));
    u32 session_idx = session - sasc->sessions;
    u32 pseudo_flow_idx = (session_idx << 1); // Keep this for direction bit
    u64 value = sasc_session_mk_table_value(thread_index, pseudo_flow_idx);
    session->thread_index = thread_index;
    *flow_index = pseudo_flow_idx; // Keep original flow index for direction

    // Try to add forward key
    if (sasc_session_add_del_key(primary, 2, value, &h)) {
        /* Race condition - someone else added the key */
        sasc_log_err("session already exists %U", format_sasc_session_key, primary);
        pool_put(sasc->sessions, session);
        return 0;
    }

    // Try to add reverse key
    if (secondary) {
        if (sasc_session_add_del_key(secondary, 2, value | 0x1, &h)) {
            /* Race condition - someone else added the reverse key */
            sasc_log_err("reverse key already exists %U", format_sasc_session_key, secondary);
            // Clean up the forward key we just added
            sasc_session_add_del_key(primary, 0, 0, &h);
            pool_put(sasc->sessions, session);
            return 0;
        }
    }

    // Initialize session
    sasc_session_slow_path_t *sp = vec_elt_at_index(sasc->sp_sessions, session_idx);
    clib_memcpy_fast(&sp->forward_key, primary, sizeof(sp->forward_key));
    if (secondary) {
        clib_memcpy_fast(&sp->reverse_key, secondary, sizeof(sp->reverse_key));
    }

    session->state = SASC_SESSION_STATE_FSOL;
    session->session_version = version + 1;
    session->protocol = primary->proto;
    session->last_heard = (u32)vlib_time_now(vlib_get_main());
    session->tenant_idx = tenant_idx;
    session->created = session->last_heard;

    /* Assign service chain */
    sasc_set_session_service_chain(tenant, session, primary->proto);

    if (is_static) {
        session->state = SASC_SESSION_STATE_STATIC;
    }
    sasc_log_debug("Created session [%u] %U", session_idx, format_sasc_session_key, &sp->forward_key);

    vlib_stats_set_gauge(sasc->active_sessions, pool_elts(sasc->sessions));

    return session;
}

sasc_session_t *
sasc_lookup_session(u32 context_id, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst, u16 dport) {
    sasc_main_t *sasc = &sasc_main;
    u64 value;
    if (!src || !dst)
        return 0;
    if (src->version != dst->version)
        return 0;

    if (src->version == AF_IP6) {
        ;
    };

    sasc_session_key_t k = {
        .context_id = context_id,
        .src = src->ip,
        .dst = dst->ip,
        .sport = sport,
        .dport = dport,
        .proto = protocol,
    };
    clib_warning("Looking up: %U", format_sasc_session_key, &k);

    clib_bihash_kv_40_8_t kv;
    clib_memcpy(&kv.key, &k, sizeof(k));
    if (clib_bihash_search_inline_40_8(&sasc->session_hash, &kv))
        return 0;
    value = kv.value;
    u32 thread_index, session_index;

    return sasc_session_from_lookup_value(sasc, value, &thread_index, &session_index);
}

void
sasc_session_remove_core(sasc_main_t *sasc, sasc_session_t *session, u32 thread_index, u32 session_index,
                         bool stop_timer) {
    u64 h;
    // Assert that we are removing the session from the same thread. Unless barrier is set.
    ASSERT(session->thread_index == thread_index || vlib_worker_thread_barrier_held());

    sasc_session_slow_path_t *sp = vec_elt_at_index(sasc->sp_sessions, session_index);
    /* Stop timer if running */
    sasc_log_debug("Removing session %u %U", session_index, format_sasc_session_key, &sp->forward_key);
    if (sasc_session_add_del_key(&sp->forward_key, 0, 0, &h)) {
        sasc_log_err("Failed to remove session key from table");
    }
    if (sasc_session_add_del_key(&sp->reverse_key, 0, 0, &h)) {
        sasc_log_err("Failed to remove session from session hash - secondary");
    }
    vlib_increment_simple_counter(&sasc->counters[SASC_COUNTER_REMOVED], thread_index, session->tenant_idx, 1);

    pool_put_index(sasc->sessions, session_index);
    vlib_stats_set_gauge(sasc->active_sessions, pool_elts(sasc->sessions));
}

void
sasc_session_remove(sasc_main_t *sasc, sasc_session_t *session, u32 thread_index, u32 session_index) {
    sasc_session_remove_core(sasc, session, thread_index, session_index, true);
}

/*
 * An existing session is being reused for a new flow with the same 6-tuple.
 * Reset counters.
 */
void
sasc_session_reopen(sasc_main_t *sasc, u32 thread_index, sasc_session_t *session) {
#if 0
  vlib_increment_simple_counter(&sasc->tenant_simple_ctr[SASC_TENANT_COUNTER_REMOVED], thread_index,
                                session->tenant_idx, 1);
  vlib_increment_simple_counter(&sasc->tenant_simple_ctr[SASC_TENANT_COUNTER_CREATED], thread_index,
                                session->tenant_idx, 1);
  vlib_increment_simple_counter(&sasc->tenant_simple_ctr[SASC_TENANT_COUNTER_REUSED], thread_index, session->tenant_idx,
                                1);
#endif
    session->bytes[SASC_FLOW_FORWARD] = 0;
    session->bytes[SASC_FLOW_REVERSE] = 0;
    session->pkts[SASC_FLOW_FORWARD] = 0;
    session->pkts[SASC_FLOW_REVERSE] = 0;
}

bool
sasc_session_is_expired(sasc_session_t *session, u32 now) {
    if (session->state == SASC_SESSION_STATE_STATIC)
        return false;

    u32 timeout = sasc_session_get_timeout(&sasc_main, session);
    return (now >= session->last_heard + timeout);
}

bool
sasc_session_is_expired_session_idx(sasc_main_t *sasc, u32 session_index) {
    sasc_session_t *session = sasc_session_at_index(sasc, session_index);
    return sasc_session_is_expired(session, vlib_time_now(vlib_get_main()));
}

int
sasc_session_try_add_secondary_key(sasc_main_t *sasc, u32 thread_index, u32 pseudo_flow_index,
                                   sasc_session_key_t *key) {
    u64 value;
    u32 session_index;
    u64 h;

    value = sasc_session_mk_table_value(thread_index, pseudo_flow_index);
    session_index = sasc_session_from_flow_index(pseudo_flow_index);
    sasc_session_slow_path_t *sp = vec_elt_at_index(sasc->sp_sessions, session_index);
    clib_memcpy(&sp->reverse_key, key, sizeof(*key));

    return sasc_session_add_del_key(key, 2, value, &h);
}

/*
 * sasc_session_clear. Delete all sessions.
 * This requires to be called within a barrier.
 */
void
sasc_session_clear(void) {
    sasc_main_t *sasc = &sasc_main;
    u32 *to_delete = 0;
    u32 *session_index;
    sasc_session_t *session;

    ASSERT(vlib_worker_thread_barrier_held());

    pool_foreach (session, sasc->sessions) {
        if (session->state != SASC_SESSION_STATE_STATIC) {
            vec_add1(to_delete, session - sasc->sessions);
        }
    }
    vec_foreach (session_index, to_delete) {
        session = sasc_session_at_index(sasc, *session_index);
        sasc_session_remove(sasc, session, session->thread_index, *session_index);
    }
    vec_reset_length(to_delete);
}

int
sasc_session_generate_reverse_key(sasc_session_key_t *forward_key, sasc_session_key_t *reverse_key) {
    /* Generate reverse key by swapping source and destination addresses and ports */
    reverse_key->src = forward_key->dst;
    reverse_key->dst = forward_key->src;
    reverse_key->sport = forward_key->dport;
    reverse_key->dport = forward_key->sport;
    reverse_key->proto = forward_key->proto;
    reverse_key->context_id = forward_key->context_id;

    return 0;
}

/* Vector of registered callbacks */
static sasc_session_expiry_cb_t *expiry_callbacks;

int
sasc_session_expiry_cb_register(sasc_session_expiry_cb_t callback) {
    vec_add1(expiry_callbacks, callback);
    return 0;
}

int
sasc_session_expiry_cb_unregister(sasc_session_expiry_cb_t callback) {
    u32 i;
    vec_foreach_index (i, expiry_callbacks) {
        if (expiry_callbacks[i] == callback) {
            vec_delete(expiry_callbacks, 1, i);
            return 0;
        }
    }
    return -1;
}

/* Call all registered callbacks with the expired sessions */
static void
sasc_session_expiry_notify(u32 *session_indices) {
    sasc_session_expiry_cb_t *cb;
    vec_foreach (cb, expiry_callbacks) {
        (*cb)(session_indices);
    }
}

/*
 * Walk the session table and expire old entries.
 * This function should be called periodically to clean up expired sessions.
 * It uses a vector to collect sessions to delete to avoid modifying the pool while iterating.
 *
 * @param max_walk_entries Maximum number of entries to walk in one iteration
 * @param max_expire_entries Maximum number of entries to expire in one iteration
 * @param cursor Pointer to cursor for resuming walk in next iteration
 * @return true if there are more entries to walk, false if we've walked all entries
 */
bool
sasc_session_walk_and_expire(u32 max_walk_entries, u32 max_expire_entries, u32 *cursor) {
    sasc_main_t *sasc = &sasc_main;
    u32 *to_delete = 0;
    u32 *session_index;
    sasc_session_t *session;
    u32 now = (u32)vlib_time_now(vlib_get_main());
    u32 entries_walked = 0;
    u32 entries_to_expire = 0;
    u32 next = *cursor;

    /* First pass: collect sessions to delete */
    do {
        next = pool_next_index(sasc->sessions, next);
        if (next == ~0) {
            *cursor = ~0; /* No more entries to process */
            break;
        }

        /* Check if we've hit the walk limit */
        if (entries_walked >= max_walk_entries) {
            *cursor = next; /* Save position for next iteration */
            break;
        }
        entries_walked++;

        session = pool_elt_at_index(sasc->sessions, next);
        if (sasc_session_is_expired(session, now)) {
            /* Check if we've hit the expire limit */
            if (entries_to_expire >= max_expire_entries) {
                *cursor = next; /* Save position for next iteration */
                break;
            }
            vec_add1(to_delete, next);
            entries_to_expire++;
        }
    } while (1);

    /* Notify callbacks before deleting sessions */
    if (vec_len(to_delete) > 0) {
        sasc_session_expiry_notify(to_delete);
    }

    /* Second pass: delete collected sessions */
    vec_foreach (session_index, to_delete) {
        session = sasc_session_at_index(sasc, *session_index);
        sasc_session_slow_path_t *sp = vec_elt_at_index(sasc->sp_sessions, *session_index);
        sasc_log_debug("Removing session %u %U", *session_index, format_sasc_session_key, &sp->forward_key);
        sasc_session_remove(sasc, session, session->thread_index, *session_index);
    }

    /* Clean up */
    vec_reset_length(to_delete);

    return (next != ~0);
}

/*
 * Process node for session expiry
 */
static uword
sasc_session_expiry_process(vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f) {
    f64 timeout = 1.0; /* Run every second */
    u32 cursor = ~0;
    const u32 MAX_WALK = 1000;  /* Walk at most 1000 entries per iteration */
    const u32 MAX_EXPIRE = 100; /* Expire at most 100 sessions per iteration */

    while (1) {
        /* Process sessions until we hit limits or finish */
        while (sasc_session_walk_and_expire(MAX_WALK, MAX_EXPIRE, &cursor)) {
            /* Yield to other processes if we hit limits */
            vlib_process_suspend(vm, timeout);
        }
        /* Wait for next interval */
        vlib_process_suspend(vm, timeout);
    }
    return 0;
}

VLIB_REGISTER_NODE(sasc_session_expiry_node) = {
    .function = sasc_session_expiry_process,
    .name = "sasc-session-expiry",
    .type = VLIB_NODE_TYPE_PROCESS,
};

static clib_error_t *
sasc_session_expiry_init(vlib_main_t *vm) {
    vlib_process_signal_event(vm, sasc_session_expiry_node.index, 0, 0);
    return 0;
}

VLIB_INIT_FUNCTION(sasc_session_expiry_init);
