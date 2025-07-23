// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <stdio.h>
#include <cbor.h>
#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>
#include "sasc.h"
#include "service.h"
#include "sasc_funcs.h"
#include <vlib/stats/stats.h>
#include "session.h"

/*
 * This file contains functions to export the SASC session database to a CBOR file.
 * Future improvement is to send request to worker threads and have the snapshot
 * generated locally by each worker.
 */

static cbor_item_t *
cbor_build_ip4(u32 addr) {
    return cbor_build_tag(52, cbor_build_bytestring((const unsigned char *)&addr, 4));
}

static cbor_item_t *
cbor_build_ip6(ip6_address_t *addr) {
    return cbor_build_tag(54, cbor_build_bytestring((const unsigned char *)addr, 16));
}

static cbor_item_t *
cbor_build_ip46(ip46_address_t *addr) {
    if (ip46_address_is_ip4(addr))
        return cbor_build_ip4(addr->ip4.as_u32);
    else
        return cbor_build_ip6(&addr->ip6);
}

#define SASC_CBOR_TAG_5TUPLE 32768

static cbor_item_t *
cbor_build_session_key(sasc_session_key_t *k) {
    cbor_item_t *cbor = cbor_new_definite_array(6);
    if (!cbor)
        return 0;
    if ((!cbor_array_push(cbor, cbor_move(cbor_build_uint32(k->context_id))) ||
         !cbor_array_push(cbor, cbor_move(cbor_build_ip46(&k->src))) ||
         !cbor_array_push(cbor, cbor_move(cbor_build_uint16(ntohs(k->sport)))) ||
         !cbor_array_push(cbor, cbor_move(cbor_build_uint8(k->proto))) ||
         !cbor_array_push(cbor, cbor_move(cbor_build_ip46(&k->dst))) ||
         !cbor_array_push(cbor, cbor_move(cbor_build_uint16(ntohs(k->dport)))))) {
        cbor_decref(&cbor);
        return 0;
    }
    return cbor_build_tag(SASC_CBOR_TAG_5TUPLE, cbor);
}

static cbor_item_t *
cbor_build_counters(sasc_session_t *session) {
    cbor_item_t *counters = cbor_new_definite_array(6);

    for (int i = 0; i < SASC_FLOW_F_B_N; i++) {
        if (!cbor_array_push(counters, cbor_move(cbor_build_uint64(session->bytes[i]))) ||
            !cbor_array_push(counters, cbor_move(cbor_build_uint32(session->pkts[i])))) {
            cbor_decref(&counters);
            counters = 0;
            break;
        }
    }
    return counters;
}

static cbor_item_t *session_states[SASC_SESSION_N_STATE];

static void
init_session_states(void) {
#define _(name, val, str) session_states[SASC_SESSION_STATE_##name] = cbor_build_string(str);
    foreach_sasc_session_state
#undef _
}

static cbor_item_t *
cbor_build_session_state(u8 state) {
    if (state >= SASC_SESSION_N_STATE || session_states[state] == NULL)
        return cbor_build_string("UNKNOWN");
    return session_states[state];
}

// Function to encode a nat_session_t as a CBOR array and write it to a file
cbor_item_t *
sasc_session_to_cbor(sasc_session_t *session) {
    sasc_tenant_t *tenant = sasc_tenant_at_index(&sasc_main, session->tenant_idx);
    cbor_item_t *s = cbor_new_definite_array(11); // 10 session fields + 1 services map

    f64 remaining_time = sasc_session_remaining_time(session, vlib_time_now(vlib_get_main()));
    u32 created = session->created + sasc_main.unix_time_0;
    u32 last_heard = session->last_heard + sasc_main.unix_time_0;
    if (!cbor_array_push(s, cbor_move(cbor_build_uint32(tenant ? tenant->context_id : 0))) ||
        !cbor_array_push(s, cbor_move(cbor_build_uint64(session - sasc_main.sessions))) ||
        !cbor_array_push(s, cbor_move(cbor_build_session_state(session->state))) ||
        !cbor_array_push(s, cbor_move(cbor_build_uint32(session->thread_index))) ||
        !cbor_array_push(
            s, cbor_move(cbor_build_session_key(&session->keys[SASC_SESSION_KEY_PRIMARY]))) ||
        !cbor_array_push(
            s, cbor_move(cbor_build_session_key(&session->keys[SASC_SESSION_KEY_SECONDARY]))) ||
        !cbor_array_push(s, cbor_build_tag(1, cbor_move(cbor_build_uint32(created)))) ||
        !cbor_array_push(s, cbor_build_tag(1, cbor_move(cbor_build_uint32(last_heard)))) ||
        !cbor_array_push(s, cbor_move(cbor_build_uint32(remaining_time))) ||
        !cbor_array_push(s, cbor_move(cbor_build_counters(session))) ||
        !cbor_array_push(s,
                         cbor_move(cbor_new_indefinite_map()))) { // Empty services map placeholder
        cbor_decref(&s);
        s = 0;
    }
    return s;
}

static void
serialize_sasc_session_services_cbor(cbor_item_t *session_array, u32 thread_index,
                                     sasc_session_t *session) {
    sasc_main_t *sasc = &sasc_main;
    sasc_service_main_t *sm = &sasc_service_main;
    u32 *service_index;
    u32 session_idx = session - sasc->sessions;
    u32 *forward_chain = sasc->effective_service_chains[session->service_chain[SASC_FLOW_FORWARD]];

    // Get the services map (11th element, index 10)
    cbor_item_t *services_map = cbor_array_get(session_array, 10);
    if (!services_map) {
        sasc_log_err("Failed to get services map from session array");
        return;
    }

    vec_foreach (service_index, forward_chain) {
        if (*service_index < vec_len(sm->services) &&
            sm->services[*service_index]->format_service_cbor) {
            cbor_item_t *service_obj =
                sm->services[*service_index]->format_service_cbor(thread_index, session_idx);
            if (service_obj) {
                bool success = cbor_map_add(
                    services_map, (struct cbor_pair){.key = cbor_move(cbor_build_string(
                                                         sm->services[*service_index]->node_name)),
                                                     .value = cbor_move(service_obj)});
                if (!success) {
                    sasc_log_err("Failed to format service %s for session %U",
                                 sm->services[*service_index]->node_name, format_sasc_session_key,
                                 &session->forward_key);
                }
            }
        }
    }
}

size_t
sasc_sessions_serialize(unsigned char **buffer, u32 *no_sessions) {
    sasc_main_t *sasc = &sasc_main;
    sasc_session_t *session;
    cbor_item_t *spt;
    *no_sessions = 0;
    u32 thread_index = 0;

    if (pool_elts(sasc->sessions) == 0) {
        return 0;
    }

    spt = cbor_new_definite_array(pool_elts(sasc->sessions));
    pool_foreach (session, sasc->sessions) {
        cbor_item_t *session_obj = sasc_session_to_cbor(session);
        if (!session_obj) {
            cbor_decref(&spt);
            return 0;
        }

        // Add service data to the session object
        serialize_sasc_session_services_cbor(session_obj, thread_index, session);

        if (!cbor_array_push(spt, cbor_move(session_obj))) {
            cbor_decref(&spt);
            return 0;
        }
    }

    // Encode the CBOR array into a byte buffer
    size_t buffer_size, length = cbor_serialize_alloc(spt, buffer, &buffer_size);
    cbor_decref(&spt);
    if (spt) {
        sasc_log_err("Dangling reference somwhere %d", cbor_refcount(spt));
    }
    return length;
}

int
sasc_sessions_to_file(const char *filename) {
    unsigned char *buffer;
    u32 no_sessions;
    size_t length = sasc_sessions_serialize(&buffer, &no_sessions);
    if (length == 0) {
        sasc_log_err("Failed to serialize sessions, length %d", length);
        return -1; // Failed to serialize
    }
    // Write the CBOR byte buffer to the file
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        clib_mem_free(buffer);
        sasc_log_err("Failed to open file %s", filename);
        return -1; // Failed to open file
    }

    size_t written = fwrite(buffer, sizeof(unsigned char), length, fp);
    fclose(fp);

    // Clean up CBOR object and buffer
    clib_mem_free(buffer);
    sasc_log_debug("written %d bytes per session: %d", written, written / no_sessions);
    if (written == length) {
        return 0; // Success
    } else {
        return -2; // Failed to write all bytes
    }
}

static clib_error_t *
sasc_dump_sessions_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    char *filename = 0;

    if (unformat_user(input, unformat_line_input, line_input)) {
        while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
            if (unformat(line_input, "%s", &filename))
                ;
            else {
                err = unformat_parse_error(line_input);
                break;
            }
        }
        unformat_free(line_input);
    }
    if (err)
        return err;

    /* Ask workers to do snapshot */
    sasc_sessions_to_file(filename);

    return err;
}

VLIB_CLI_COMMAND(dump_sasc_session_command, static) = {
    .path = "dump sasc session",
    .short_help = "dump sasc session <filename>",
    .function = sasc_dump_sessions_command_fn,
};

#define SASC_RING_ENTRY_SIZE 1024 // 512 bytes fixed size per entry

// Global stats ring buffer index
static u32 sasc_stats_ring_index = ~0;

// Initialize stats ring buffer
void
sasc_ring_init(u32 ring_size) {
    vlib_stats_ring_config_t config = {.entry_size = SASC_RING_ENTRY_SIZE,
                                       .ring_size = ring_size,
                                       .n_threads = vlib_get_n_threads()};

    sasc_stats_ring_index = vlib_stats_add_ring_buffer(&config, "/sasc/session/events");
    if (sasc_stats_ring_index == CLIB_U32_MAX) {
        sasc_log_err("Failed to create SASC stats ring buffer");
    }
}

// Producer: Write CBOR directly to stats ring buffer
bool
sasc_ring_write_cbor(u32 thread_index, cbor_item_t *obj) {
    if (sasc_stats_ring_index == CLIB_U32_MAX)
        return false;

    // Reserve a slot for direct serialization
    void *slot = vlib_stats_ring_reserve_slot(sasc_stats_ring_index, thread_index);
    if (!slot)
        return false;

    // Serialize CBOR directly into the slot (zero copy)
    size_t serialized_size = cbor_serialize(obj, slot, SASC_RING_ENTRY_SIZE);
    if (serialized_size > SASC_RING_ENTRY_SIZE) {
        vlib_stats_ring_abort_slot(sasc_stats_ring_index, thread_index);
        return false;
    }

    // Commit the slot
    if (vlib_stats_ring_commit_slot(sasc_stats_ring_index, thread_index) != 0) {
        return false;
    }

    return true;
}

static void
sasc_session_expiry_callback(u32 *session_indices) {
    u32 thread_index = 0;
    if (vec_len(session_indices) == 0)
        return;

    sasc_main_t *sasc = &sasc_main;
    sasc_session_t *session;
    u32 *session_index;

    vec_foreach (session_index, session_indices) {
        session = sasc_session_at_index(sasc, *session_index);
        if (!session)
            continue;

        cbor_item_t *session_obj = sasc_session_to_cbor(session);
        if (!session_obj)
            continue;

        // Add service data to the session object
        serialize_sasc_session_services_cbor(session_obj, thread_index, session);

        if (!sasc_ring_write_cbor(thread_index, session_obj)) {
            sasc_log_err("Error writing session to ring buffer: %u: %U", *session_index,
                         format_sasc_session_key, &session->forward_key);
        }

        cbor_decref(&session_obj);
    }
}

static clib_error_t *
sasc_dump_sessions_ring_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    u32 ring_size = 1024;
    if (unformat_user(input, unformat_line_input, line_input)) {
        while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
            if (unformat(line_input, "%d", &ring_size))
                ;
        }
    }
    sasc_ring_init(ring_size);
    sasc_session_expiry_cb_register(sasc_session_expiry_callback);

    return 0;
}

VLIB_CLI_COMMAND(dump_sasc_session_ring_command, static) = {
    .path = "dump sasc session ring",
    .short_help = "dump sasc session ring <ring_size>",
    .function = sasc_dump_sessions_ring_command_fn,
};

clib_error_t *
sasc_export_init(vlib_main_t *vm) {
    init_session_states();
    return 0;
}

VLIB_INIT_FUNCTION(sasc_export_init);