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

static cbor_item_t *session_states[7]; // SASC_SESSION_N_STATE = 7
static void
init_session_states(void) {
    session_states[0] = cbor_build_string("FSOL");            // SASC_SESSION_STATE_FSOL
    session_states[1] = cbor_build_string("ESTABLISHED");     // SASC_SESSION_STATE_ESTABLISHED
    session_states[2] = cbor_build_string("TIME_WAIT");       // SASC_SESSION_STATE_TIME_WAIT
    session_states[3] = cbor_build_string("TCP_TRANSITORY");  // SASC_SESSION_STATE_TCP_TRANSITORY
    session_states[4] = cbor_build_string("TCP_ESTABLISHED"); // SASC_SESSION_STATE_TCP_ESTABLISHED
    session_states[5] = cbor_build_string("STATIC");          // SASC_SESSION_STATE_STATIC
    session_states[6] = cbor_build_string("EXPIRED");         // SASC_SESSION_STATE_EXPIRED
}

static cbor_item_t *
cbor_build_session_state(u8 state) {
    return session_states[state];
}

// Function to encode a nat_session_t as a CBOR array and write it to a file
cbor_item_t *
sasc_session_to_cbor(sasc_session_t *session) {
    init_session_states();
    sasc_tenant_t *tenant = sasc_tenant_at_index(&sasc_main, session->tenant_idx);
    cbor_item_t *s = cbor_new_definite_array(10);

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
        !cbor_array_push(s, cbor_move(cbor_build_counters(session)))) {
        cbor_decref(&s);
        s = 0;
    }
    return s;
}

static void
serialize_sasc_session_services_cbor(cbor_item_t *session_obj, u32 thread_index,
                                     sasc_session_t *session) {
    sasc_main_t *sasc = &sasc_main;
    sasc_service_main_t *sm = &sasc_service_main;
    u32 *service_index;
    u32 session_idx = session - sasc->sessions;
    u32 *forward_chain = sasc->effective_service_chains[session->service_chain[SASC_FLOW_FORWARD]];
    bool success = false;
    vec_foreach (service_index, forward_chain) {
        if (*service_index < vec_len(sm->services) &&
            sm->services[*service_index]->format_service_cbor) {
            cbor_item_t *service_obj =
                sm->services[*service_index]->format_service_cbor(thread_index, session_idx);
            if (service_obj) {
                success = cbor_map_add(
                    session_obj, (struct cbor_pair){.key = cbor_move(cbor_build_string(
                                                        sm->services[*service_index]->node_name)),
                                                    .value = cbor_move(service_obj)});
            }
            if (!success) {
                sasc_log_err("Failed to format service %s for session %U",
                             sm->services[*service_index]->node_name, format_sasc_session_key,
                             &session->forward_key);
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

    spt = cbor_new_definite_array(pool_elts(sasc->sessions));
    pool_foreach (session, sasc->sessions) {
        if (!cbor_array_push(spt, sasc_session_to_cbor(session))) {
            cbor_decref(&spt);
            return 0;
        }
        // Allow services to add additional data to the session
        serialize_sasc_session_services_cbor(spt, thread_index, session);
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

    // Serialize CBOR directly into the slot
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

// Producer: Write multiple CBOR objects using batch API for better performance
bool
sasc_ring_write_cbor_batch(u32 thread_index, cbor_item_t **objs, u32 count) {
    if (sasc_stats_ring_index == CLIB_U32_MAX || count == 0)
        return false;

    // Reserve multiple slots for batch serialization
    void **slots = vlib_stats_ring_reserve_batch(sasc_stats_ring_index, thread_index, count);
    if (!slots)
        return false;

    bool success = true;
    for (u32 i = 0; i < count; i++) {
        if (!objs[i]) {
            success = false;
            break;
        }

        // Serialize CBOR directly into the slot
        size_t serialized_size = cbor_serialize(objs[i], slots[i], SASC_RING_ENTRY_SIZE);
        if (serialized_size > SASC_RING_ENTRY_SIZE) {
            success = false;
            break;
        }
    }

    if (success) {
        // Commit all slots at once
        if (vlib_stats_ring_commit_batch(sasc_stats_ring_index, thread_index, count) != 0) {
            success = false;
        }
    }

    // Clean up allocated slots array
    clib_mem_free(slots);
    return success;
}

static void
sasc_session_expiry_callback(u32 *session_indices) {
    sasc_main_t *sasc = &sasc_main;
    u32 *session_index;
    sasc_session_t *session;
    u32 thread_index = 0;
    u32 session_count = vec_len(session_indices);

    if (session_count == 0)
        return;

    // Use batch API for better performance when multiple sessions expire
    if (session_count > 1) {
        // Pre-allocate CBOR objects array for batch processing
        cbor_item_t **session_objs = clib_mem_alloc(session_count * sizeof(cbor_item_t *));
        if (!session_objs) {
            // Fall back to individual writes if allocation fails
            goto individual_writes;
        }

        u32 valid_count = 0;
        vec_foreach (session_index, session_indices) {
            session = sasc_session_at_index(sasc, *session_index);
            session_objs[valid_count] = cbor_new_indefinite_map();

            bool success =
                cbor_map_add(session_objs[valid_count],
                             (struct cbor_pair){.key = cbor_move(cbor_build_string("session")),
                                                .value = cbor_move(sasc_session_to_cbor(session))});

            if (!success) {
                sasc_log_err("Failed to add session to CBOR map");
                cbor_decref(&session_objs[valid_count]);
                continue;
            }

            sasc_log_debug("Session expired: %U", format_sasc_session_key, &session->forward_key);

            // Add service data if available
            serialize_sasc_session_services_cbor(session_objs[valid_count], thread_index, session);
            valid_count++;
        }

        // Write all sessions in batch
        if (valid_count > 0) {
            if (!sasc_ring_write_cbor_batch(thread_index, session_objs, valid_count)) {
                sasc_log_err("Ring full, dropping %u sessions", valid_count);
            }
        }

        // Cleanup CBOR objects
        for (u32 i = 0; i < valid_count; i++) {
            cbor_decref(&session_objs[i]);
        }
        clib_mem_free(session_objs);
    } else {
    // Single session - use individual write
    individual_writes:
        vec_foreach (session_index, session_indices) {
            cbor_item_t *session_obj = cbor_new_indefinite_map();
            session = sasc_session_at_index(sasc, *session_index);
            bool success = cbor_map_add(
                session_obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("session")),
                                                .value = cbor_move(sasc_session_to_cbor(session))});
            if (!success) {
                sasc_log_err("Failed to add session to CBOR map");
                continue;
            }

            sasc_log_debug("Session expired: %U", format_sasc_session_key, &session->forward_key);

            // Add service data if available
            serialize_sasc_session_services_cbor(session_obj, thread_index, session);

            // Write CBOR directly to ring
            if (!sasc_ring_write_cbor(thread_index, session_obj)) {
                sasc_log_err("Ring full, dropping session %U", format_sasc_session_key,
                             &session->forward_key);
            }

            // Cleanup CBOR object
            cbor_decref(&session_obj);
        }
    }
}

// Export multiple sessions to ring buffer using batch API
int
sasc_sessions_to_ring_batch(u32 thread_index, u32 *session_indices, u32 count) {
    if (sasc_stats_ring_index == CLIB_U32_MAX || count == 0)
        return -1;

    sasc_main_t *sasc = &sasc_main;
    sasc_session_t *session;
    u32 *session_index;

    // Pre-allocate CBOR objects array for batch processing
    cbor_item_t **session_objs = clib_mem_alloc(count * sizeof(cbor_item_t *));
    if (!session_objs) {
        sasc_log_err("Failed to allocate memory for batch session export");
        return -1;
    }

    u32 valid_count = 0;
    vec_foreach (session_index, session_indices) {
        if (valid_count >= count)
            break;

        session = sasc_session_at_index(sasc, *session_index);
        if (!session) {
            sasc_log_err("Invalid session index: %u", *session_index);
            continue;
        }

        session_objs[valid_count] = cbor_new_indefinite_map();

        bool success =
            cbor_map_add(session_objs[valid_count],
                         (struct cbor_pair){.key = cbor_move(cbor_build_string("session")),
                                            .value = cbor_move(sasc_session_to_cbor(session))});

        if (!success) {
            sasc_log_err("Failed to add session to CBOR map");
            cbor_decref(&session_objs[valid_count]);
            continue;
        }

        // Add service data if available
        serialize_sasc_session_services_cbor(session_objs[valid_count], thread_index, session);
        valid_count++;
    }

    // Write all sessions in batch
    int result = 0;
    if (valid_count > 0) {
        if (!sasc_ring_write_cbor_batch(thread_index, session_objs, valid_count)) {
            sasc_log_err("Ring full, dropping %u sessions", valid_count);
            result = -1;
        } else {
            sasc_log_debug("Successfully exported %u sessions to ring buffer", valid_count);
        }
    }

    // Cleanup CBOR objects
    for (u32 i = 0; i < valid_count; i++) {
        cbor_decref(&session_objs[i]);
    }
    clib_mem_free(session_objs);

    return result;
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

// CLI command to test batch export functionality
static clib_error_t *
sasc_test_batch_export_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    u32 count = 100; // Default batch size
    u32 thread_index = 0;

    if (unformat_user(input, unformat_line_input, line_input)) {
        while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
            if (unformat(line_input, "count %d", &count))
                ;
            else if (unformat(line_input, "thread %d", &thread_index))
                ;
        }
    }

    if (sasc_stats_ring_index == CLIB_U32_MAX) {
        return clib_error_return(
            0, "Ring buffer not initialized.");
    }

    sasc_main_t *sasc = &sasc_main;
    sasc_session_t *session;
    u32 *session_indices = 0;
    u32 session_count = 0;

    // Collect session indices (up to count)
    pool_foreach (session, sasc->sessions) {
        if (session_count >= count)
            break;
        vec_add1(session_indices, session - sasc->sessions);
        session_count++;
    }

    if (session_count == 0) {
        return clib_error_return(0, "No sessions available for export.");
    }

    // Measure performance
    f64 start_time = vlib_time_now(vm);

    // Export using batch API
    int result = sasc_sessions_to_ring_batch(thread_index, session_indices, session_count);

    f64 end_time = vlib_time_now(vm);
    f64 duration_ns = (end_time - start_time) * 1e9;

    if (result == 0) {
        vlib_cli_output(vm, "Successfully exported %u sessions in %.2f ns (%.2f ns/session)\n",
                        session_count, duration_ns, duration_ns / session_count);
    } else {
        vlib_cli_output(vm, "Failed to export sessions\n");
    }

    vec_free(session_indices);
    return 0;
}

VLIB_CLI_COMMAND(sasc_test_batch_export_command, static) = {
    .path = "test sasc batch export",
    .short_help = "test sasc batch export [count <n>] [thread <n>]",
    .function = sasc_test_batch_export_command_fn,
};
