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
#include "export.h"
#include <vnet/ip/ip.h>

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

/**
 * Build a histogram CBOR object
 * Format: [buckets_array, min_value, max_value, bucket_count, bucket_width]
 */
static cbor_item_t *
cbor_build_histogram(const u64 *buckets, u32 bucket_count, u64 min_value, u64 max_value,
                     u64 bucket_width) {
    cbor_item_t *histogram = cbor_new_definite_array(5);
    if (!histogram)
        return 0;

    // Create buckets array
    cbor_item_t *buckets_array = cbor_new_definite_array(bucket_count);
    if (!buckets_array) {
        cbor_decref(&histogram);
        return 0;
    }

    for (u32 i = 0; i < bucket_count; i++) {
        if (!cbor_array_push(buckets_array, cbor_move(cbor_build_uint64(buckets[i])))) {
            cbor_decref(&histogram);
            cbor_decref(&buckets_array);
            return 0;
        }
    }

    // Add all components to histogram
    if (!cbor_array_push(histogram, cbor_move(buckets_array)) ||
        !cbor_array_push(histogram, cbor_move(cbor_build_uint64(min_value))) ||
        !cbor_array_push(histogram, cbor_move(cbor_build_uint64(max_value))) ||
        !cbor_array_push(histogram, cbor_move(cbor_build_uint32(bucket_count))) ||
        !cbor_array_push(histogram, cbor_move(cbor_build_uint64(bucket_width)))) {
        cbor_decref(&histogram);
        return 0;
    }

    return histogram;
}

/**
 * Build a histogram CBOR object (public interface)
 * Format: [buckets_array, min_value, max_value, bucket_count, bucket_width]
 */
cbor_item_t *
sasc_build_histogram_cbor(const u64 *buckets, u32 bucket_count, u64 min_value, u64 max_value,
                          u64 bucket_width) {
    return cbor_build_histogram(buckets, bucket_count, min_value, max_value, bucket_width);
}

#if 0
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
#endif
static cbor_item_t *session_states[SASC_SESSION_N_STATE];
static const char *session_state_strings[SASC_SESSION_N_STATE];
static void
init_session_states(void) {
#define _(name, val, str) session_states[SASC_SESSION_STATE_##name] = cbor_build_string(str);
    foreach_sasc_session_state
#undef _
#define _(name, val, str) session_state_strings[SASC_SESSION_STATE_##name] = str;
        foreach_sasc_session_state
#undef _
}

// Helper functions for computed session fields
static inline u64
get_session_index(const sasc_service_state_t *st, u32 session_index) {
    sasc_session_t *session = (sasc_session_t *)st;
    return session - sasc_main.sessions;
}

static inline u64
get_created_time(const sasc_service_state_t *st, u32 session_index) {
    sasc_session_t *session = (sasc_session_t *)st;
    return session->created + sasc_main.unix_time_0;
}

static inline u64
get_last_heard_time(const sasc_service_state_t *st, u32 session_index) {
    sasc_session_t *session = (sasc_session_t *)st;
    return session->last_heard + sasc_main.unix_time_0;
}

static inline u64
get_duration_time(const sasc_service_state_t *st, u32 session_index) {
    sasc_session_t *session = (sasc_session_t *)st;
    return session->last_heard - session->created;
}

static inline const char *
get_session_state_string(const sasc_service_state_t *st, u32 session_index) {
    sasc_session_t *session = (sasc_session_t *)st;
    return session_state_strings[session->state];
}

// Session field descriptions for schema generation
static const sasc_field_desc_t session_desc[] = {
    {"tenant_id", SASC_T_U32, offsetof(sasc_session_t, tenant_idx), -1, NULL, NULL, false},
    {"session_index", SASC_T_U64, offsetof(sasc_session_t, thread_index), -1,
     (sasc_get_u64_fn)get_session_index, NULL, false},
    {"state", SASC_T_TSTR, offsetof(sasc_session_t, state), -1, NULL, NULL,
     (sasc_get_str_fn)get_session_state_string, false},
    {"thread_index", SASC_T_U32, offsetof(sasc_session_t, thread_index), -1, NULL, NULL, false},
    {"forward_key", SASC_T_SESSION_KEY, offsetof(sasc_session_t, forward_key), -1, NULL, NULL,
     false},
    {"reverse_key", SASC_T_SESSION_KEY, offsetof(sasc_session_t, reverse_key), -1, NULL, NULL,
     false},
    {"created", SASC_T_TIMESTAMP, 0, -1, (sasc_get_u64_fn)get_created_time, NULL, false},
    {"last_heard", SASC_T_TIMESTAMP, 0, -1, (sasc_get_u64_fn)get_last_heard_time, NULL, false},
    {"duration", SASC_T_U32, 0, -1, (sasc_get_u64_fn)get_duration_time, NULL, false},
    {"bytes_forward", SASC_T_U64, offsetof(sasc_session_t, bytes), SASC_FLOW_FORWARD, NULL, NULL,
     false},
    {"bytes_reverse", SASC_T_U64, offsetof(sasc_session_t, bytes), SASC_FLOW_REVERSE, NULL, NULL,
     false},
    {"pkts_forward", SASC_T_U32, offsetof(sasc_session_t, pkts), SASC_FLOW_FORWARD, NULL, NULL,
     false},
    {"pkts_reverse", SASC_T_U32, offsetof(sasc_session_t, pkts), SASC_FLOW_REVERSE, NULL, NULL,
     false},
    {"service_chain_forward", SASC_T_U16, offsetof(sasc_session_t, service_chain),
     SASC_FLOW_FORWARD, NULL, NULL, false},
    {"service_chain_reverse", SASC_T_U16, offsetof(sasc_session_t, service_chain),
     SASC_FLOW_REVERSE, NULL, NULL, false},
};

static const size_t session_field_count = sizeof(session_desc) / sizeof(session_desc[0]);

static cbor_item_t *
format_sasc_session_cbor(sasc_session_t *session) {
    return sasc_encode_array_generic(session_desc, session_field_count,
                                     (const sasc_service_state_t *)session,
                                     session - sasc_main.sessions);
}

static void
serialize_sasc_session_services_cbor(cbor_item_t *services_map, u32 thread_index,
                                     sasc_session_t *session) {
    sasc_main_t *sasc = &sasc_main;
    sasc_service_main_t *sm = &sasc_service_main;
    u32 *service_index;
    u32 session_idx = session - sasc->sessions;
    u32 *forward_chain = sasc->effective_service_chains[session->service_chain[SASC_FLOW_FORWARD]];

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
        cbor_item_t *session_obj = format_sasc_session_cbor(session);
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
    // Generate basic session schema first
    cbor_item_t *session_schema =
        sasc_export_schema_generic("sasc", session_desc, session_field_count, 1);

    // Collect service schemas
    sasc_service_main_t *sm = &sasc_service_main;
    cbor_item_t *service_schemas = cbor_new_indefinite_map();

    for (int i = 0; i < vec_len(sm->services); i++) {
        sasc_service_registration_t *reg = vec_elt_at_index(sm->services, i)[0];
        if (reg->export_schema) {
            cbor_item_t *service_schema = reg->export_schema();
            if (service_schema) {
                bool success = cbor_map_add(
                    service_schemas,
                    (struct cbor_pair){.key = cbor_move(cbor_build_string(reg->node_name)),
                                       .value = cbor_move(service_schema)});
                if (!success) {
                    sasc_log_err("Failed to add schema for service %s", reg->node_name);
                }
            }
        }
    }

    // Create combined schema: [session_schema, service_schemas]
    cbor_item_t *combined_schema = cbor_new_definite_array(2);
    if (!cbor_array_push(combined_schema, cbor_move(session_schema)) ||
        !cbor_array_push(combined_schema, cbor_move(service_schemas))) {
        sasc_log_err("Failed to create combined schema");
        cbor_decref(&combined_schema);
        combined_schema = NULL;
    }

    size_t schema_size = 0;
    unsigned char *schema_data = NULL;

    if (combined_schema) {
        schema_size = cbor_serialized_size(combined_schema);
        schema_data = clib_mem_alloc(schema_size);
        if (schema_data) {
            size_t serialized_size = cbor_serialize(combined_schema, schema_data, schema_size);
            if (serialized_size != schema_size) {
                sasc_log_err("Failed to serialize schema, size %d", serialized_size);
                clib_mem_free(schema_data);
                schema_data = 0;
            }
        }
    }

    vlib_stats_ring_config_t config = {.entry_size = SASC_RING_ENTRY_SIZE,
                                       .ring_size = ring_size,
                                       .n_threads = vlib_get_n_threads(),
                                       .schema_size = schema_size,
                                       .schema_version = 1};

    sasc_stats_ring_index =
        vlib_stats_add_ring_buffer(&config, schema_data, "/sasc/session/events");
    if (sasc_stats_ring_index == CLIB_U32_MAX) {
        sasc_log_err("Failed to create SASC stats ring buffer");
    }

    // Cleanup
    if (schema_data) {
        clib_mem_free(schema_data);
    }
    if (combined_schema) {
        cbor_decref(&combined_schema);
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
    if (cbor_serialize(obj, slot, SASC_RING_ENTRY_SIZE) == 0) {
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

        cbor_item_t *session_obj = format_sasc_session_cbor(session);
        if (!session_obj)
            continue;

        // Add service data to the session object
        cbor_item_t *services_map = cbor_new_indefinite_map();
        serialize_sasc_session_services_cbor(services_map, thread_index, session);
        if (!cbor_array_push(session_obj, cbor_move(services_map))) {
            sasc_log_err("Failed to add services map to session object");
            cbor_decref(&session_obj);
            continue;
        }

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

static clib_error_t *
sasc_show_schema_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    if (sasc_stats_ring_index == CLIB_U32_MAX) {
        return clib_error_return(0, "SASC ring buffer not initialized");
    }

    u32 schema_size, schema_version;
    if (vlib_stats_ring_get_schema(sasc_stats_ring_index, 0, 0, &schema_size, &schema_version) !=
        0) {
        return clib_error_return(0, "No schema found in ring buffer");
    }

    unsigned char *schema_data = clib_mem_alloc(schema_size);
    if (!schema_data) {
        return clib_error_return(0, "Failed to allocate memory for schema");
    }

    if (vlib_stats_ring_get_schema(sasc_stats_ring_index, 0, schema_data, &schema_size,
                                   &schema_version) != 0) {
        clib_mem_free(schema_data);
        return clib_error_return(0, "Failed to retrieve schema");
    }

    // Parse and display schema
    cbor_item_t *schema = cbor_load(schema_data, schema_size, &(struct cbor_load_result){0});
    if (schema) {
        vlib_cli_output(vm, "SASC Schema (version %u):\n", schema_version);
        // TODO: Add proper schema formatting
        cbor_decref(&schema);
    }

    clib_mem_free(schema_data);
    return 0;
}

VLIB_CLI_COMMAND(sasc_show_schema_command, static) = {
    .path = "show sasc schema",
    .short_help = "show sasc schema",
    .function = sasc_show_schema_command_fn,
};

clib_error_t *
sasc_export_init(vlib_main_t *vm) {
    init_session_states();
    return 0;
}

cbor_item_t *
sasc_encode_array_generic(const sasc_field_desc_t *desc, size_t nfields,
                          const sasc_service_state_t *st, u32 session_index) {
    cbor_item_t *arr = cbor_new_indefinite_array();
    for (size_t i = 0; i < nfields; i++) {
        const sasc_field_desc_t *d = &desc[i];

        // fetch value
        switch (d->type) {
        case SASC_T_U8: {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u8 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u8 *)((const u8 *)st + d->offset));
            if (d->omit_if_zero && v == 0) {
                if (!cbor_array_push(arr, cbor_move(cbor_build_uint8((u8)v))))
                    return 0;
                break;
            }
            if (!cbor_array_push(arr, cbor_move(cbor_build_uint8((u8)v))))
                return 0;
            break;
        }
        case SASC_T_U16: {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u16 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u16 *)((const u8 *)st + d->offset));
            if (d->omit_if_zero && v == 0) {
                if (!cbor_array_push(arr, cbor_move(cbor_build_uint16(0))))
                    return 0;
                break;
            }
            if (!cbor_array_push(arr, cbor_move(cbor_build_uint16((u16)v))))
                return 0;
            break;
        }
        case SASC_T_U32: {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u32 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u32 *)((const u8 *)st + d->offset));
            if (d->omit_if_zero && v == 0) {
                if (!cbor_array_push(arr, cbor_move(cbor_build_uint32(0))))
                    return 0;
                break;
            }
            if (!cbor_array_push(arr, cbor_move(cbor_build_uint32((u32)v))))
                return 0;
            break;
        }
        case SASC_T_U64: {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u64 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u64 *)((const u8 *)st + d->offset));
            if (d->omit_if_zero && v == 0) {
                if (!cbor_array_push(arr, cbor_move(cbor_build_uint64(0))))
                    return 0;
                break;
            }
            if (!cbor_array_push(arr, cbor_move(cbor_build_uint64(v))))
                return 0;
            break;
        }
        case SASC_T_F64: {
            double dv = d->get_f64 ? d->get_f64(st, session_index) :
                                     *(const double *)((const u8 *)st + d->offset);
            if (!cbor_array_push(arr, cbor_move(cbor_build_float8(dv))))
                return 0;
            break;
        }
        case SASC_T_BOOL: {
            bool v = *(const bool *)((const u8 *)st + d->offset);
            if (!cbor_array_push(arr, cbor_move(cbor_build_bool(v))))
                return 0;
            break;
        }
        case SASC_T_SESSION_KEY: {
            sasc_session_key_t *k = (sasc_session_key_t *)((const u8 *)st + d->offset);
            if (!cbor_array_push(arr, cbor_move(cbor_build_session_key(k))))
                return 0;
            break;
        }
        case SASC_T_TIMESTAMP: {
            u64 v = d->get_u64 ? d->get_u64(st, session_index) :
                                 *(const u64 *)((const u8 *)st + d->offset);
            if (!cbor_array_push(arr,
                                 cbor_move(cbor_build_tag(1, cbor_move(cbor_build_uint64(v))))))
                return 0;
            break;
        }
        case SASC_T_IP4: {
            u32 v = *(const u32 *)((const u8 *)st + d->offset);
            if (!cbor_array_push(arr, cbor_move(cbor_build_ip4(v))))
                return 0;
            break;
        }
        case SASC_T_IP6: {
            ip6_address_t *v = (ip6_address_t *)((const u8 *)st + d->offset);
            if (!cbor_array_push(arr, cbor_move(cbor_build_ip6(v))))
                return 0;
            break;
        }
        case SASC_T_TSTR: {
            if (d->get_str) {
                const char *str = d->get_str(st, session_index);
                if (!cbor_array_push(arr, cbor_move(cbor_build_string(str))))
                    return 0;
            } else {
                if (!cbor_array_push(arr, cbor_move(cbor_new_null())))
                    return 0;
            }
            break;
        }
        case SASC_T_HISTOGRAM: {
            // For histogram type, we expect a getter function that returns histogram data
            // The histogram should be encoded as: [buckets_array, min_value, max_value,
            // bucket_count]
            if (d->get_histogram) {
                cbor_item_t *histogram_data = d->get_histogram(st, session_index);
                if (histogram_data) {
                    if (!cbor_array_push(arr, cbor_move(histogram_data)))
                        return 0;
                } else {
                    if (!cbor_array_push(arr, cbor_move(cbor_new_null())))
                        return 0;
                }
            } else {
                if (!cbor_array_push(arr, cbor_move(cbor_new_null())))
                    return 0;
            }
            break;
        }
        default:
            if (!cbor_array_push(arr, cbor_move(cbor_new_null())))
                return 0; // or ASSERT(0)
        }
    }
    return arr;
}

cbor_item_t *
sasc_export_schema_generic(const char *service_name, const sasc_field_desc_t *desc, size_t nfields,
                           u16 version) {
    cbor_item_t *fields = cbor_new_definite_array(nfields);
    for (size_t i = 0; i < nfields; i++) {
        cbor_item_t *f = cbor_new_definite_array(3);
        if (!cbor_array_push(f, cbor_move(cbor_build_uint32(i))))
            return 0;
        if (!cbor_array_push(f, cbor_move(cbor_build_string(desc[i].name))))
            return 0;
        uint8_t type_id =
            (desc[i].type == SASC_T_U8)          ? 1 :
            (desc[i].type == SASC_T_U16)         ? 2 :
            (desc[i].type == SASC_T_U32)         ? 3 :
            (desc[i].type == SASC_T_U64)         ? 4 :
            (desc[i].type == SASC_T_F64)         ? 13 :
            (desc[i].type == SASC_T_BOOL)        ? 20 :
            (desc[i].type == SASC_T_SESSION_KEY) ? 21 :
            (desc[i].type == SASC_T_TIMESTAMP)   ? 22 :
            (desc[i].type == SASC_T_TSTR)        ? 5 :
            (desc[i].type == SASC_T_HISTOGRAM) ?
                                            23 :
                                            255; // CBOR type 5 is text string, 23 for histogram
        if (!cbor_array_push(f, cbor_move(cbor_build_uint8(type_id))))
            return 0;
        if (!cbor_array_push(fields, cbor_move(f)))
            return 0;
    }
    cbor_item_t *desc_arr = cbor_new_definite_array(3);
    if (!cbor_array_push(desc_arr, cbor_move(cbor_build_string(service_name))))
        return 0;
    if (!cbor_array_push(desc_arr, cbor_move(cbor_build_uint16(version))))
        return 0;
    if (!cbor_array_push(desc_arr, cbor_move(fields)))
        return 0;
    return desc_arr;
}

u8 *
sasc_format_text_generic(u8 *s, const sasc_field_desc_t *desc, size_t nfields,
                         const sasc_service_state_t *st, u32 session_index,
                         const char *service_name) {
    u8 indent = 2;
    s = format(s, "%U%s:\n", format_white_space, indent, service_name);

    for (size_t i = 0; i < nfields; i++) {
        const sasc_field_desc_t *d = &desc[i];

        // Skip fields that should be omitted if zero
        if (d->omit_if_zero) {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u8 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u8 *)((const u8 *)st + d->offset));
            if (v == 0)
                continue;
        }

        // Format field name and value based on type
        switch (d->type) {
        case SASC_T_U8: {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u8 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u8 *)((const u8 *)st + d->offset));
            s = format(s, "%U%s: %u\n", format_white_space, indent + 2, d->name, (u8)v);
            break;
        }
        case SASC_T_U16: {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u16 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u16 *)((const u8 *)st + d->offset));
            s = format(s, "%U%s: %u\n", format_white_space, indent + 2, d->name, (u16)v);
            break;
        }
        case SASC_T_U32: {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u32 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u32 *)((const u8 *)st + d->offset));
            s = format(s, "%U%s: %u\n", format_white_space, indent + 2, d->name, (u32)v);
            break;
        }
        case SASC_T_U64: {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u64 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u64 *)((const u8 *)st + d->offset));
            s = format(s, "%U%s: %llu\n", format_white_space, indent + 2, d->name, v);
            break;
        }
        case SASC_T_F64: {
            double dv = d->get_f64 ? d->get_f64(st, session_index) :
                                     (d->elem >= 0 ?
                                          ((const double *)((const u8 *)st + d->offset))[d->elem] :
                                          *(const double *)((const u8 *)st + d->offset));
            s = format(s, "%U%s: %.6f\n", format_white_space, indent + 2, d->name, dv);
            break;
        }
        case SASC_T_BOOL: {
            bool v = (d->elem >= 0 ? ((const bool *)((const u8 *)st + d->offset))[d->elem] :
                                     *(const bool *)((const u8 *)st + d->offset));
            s = format(s, "%U%s: %s\n", format_white_space, indent + 2, d->name,
                       v ? "true" : "false");
            break;
        }
        case SASC_T_SESSION_KEY: {
            sasc_session_key_t *k = (sasc_session_key_t *)((const u8 *)st + d->offset);
            s = format(s, "%U%s: %U\n", format_white_space, indent + 2, d->name,
                       format_sasc_session_key, k);
            break;
        }
        case SASC_T_TIMESTAMP: {
            u64 v = d->get_u64 ?
                        d->get_u64(st, session_index) :
                        (d->elem >= 0 ? ((const u64 *)((const u8 *)st + d->offset))[d->elem] :
                                        *(const u64 *)((const u8 *)st + d->offset));
            s = format(s, "%U%s: %llu\n", format_white_space, indent + 2, d->name, v);
            break;
        }
        case SASC_T_IP4: {
            u32 v = (d->elem >= 0 ? ((const u32 *)((const u8 *)st + d->offset))[d->elem] :
                                    *(const u32 *)((const u8 *)st + d->offset));
            s = format(s, "%U%s: %U\n", format_white_space, indent + 2, d->name, format_ip4_address,
                       &v);
            break;
        }
        case SASC_T_IP6: {
            ip6_address_t *v = (ip6_address_t *)((const u8 *)st + d->offset);
            s = format(s, "%U%s: %U\n", format_white_space, indent + 2, d->name, format_ip6_address,
                       v);
            break;
        }
        case SASC_T_TSTR: {
            if (d->get_str) {
                const char *str = d->get_str(st, session_index);
                s = format(s, "%U%s: %s\n", format_white_space, indent + 2, d->name,
                           str ? str : "null");
            } else {
                s = format(s, "%U%s: null\n", format_white_space, indent + 2, d->name);
            }
            break;
        }
        case SASC_T_HISTOGRAM: {
            if (d->get_histogram) {
                cbor_item_t *histogram_data = d->get_histogram(st, session_index);
                if (histogram_data) {
                    s = format(s, "%U%s: [histogram data]\n", format_white_space, indent + 2,
                               d->name);
                    // Could implement histogram text formatting here if needed
                } else {
                    s = format(s, "%U%s: null\n", format_white_space, indent + 2, d->name);
                }
            } else {
                s = format(s, "%U%s: null\n", format_white_space, indent + 2, d->name);
            }
            break;
        }
        default:
            s = format(s, "%U%s: [unknown type]\n", format_white_space, indent + 2, d->name);
            break;
        }
    }
    return s;
}

VLIB_INIT_FUNCTION(sasc_export_init);