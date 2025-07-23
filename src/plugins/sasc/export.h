// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#ifndef SASC_EXPORT_H
#define SASC_EXPORT_H

#include <vlib/vlib.h>
#include <stdbool.h>
#include <cbor.h>

typedef enum {
    SASC_T_U8,
    SASC_T_U16,
    SASC_T_U32,
    SASC_T_U64,
    SASC_T_F64,
    SASC_T_BOOL,
    SASC_T_IP4,
    SASC_T_IP6,
    SASC_T_TSTR,
    SASC_T_TIME,        /* add as needed */
    SASC_T_SESSION_KEY, /* session key structure */
    SASC_T_TIMESTAMP,   /* timestamp with tag 1 */
    SASC_T_ENUM,        /* enum with string mapping */
    SASC_T_HISTOGRAM,   /* histogram array with metadata */
    SASC_T_ARRAY,       /* fixed-size array */
    SASC_T_NESTED,      /* nested structure with its own descriptor */
} sasc_type_t;

typedef struct sasc_service_state_ sasc_service_state_t; // service-specific state structs cast here

typedef union {
    u64 u64_val;
    f64 f64_val;
    char *str_val;
    sasc_session_key_t session_key_val;
    // ... other types
} sasc_value_t;

// typedef u64 (*sasc_get_u64_fn)(const sasc_service_state_t *st, u32 session_index);
// typedef double (*sasc_get_f64_fn)(const sasc_service_state_t *st, u32 session_index);
// typedef const char *(*sasc_get_str_fn)(const sasc_service_state_t *st, u32 session_index);
// typedef sasc_session_key_t *(*sasc_get_session_key_fn)(const sasc_service_state_t *st, u32 session_index);
// typedef cbor_item_t *(*sasc_get_histogram_fn)(const sasc_service_state_t *st, u32 session_index);
typedef void (*sasc_get_value_fn)(const void *data, u32 session_index, sasc_value_t *result);

typedef struct sasc_field_desc_t {
    const char *name; // for schema only (not used by encoder at runtime)
    sasc_type_t type;
    // If direct member:
    size_t offset; // offsetof(service_state_t, field)
    // If computed:
    sasc_get_value_fn get_value;
    // If nested structure:
    const struct sasc_field_desc_t *nested_desc; // descriptor for nested structure
    size_t nested_count;                         // number of fields in nested structure
    // If array type:
    sasc_type_t element_type; // type of array elements (for SASC_T_ARRAY)
    size_t array_size;        // number of elements in array (for SASC_T_ARRAY)

    bool (*condition)(const void *data, u32 session_index);
} sasc_field_desc_t;

cbor_item_t *sasc_export_schema_generic(const char *service_name, const sasc_field_desc_t *desc, size_t nfields,
                                        u16 version);

cbor_item_t *sasc_encode_array_generic(const sasc_field_desc_t *desc, size_t nfields, const sasc_service_state_t *st,
                                       u32 session_index);

/**
 * Generic text formatter that processes field descriptions to create human-readable output
 * Similar to sasc_encode_array_generic but for text formatting instead of CBOR
 */
u8 *sasc_format_text_generic(u8 *s, const sasc_field_desc_t *desc, size_t nfields, const sasc_service_state_t *st,
                             u32 session_index, const char *service_name);

/**
 * Compact text formatter that creates a single-line, 4-column layout for session details
 * Format: ID:0 Thread:0 Tenant:0 Index:0 │ State:EST TTL:7435s Duration:0s │ Pkts:2→1 Bytes:80→40 │
 * F/R-Chains: service_name
 */
u8 *sasc_format_text_compact(u8 *s, const sasc_field_desc_t *desc, size_t nfields, const sasc_service_state_t *st,
                             u32 session_index, const char *service_name);

/**
 * Build a histogram CBOR object
 * Format: [buckets_array, min_value, max_value, bucket_count, bucket_width]
 */
cbor_item_t *sasc_build_histogram_cbor(const u64 *buckets, u32 bucket_count, u64 min_value, u64 max_value,
                                       u64 bucket_width);

#endif