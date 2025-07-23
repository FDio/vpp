// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#ifndef SASC_EXPORT_H
#define SASC_EXPORT_H

#include <vlib/vlib.h>
#include <stdbool.h>
#include <cbor.h>

typedef enum {
    SASC_T_U32,
    SASC_T_U64,
    SASC_T_F64,
    SASC_T_BOOL,
    SASC_T_IP4,
    SASC_T_IP6,
    SASC_T_TSTR,
    SASC_T_TIME, /* add as needed */
    SASC_T_SESSION_KEY, /* session key structure */
    SASC_T_TIMESTAMP, /* timestamp with tag 1 */
    SASC_T_ENUM, /* enum with string mapping */
} sasc_type_t;

typedef struct sasc_service_state_ sasc_service_state_t; // service-specific state structs cast here

typedef u64 (*sasc_get_u64_fn)(const sasc_service_state_t *st, u32 session_index);
typedef double (*sasc_get_f64_fn)(const sasc_service_state_t *st, u32 session_index);
typedef const char *(*sasc_get_str_fn)(const sasc_service_state_t *st, u32 session_index);

typedef struct {
    const char *name; // for schema only (not used by encoder at runtime)
    sasc_type_t type;
    // If direct member:
    size_t offset; // offsetof(service_state_t, field)
    int elem;      // -1 for scalar, else fixed array index
    // If computed:
    sasc_get_u64_fn get_u64; // used when type is an integer-like
    sasc_get_f64_fn get_f64; // used when type is a float-like
    sasc_get_str_fn get_str; // used when type is a string-like
    // Optional filter (omit field from array but keep position? see below)
    bool omit_if_zero;
} sasc_field_desc_t;

cbor_item_t *
sasc_export_schema_generic(const char *service_name,
                           const sasc_field_desc_t *desc, size_t nfields, u16 version);

cbor_item_t *
sasc_encode_array_generic(const sasc_field_desc_t *desc, size_t nfields,
                          const sasc_service_state_t *st, u32 session_index);

#endif