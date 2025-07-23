// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_sasc_service_h
#define included_sasc_service_h

#include <vlib/vlib.h>
#include <cbor.h>

typedef u8 *(*format_service_fn)(u8 *s, u32 thread_index, u32 session_index, bool detail);
typedef cbor_item_t *(*format_service_cbor_fn)(u32 thread_index, u32 session_index);
typedef cbor_item_t *(*export_schema_fn)(void);
typedef u64 (*service_memory_usage_fn)(void);

typedef struct _sasc_service_registration_t {
    struct _sasc_service_registration_t *next;
    const char *node_name;
    char **depends_on;
    char **conflicts_with;
    char **runs_after;
    u32 protocol_mask;
    format_service_fn format_service;
    format_service_cbor_fn format_service_cbor;
    export_schema_fn export_schema;
    service_memory_usage_fn memory_usage;
} sasc_service_registration_t;

typedef struct {
    sasc_service_registration_t *next_service;
    sasc_service_registration_t **services;
    uword *service_index_by_name;
} sasc_service_main_t;

extern sasc_service_main_t sasc_service_main;

/* Lookup service name from index */
const char *sasc_service_name_from_index(u32 index);

#define SASC_SERVICE_MASK(x) sasc_service_mask_##x

#ifndef CLIB_MARCH_VARIANT
#define SASC_SERVICE_DEFINE(x)                                                                                         \
    static sasc_service_registration_t sasc_service_registration_##x;                                                  \
    static void __sasc_service_add_registration_##x(void) __attribute__((__constructor__));                            \
    u8 sasc_service_index_in_bitmap_##x;                                                                               \
    u32 sasc_service_mask_##x;                                                                                         \
    static void __sasc_service_add_registration_##x(void) {                                                            \
        sasc_service_main_t *sm = &sasc_service_main;                                                                  \
        sasc_service_registration_t *r = &sasc_service_registration_##x;                                               \
        r->next = sm->next_service;                                                                                    \
        sm->next_service = r;                                                                                          \
    }                                                                                                                  \
    static sasc_service_registration_t sasc_service_registration_##x
#else
#define SASC_SERVICE_DEFINE(x)                                                                                         \
    SASC_SERVICE_DECLARE(x);                                                                                           \
    static sasc_service_registration_t __clib_unused unused_sasc_service_registration_##x

#endif

#define SASC_SERVICES(...)                                                                                             \
    (char *[]) { __VA_ARGS__, 0 }

#endif //__included_service_h__