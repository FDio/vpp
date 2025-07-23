/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright(c) 2025 Cisco Systems, Inc. */

#ifndef __SASC_FORMAT_H__
#define __SASC_FORMAT_H__

#include <vnet/format_fns.h>
#include <vppinfra/format.h>

format_function_t format_sasc_session_key;
format_function_t format_sasc_tenant;
format_function_t format_sasc_tenant_extra;
format_function_t format_sasc_session_type;
format_function_t format_sasc_session_proto;
format_function_t format_sasc_session_state;
format_function_t format_sasc_session_detail;
format_function_t format_sasc_service_chain;
format_function_t format_sasc_effective_service_chain;
format_function_t format_sasc_service_chain_from_vector;
format_function_t format_sasc_memory_usage;

#endif /* __SASC_FORMAT_H__ */