// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <sasc/sasc.h>
#include <string.h> // Add this include for memcmp

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <sasc/sasc.api_enum.h>
#include <sasc/sasc.api_types.h>
// #include <sasc/sasc_types_funcs.h>
#include <vnet/mfib/mfib_table.h>
#include <sasc/service.h>
#define REPLY_MSG_ID_BASE sasc->msg_id_base
#include <vlibapi/api_helper_macros.h>

#include <sasc/sasc.api.c>
static clib_error_t *
sasc_plugin_api_hookup(vlib_main_t *vm) {
    // sasc_main_t *sasc = &sasc_main;
    // sasc->msg_id_base = setup_message_id_table();
    return 0;
}
VLIB_API_INIT_FUNCTION(sasc_plugin_api_hookup);
